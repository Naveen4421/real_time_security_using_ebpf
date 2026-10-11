#!/usr/bin/env python3
"""Steady-state overhead of each security stack (RQ5), with benign load only.

Stacks (agents switched on and off without reinstalling, so versions stay fixed):
  c0  none                     baseline: no Falco, Talon, Tetragon or KubeArmor running
  c1  falco                    Falco (modern eBPF) + Falcosidekick + Talon (M1 rules)
  c2  tetragon                 Tetragon with the M3 policy loaded
  c3  kubearmor                KubeArmor (AppArmor) with the M4 policy loaded
  c4  falco+tetragon           layered: c1 and c2 together

Each block: switch the stack, deploy the backend (2 replicas), warm up, then measure an idle
window and three open-loop load levels in shuffled order. Per window it records the load
generator's latency and errors, and CPU time and memory per pod read from the cgroup files
(cpu.stat usage_usec, memory.current), plus host CPU from /proc/stat.

Run from the repo root inside tmux, e.g.:
  python3 eval/overhead/overhead.py --reps 10
Analyse with: python3 eval/analysis/overhead_summary.py eval/results/overhead-<stamp>
"""
import argparse
import csv
import glob
import json
import os
import random
import subprocess
import sys
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
EVAL = os.path.join(ROOT, "eval")
sys.path.insert(0, os.path.join(EVAL, "harness"))
from run import NS, apply_mechanism, deploy_app, kubectl_json, sh  # noqa: E402

STACKS = {
    "c0": {"falco": False, "tetragon": False, "kubearmor": False, "policy": None},
    "c1": {"falco": True, "tetragon": False, "kubearmor": False, "policy": None},
    "c2": {"falco": False, "tetragon": True, "kubearmor": False, "policy": "tetragon-kill.yaml"},
    "c3": {"falco": False, "tetragon": False, "kubearmor": True, "policy": "kubearmor-block.yaml"},
    "c4": {"falco": True, "tetragon": True, "kubearmor": False, "policy": "tetragon-kill.yaml"},
}
OFF = "eval-overhead-off"  # nodeSelector key no node has: removes a DaemonSet's pods


def set_daemonset(ns, name, label, on):
    patch = {"spec": {"template": {"spec": {"nodeSelector": {OFF: None if on else "true"}}}}}
    sh(["kubectl", "patch", "ds", "-n", ns, name, "--type", "merge", "-p", json.dumps(patch)])
    if on:
        sh(f"kubectl rollout status ds/{name} -n {ns} --timeout=300s", timeout=320)
    else:
        sh(f"kubectl wait --for=delete pod -n {ns} -l app.kubernetes.io/name={label} --timeout=180s",
           check=False, timeout=200)


def set_falco(on):
    set_daemonset("falco", "falco", "falco", on)
    for dep, n in (("falco-falcosidekick", 2), ("falco-talon", 1)):
        sh(f"kubectl scale deploy -n falco {dep} --replicas={n if on else 0}")
        if on:
            sh(f"kubectl rollout status deploy/{dep} -n falco --timeout=180s", timeout=200)
    if on:
        apply_mechanism("m1")  # Talon with the terminate rules, as in M1


def set_stack(stack):
    cfg = STACKS[stack]
    # KubeArmor's webhook must be gone before other agents' pods are recreated (see setup/kubearmor.sh)
    if not cfg["kubearmor"]:
        sh("bash eval/setup/kubearmor.sh uninstall", check=False, timeout=600)
    set_falco(cfg["falco"])
    set_daemonset("kube-system", "tetragon", "tetragon", cfg["tetragon"])
    if cfg["kubearmor"]:
        sh("bash eval/setup/kubearmor.sh install", timeout=900)


def tracked_pods():
    """Pods whose resource use is recorded, grouped by component."""
    groups = {"falco": "falco", "kube-system": None, "kubearmor": "kubearmor", NS: "backend"}
    out = []
    for ns, comp in groups.items():
        try:
            items = kubectl_json(f"get pods -n {ns}")["items"]
        except Exception:
            continue
        for p in items:
            name = p["metadata"]["name"]
            if ns == "kube-system":
                if not name.startswith("tetragon"):
                    continue
                c = "tetragon"
            else:
                c = comp
            uid = p["metadata"]["uid"].replace("-", "_")
            dirs = glob.glob(f"/sys/fs/cgroup/kubepods.slice/**/*pod{uid}.slice", recursive=True)
            if dirs:
                out.append({"component": c, "pod": name, "dir": dirs[0]})
    return out


def read_int(path, key=None):
    try:
        with open(path) as f:
            if key is None:
                return int(f.read().strip())
            for line in f:
                k, v = line.split()
                if k == key:
                    return int(v)
    except (OSError, ValueError):
        return None


def host_cpu():
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:]]
    idle = v[3] + v[4]
    return sum(v), idle


class Sampler(threading.Thread):
    def __init__(self, pods, path, interval=2.0):
        super().__init__(daemon=True)
        self.pods, self.path, self.interval = pods, path, interval
        self.stop_event = threading.Event()

    def sample(self):
        tot, idle = host_cpu()
        rec = {"t": time.time(), "host_total": tot, "host_idle": idle, "pods": {}}
        for p in self.pods:
            rec["pods"][p["pod"]] = {"component": p["component"],
                                     "cpu_usec": read_int(os.path.join(p["dir"], "cpu.stat"), "usage_usec"),
                                     "mem": read_int(os.path.join(p["dir"], "memory.current"))}
        return rec

    def run(self):
        with open(self.path, "a") as f:
            while not self.stop_event.is_set():
                f.write(json.dumps(self.sample()) + "\n")
                f.flush()
                self.stop_event.wait(self.interval)

    def stop(self):
        self.stop_event.set()
        self.join(timeout=10)


def window(stack, rep, rate, args, svc_ip, block_dir, sampler):
    tag = f"{stack}-r{rep:02d}-{rate}"
    rec = {"stack": stack, "rep": rep, "rate": rate, "t_start": time.time()}
    start = sampler.sample()
    if rate == 0:
        time.sleep(args.window)
    else:
        sh([sys.executable, os.path.join(EVAL, "load", "loadgen.py"), "--url",
            f"http://{svc_ip}:5000/api/security/status", "--rate", str(rate), "--duration", str(args.window),
            "--timeout", "1", "--out", os.path.join(block_dir, f"load-{tag}.csv")], timeout=args.window + 120)
    end = sampler.sample()
    rec["t_end"] = time.time()
    dt = end["t"] - start["t"]
    dtot = end["host_total"] - start["host_total"]
    rec["host_cpu_busy"] = 1 - (end["host_idle"] - start["host_idle"]) / dtot if dtot else None
    comp_cpu, comp_mem = {}, {}
    for pod, e in end["pods"].items():
        s = start["pods"].get(pod)
        if not s or e["cpu_usec"] is None or s["cpu_usec"] is None:
            continue
        c = e["component"]
        comp_cpu[c] = comp_cpu.get(c, 0) + (e["cpu_usec"] - s["cpu_usec"]) / 1e6 / dt
        if e["mem"] is not None:
            comp_mem[c] = comp_mem.get(c, 0) + e["mem"] / 2**20
    for c in ("backend", "falco", "tetragon", "kubearmor"):
        rec[f"cpu_{c}"] = comp_cpu.get(c, 0.0)
        rec[f"mem_mb_{c}"] = comp_mem.get(c, 0.0)
    rec["cpu_agents"] = sum(v for k, v in comp_cpu.items() if k != "backend")
    rec["mem_mb_agents"] = sum(v for k, v in comp_mem.items() if k != "backend")
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stacks", default="c0,c1,c2,c3,c4")
    ap.add_argument("--rates", default="500,1500,2500", help="requests/s; an idle window (0) is always added")
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--window", type=float, default=60, help="seconds per measurement window")
    ap.add_argument("--warmup", type=float, default=30)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    stacks = args.stacks.split(",")
    rates = [0] + [int(r) for r in args.rates.split(",")]
    session = args.out or os.path.join(EVAL, "results", time.strftime("overhead-%Y%m%d-%H%M"))
    os.makedirs(session, exist_ok=True)
    rng = random.Random(args.seed)
    # Every repetition visits every stack once, in a fresh random order (spreads drift).
    plan = []
    for rep in range(args.reps):
        order = stacks[:]
        rng.shuffle(order)
        for s in order:
            r = rates[:]
            rng.shuffle(r)
            plan.append((rep, s, r))
    with open(os.path.join(session, "plan.json"), "w") as f:
        json.dump({"args": vars(args), "plan": plan}, f, indent=2)

    rows = []
    try:
        for i, (rep, stack, order) in enumerate(plan):
            print(f"[{i + 1}/{len(plan)}] rep {rep} stack {stack} rates {order}", flush=True)
            block_dir = os.path.join(session, f"{stack}-r{rep:02d}")
            os.makedirs(block_dir, exist_ok=True)
            try:
                set_stack(stack)
                deploy_app(False, STACKS[stack]["policy"])
                svc_ip = sh(f"kubectl get svc -n {NS} backend -o jsonpath='{{.spec.clusterIP}}'")
                sh([sys.executable, os.path.join(EVAL, "load", "loadgen.py"), "--url",
                    f"http://{svc_ip}:5000/api/security/status", "--rate", "200", "--duration",
                    str(args.warmup), "--timeout", "1", "--out", "/dev/null"], timeout=args.warmup + 60)
                sampler = Sampler(tracked_pods(), os.path.join(block_dir, "samples.jsonl"))
                sampler.start()
                for rate in order:
                    rec = window(stack, rep, rate, args, svc_ip, block_dir, sampler)
                    rows.append(rec)
                    print(f"    rate {rate:>5}: agents {rec['cpu_agents']:.3f} cores, "
                          f"backend {rec['cpu_backend']:.3f} cores, host {rec['host_cpu_busy']:.3f}", flush=True)
                    time.sleep(5)
                sampler.stop()
            except Exception as e:
                print(f"  block failed: {e}", flush=True)
                rows.append({"stack": stack, "rep": rep, "error": str(e)})
            with open(os.path.join(session, "windows.csv"), "w", newline="") as f:
                keys = []
                for r in rows:
                    keys += [k for k in r if k not in keys]
                w = csv.DictWriter(f, fieldnames=keys)
                w.writeheader()
                w.writerows(rows)
    finally:
        sh(f"kubectl delete namespace {NS} --ignore-not-found --wait=false", check=False)
        print("Restoring the measurement stack (Falco, Talon, Tetragon on; KubeArmor off)", flush=True)
        sh("bash eval/setup/kubearmor.sh uninstall", check=False, timeout=600)
        set_falco(True)
        set_daemonset("kube-system", "tetragon", "tetragon", True)
    print(f"Done. Results in {session}\nAnalyse with: python3 eval/analysis/overhead_summary.py {session}")


if __name__ == "__main__":
    main()
