#!/usr/bin/env python3
"""Experiment harness for the containment study (docs/containment_study_plan.md).

For every (mechanism, scenario) pair it performs --runs repetitions in a shuffled
order. Each run: fresh namespace and pods, warm-up under load, attack scenario,
observation window, re-compromise probe, evidence check, teardown.

Safe mechanisms only so far: m0 (detect only), m1 (Talon terminate),
m2 (Talon egress NetworkPolicy), m5 (in-app RASP).

Run from the repo root, e.g.:
  python3 eval/harness/run.py --mechanisms m0,m1,m2,m5 --scenarios s1-exec-discovery --runs 20
"""
import argparse
import glob
import json
import os
import random
import shlex
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
EVAL = os.path.join(ROOT, "eval")
NS = "eval"
os.environ.setdefault("KUBECONFIG", os.path.expanduser("~/.kube/config"))

MECHANISMS = {
    "m0": {"talon_rules": "talon-none.yaml", "rasp": False, "desc": "detect only"},
    "m1": {"talon_rules": "talon-terminate.yaml", "rasp": False, "desc": "Talon pod termination"},
    "m2": {"talon_rules": "talon-netpol.yaml", "rasp": False, "desc": "Talon egress NetworkPolicy"},
    "m5": {"talon_rules": "talon-none.yaml", "rasp": True, "desc": "in-app RASP lockdown"},
}


def sh(cmd, check=True, capture=True, timeout=300, input_text=None):
    res = subprocess.run(cmd, shell=isinstance(cmd, str), text=True, input=input_text,
                         capture_output=capture, timeout=timeout)
    if check and res.returncode != 0:
        raise RuntimeError(f"command failed ({res.returncode}): {cmd}\n{res.stderr}")
    return res.stdout.strip() if capture else ""


def kubectl_json(args):
    return json.loads(sh(f"kubectl {args} -o json"))


def load_config():
    cfg = {}
    with open(os.path.join(EVAL, "config.env")) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k] = v.strip().strip('"')
    return cfg


def node_ip():
    return sh("kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type==\"InternalIP\")].address}'")


def talon_deployment():
    names = [n for n in sh("kubectl get deploy -n falco -o name").split() if "talon" in n]
    if not names:
        raise RuntimeError("Falco Talon deployment not found in namespace falco; run eval/setup/03-install-stack.sh")
    return names[0]


def talon_chart():
    """Local chart file downloaded by setup/03-install-stack.sh (no network needed)."""
    charts = sorted(glob.glob(os.path.join(EVAL, "stack", "charts", "falco-talon-*.tgz")))
    if not charts:
        raise RuntimeError("Talon chart not found in eval/stack/charts; run eval/setup/03-install-stack.sh")
    return charts[-1]


def apply_mechanism(mech):
    rules = os.path.join(EVAL, "mechanisms", MECHANISMS[mech]["talon_rules"])
    sh(f"helm upgrade falco-talon {shlex.quote(talon_chart())} -n falco --reuse-values "
       f"--set-file config.rulesOverride={shlex.quote(rules)}", timeout=600)
    deploy = talon_deployment()
    sh(f"kubectl rollout restart -n falco {deploy}")
    sh(f"kubectl rollout status -n falco {deploy} --timeout=180s", timeout=200)
    time.sleep(3)


def deploy_app(rasp):
    sh(f"kubectl delete namespace {NS} --ignore-not-found --wait=true --timeout=180s", timeout=200)
    sh(f"kubectl create namespace {NS}")
    with open(os.path.join(EVAL, "k8s", "app.yaml")) as f:
        manifest = f.read().replace("__RASP__", "true" if rasp else "false")
    sh(f"kubectl apply -n {NS} -f -", input_text=manifest)
    sh(f"kubectl rollout status -n {NS} deploy/backend --timeout=180s", timeout=200)


def backend_pods():
    pods = kubectl_json(f"get pods -n {NS} -l app=backend")["items"]
    return [p for p in pods if p["status"].get("phase") == "Running" and not p["metadata"].get("deletionTimestamp")]


def is_ready(pod):
    return any(c["type"] == "Ready" and c["status"] == "True" for c in pod["status"].get("conditions", []))


class Watcher(threading.Thread):
    """Polls pods and NetworkPolicies, recording when each change is first seen."""

    def __init__(self, target, out_path, interval=0.25):
        super().__init__(daemon=True)
        self.target, self.out_path, self.interval = target, out_path, interval
        self.stop_event = threading.Event()
        self.timeline = {}

    def mark(self, key, t):
        self.timeline.setdefault(key, t)

    def run(self):
        known_pods = None
        with open(self.out_path, "w") as log:
            while not self.stop_event.is_set():
                try:
                    items = kubectl_json(f"get pods,networkpolicies -n {NS}")["items"]
                except Exception:
                    time.sleep(self.interval)
                    continue
                # Stamp after the query returns: the observed state held by then,
                # so timeline values are upper bounds (resolution ~ one query, ~0.3 s).
                t = time.time()
                pods = [i for i in items if i["kind"] == "Pod"]
                pols = [i for i in items if i["kind"] == "NetworkPolicy"]
                names = {p["metadata"]["name"] for p in pods}
                if known_pods is None:
                    known_pods = set(names)
                tgt = next((p for p in pods if p["metadata"]["name"] == self.target), None)
                if tgt is None:
                    self.mark("target_gone", t)
                elif tgt["metadata"].get("deletionTimestamp"):
                    self.mark("target_deleting", t)
                for p in pods:
                    if p["metadata"]["name"] not in known_pods:
                        self.mark("new_pod_seen", t)
                        if is_ready(p):
                            self.mark("new_pod_ready", t)
                if pols:
                    self.mark("netpol_seen", t)
                log.write(json.dumps({"t": t, "pods": sorted(names), "netpols": len(pols),
                                      "target_deleting": bool(tgt and tgt["metadata"].get("deletionTimestamp"))}) + "\n")
                time.sleep(self.interval)

    def stop(self):
        self.stop_event.set()
        self.join(timeout=10)


def exec_script(scenario, run_id, collector, steps=None):
    """Shell script run inside the pod: each step, then a beacon to the collector."""
    steps = scenario["steps"] if steps is None else steps
    lines = [
        f'C="{collector}/beacon?run={run_id}"',
        'b(){ wget -q -T 2 -O /dev/null "$C&step=$1" 2>/dev/null; }',
        "b 0",
    ]
    for i, cmd in enumerate(steps, 1):
        lines.append(f"sh -c {shlex.quote(cmd)} >/dev/null 2>&1; b {i}; sleep {scenario['interval_s']}")
    return "\n".join(lines) + "\n"


def run_exec_scenario(scenario, pod, run_id, collector, wait_s):
    script = exec_script(scenario, run_id, collector)
    proc = subprocess.Popen(["kubectl", "exec", "-i", "-n", NS, pod, "-c", "backend", "--", "sh", "-s"],
                            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    proc.stdin.write(script)
    proc.stdin.close()
    try:
        proc.wait(timeout=wait_s)
    except subprocess.TimeoutExpired:
        proc.kill()
    return {"exec_returncode": proc.returncode}


def http_step(ip, endpoint, timeout=3):
    t = time.time()
    req = urllib.request.Request(f"http://{ip}:5000/api/threat/{endpoint}", method="POST", data=b"")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
    except Exception:
        status = 0
    return {"t": t, "endpoint": endpoint, "status": status}


def http_step_ran(status):
    """The step reached the app and was not blocked. 403 = RASP lockdown, 0 = no response.
    500 counts as ran: e.g. spawn-shell starts a shell, then `whoami` fails for UID 10001."""
    return status not in (0, 403)


def run_http_scenario(scenario, pod_ip):
    results = []
    for ep in scenario["steps"]:
        results.append(http_step(pod_ip, ep))
        time.sleep(scenario["interval_s"])
    return {"http_steps": results}


def check_collector_from_pod(pod, collector):
    try:
        sh(f"kubectl exec -n {NS} {pod} -c backend -- wget -q -T 3 -O /dev/null {collector}/health", timeout=20)
    except Exception as e:
        sys.exit(f"Pods cannot reach the collector at {collector}. Check the firewall (see eval/README.md).\n{e}")


def recompromise_probe(scenario, run_id, collector):
    """After containment, try the first attack step once more against a live pod."""
    pods = backend_pods()
    if not pods:
        return {"recheck_pod": None, "recheck_ok": False}
    pod = pods[0]
    if scenario["type"] == "exec":
        script = exec_script(scenario, f"{run_id}-recheck", collector, steps=scenario["steps"][:1])
        try:
            sh(["kubectl", "exec", "-i", "-n", NS, pod["metadata"]["name"], "-c", "backend", "--", "sh", "-s"],
               input_text=script, timeout=20)
        except Exception:
            pass
        return {"recheck_pod": pod["metadata"]["name"], "recheck_run": f"{run_id}-recheck"}
    if scenario["type"] == "http":
        res = http_step(pod["status"]["podIP"], scenario["steps"][0])
        return {"recheck_pod": pod["metadata"]["name"], "recheck_ok": http_step_ran(res["status"]), "recheck_http": res}
    return {}


def evidence_check(target):
    try:
        sh(f"kubectl logs -n {NS} {target} -c backend --tail=5", timeout=20)
        return {"target_logs_available": True}
    except Exception:
        return {"target_logs_available": False}


def record_versions(path):
    info = {"time": time.time()}
    for key, cmd in {
        "kernel": "uname -r",
        "k3s": "k3s --version | head -1",
        "helm_releases": "helm list -A -o json",
        "lsm": "cat /sys/kernel/security/lsm",
        "cpu": "nproc",
    }.items():
        try:
            info[key] = sh(cmd)
        except Exception as e:
            info[key] = f"error: {e}"
    with open(path, "w") as f:
        json.dump(info, f, indent=2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mechanisms", default="m0,m1,m2,m5")
    ap.add_argument("--scenarios", default="s1-exec-discovery")
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--warmup", type=float, default=60, help="seconds of load before the attack")
    ap.add_argument("--observe", type=float, default=120, help="seconds observed after the attack starts")
    ap.add_argument("--rate", type=float, default=50, help="benign requests per second")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    cfg = load_config()
    port = int(cfg.get("COLLECTOR_PORT", 9999))
    mechs = args.mechanisms.split(",")
    for m in mechs:
        if m not in MECHANISMS:
            sys.exit(f"unknown mechanism {m}; available: {', '.join(MECHANISMS)}")
    scenarios = {}
    for s in args.scenarios.split(","):
        with open(os.path.join(EVAL, "scenarios", f"{s}.json")) as f:
            scenarios[s] = json.load(f)
        if "m5" in mechs and scenarios[s]["type"] == "exec":
            print(f"WARNING: m5 (RASP) only reacts to HTTP threat requests; with {s} it behaves like m0.")

    session = args.out or os.path.join(EVAL, "results", time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(os.path.join(session, "runs"), exist_ok=True)
    record_versions(os.path.join(session, "session.json"))

    collector_proc = subprocess.Popen([sys.executable, os.path.join(EVAL, "collector", "collector.py"),
                                       "--port", str(port), "--out", session])
    collector = f"http://{node_ip()}:{port}"
    time.sleep(1)

    plan = [(m, s) for m in mechs for s in scenarios for _ in range(args.runs)]
    random.Random(args.seed).shuffle(plan)
    with open(os.path.join(session, "plan.json"), "w") as f:
        json.dump({"args": vars(args), "plan": plan}, f, indent=2)

    current = None
    try:
        for idx, (mech, scen_name) in enumerate(plan):
            scenario = scenarios[scen_name]
            run_id = f"{idx:03d}-{mech}-{scen_name}"
            run_dir = os.path.join(session, "runs", run_id)
            os.makedirs(run_dir, exist_ok=True)
            print(f"[{idx + 1}/{len(plan)}] {run_id}", flush=True)
            meta = {"run": run_id, "mechanism": mech, "scenario": scen_name, "ok": False}
            try:
                if mech != current:
                    apply_mechanism(mech)
                    current = mech
                deploy_app(MECHANISMS[mech]["rasp"])
                pods = backend_pods()
                target = pods[0]
                if idx == 0:
                    check_collector_from_pod(target["metadata"]["name"], collector)
                svc_ip = sh(f"kubectl get svc -n {NS} backend -o jsonpath='{{.spec.clusterIP}}'")
                meta.update({"target_pod": target["metadata"]["name"], "target_ip": target["status"]["podIP"],
                             "warmup_s": args.warmup, "observe_s": args.observe, "rate": args.rate})

                urllib.request.urlopen(f"http://127.0.0.1:{port}/run?id={run_id}", timeout=5).read()
                load = subprocess.Popen([sys.executable, os.path.join(EVAL, "load", "loadgen.py"),
                                         "--url", f"http://{svc_ip}:5000/api/security/status",
                                         "--rate", str(args.rate), "--duration", str(args.warmup + args.observe),
                                         "--out", os.path.join(run_dir, "load.csv")])
                time.sleep(args.warmup)

                watcher = Watcher(meta["target_pod"], os.path.join(run_dir, "pods.jsonl"))
                watcher.start()
                meta["t_action"] = time.time()
                if scenario["type"] == "exec":
                    meta.update(run_exec_scenario(scenario, meta["target_pod"], run_id, collector, args.observe))
                elif scenario["type"] == "http":
                    meta.update(run_http_scenario(scenario, meta["target_ip"]))
                remaining = meta["t_action"] + args.observe - time.time()
                if remaining > 0:
                    time.sleep(remaining)
                watcher.stop()
                meta["timeline"] = watcher.timeline

                meta.update(recompromise_probe(scenario, run_id, collector))
                meta.update(evidence_check(meta["target_pod"]))
                load.wait(timeout=60)
                meta["ok"] = True
            except Exception as e:
                meta["error"] = str(e)
                print(f"  run failed: {e}", flush=True)
            with open(os.path.join(run_dir, "meta.json"), "w") as f:
                json.dump(meta, f, indent=2)
    finally:
        collector_proc.terminate()
        sh(f"kubectl delete namespace {NS} --ignore-not-found --wait=false", check=False)
    print(f"Done. Results in {session}\nAnalyse with: python3 eval/analysis/analyze.py {session}")


if __name__ == "__main__":
    main()
