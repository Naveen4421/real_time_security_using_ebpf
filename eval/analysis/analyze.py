#!/usr/bin/env python3
"""Compute per-run metrics and a per-(mechanism, scenario) summary for a results session.

Usage: python3 eval/analysis/analyze.py eval/results/<session>
Writes <session>/runs.csv and <session>/summary.csv. Metric definitions follow
docs/containment_study_plan.md Section 5; all times are seconds on the host clock.
"""
import csv
import json
import math
import os
import random
import sys
from collections import defaultdict
from datetime import datetime, timezone

EVAL = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(EVAL, "harness"))
from run import http_step_ran  # noqa: E402  (one definition of a completed HTTP step)


def parse_falco_time(s):
    """Falco uses RFC 3339 with nanoseconds; Python handles microseconds."""
    if not s:
        return None
    s = s.rstrip("Z")
    if "." in s:
        head, frac = s.split(".", 1)
        s = f"{head}.{frac[:6]}"
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc).timestamp()


def percentile(values, p):
    if not values:
        return None
    v = sorted(values)
    k = max(0, math.ceil(p / 100 * len(v)) - 1)
    return v[k]


def median(values):
    return percentile(values, 50)


def bootstrap_ci(values, stat=median, n=2000, seed=0):
    if len(values) < 2:
        return None, None
    rng = random.Random(seed)
    stats = sorted(stat([rng.choice(values) for _ in values]) for _ in range(n))
    return stats[int(0.025 * n)], stats[int(0.975 * n) - 1]


def load_window_stats(rows, t0, t1):
    sel = [r for r in rows if t0 <= r[0] < t1]
    if not sel:
        return None, None
    errors = sum(1 for r in sel if r[2] != 200)
    ok_lat = [r[1] for r in sel if r[2] == 200]
    return errors / len(sel), percentile(ok_lat, 99)


def scenario_steps(name):
    path = os.path.join(EVAL, "scenarios", f"{name}.json")
    if os.path.exists(path):
        with open(path) as f:
            return len(json.load(f).get("steps", []))
    return None


BLOCKED_RC = {"126", "127", "137"}  # could not execute / not found / killed (SIGKILL)


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip().startswith("{")]


def tetragon_metrics(run_dir, meta, t_action):
    """Exact kernel-side times from Tetragon (only when tetragon.jsonl was saved):
    L_kernel_kill_s  first process killed by the M3 policy
    L_session_end_s  exit of the attacker's shell (exec scenario), or its kill at start
    L_app_killed_s   first exit of the target pod's node server.js (HTTP scenario)"""
    evs = read_jsonl(os.path.join(run_dir, "tetragon.jsonl"))
    if not evs:
        return {}
    t_end = t_action + meta.get("observe_s", 120)  # the re-compromise probe comes later
    out = {}
    kills, execs, exits = [], [], []
    for e in evs:
        t = parse_falco_time(e.get("time"))
        if t is None or not (t_action <= t <= t_end):
            continue
        kind = next((k for k in e if k.startswith("process_")), None)
        body = e[kind]
        proc = body.get("process", {})
        pod = (proc.get("pod") or {}).get("name")
        if kind == "process_kprobe" and body.get("action") == "KPROBE_ACTION_SIGKILL":
            kills.append(t)
        elif kind == "process_exec" and pod == meta.get("target_pod"):
            execs.append((t, proc))
        elif kind == "process_exit" and pod == meta.get("target_pod"):
            exits.append((t, proc))
    if kills:
        out["L_kernel_kill_s"] = min(kills) - t_action
    if meta.get("http_steps") is None:
        session = next((p for t, p in sorted(execs, key=lambda x: x[0]) if p.get("arguments") == "-s"), None)
        if session:
            end = [t for t, p in exits if p.get("exec_id") == session.get("exec_id")]
            if end:
                out["L_session_end_s"] = min(end) - t_action
        elif kills:
            out["L_session_end_s"] = min(kills) - t_action
    else:
        # The server is the container's PID 1; spawn-shell forks node children that M3 also kills.
        app = [t for t, p in exits if p.get("binary", "").endswith("/node")
               and ((p.get("pod") or {}).get("container") or {}).get("pid") == 1]
        if app:
            out["L_app_killed_s"] = min(app) - t_action
    return out


def kubearmor_metrics(run_dir, t_action):
    """First KubeArmor block alert for the M4 policy (only when kubearmor.jsonl was saved)."""
    alerts = [a for a in read_jsonl(os.path.join(run_dir, "kubearmor.jsonl"))
              if a.get("PolicyName") == "eval-m4-block"]
    times = [t for t in (parse_falco_time(a.get("UpdatedTime")) for a in alerts) if t and t >= t_action]
    out = {"block_alerts": len(times)} if alerts else {}
    if times:
        out["L_block_alert_s"] = min(times) - t_action
    return out


def abuse_metrics(meta, actions, run_dir, t_action):
    """RQ4: what repeated triggering costs normal users, over the trigger period.
    unavail_s: 1-s bins in which fewer than half of the benign requests succeeded."""
    with open(os.path.join(EVAL, "scenarios", f"{meta['scenario']}.json")) as f:
        dur = json.load(f)["duration_s"]
    out = {"triggers": len(meta["abuse_requests"]),
           "triggers_answered": sum(1 for r in meta["abuse_requests"] if r["status"] != 0),
           "terminations": sum(1 for a in actions if (a.get("body") or {}).get("status") == "success"),
           "terminations_skipped": sum(1 for a in actions if (a.get("body") or {}).get("status") == "ignored"),
           "restarts_total": meta.get("restarts_total")}
    load_path = os.path.join(run_dir, "load.csv")
    if os.path.exists(load_path):
        with open(load_path) as f:
            rows = [(float(r["t_send"]), int(r["status"])) for r in csv.DictReader(f)]
        win = [r for r in rows if t_action <= r[0] < t_action + dur]
        if win:
            out["err_rate_abuse"] = sum(1 for r in win if r[1] != 200) / len(win)
        bins = defaultdict(lambda: [0, 0])
        for t, status in win:
            b = bins[int(t - t_action)]
            b[0] += 1
            b[1] += status == 200
        down = [s for s in range(int(dur)) if bins[s][0] and bins[s][1] < bins[s][0] / 2]
        out["unavail_s"] = len(down)
        longest = run_len = 0
        for s in range(int(dur)):
            run_len = run_len + 1 if s in down else 0
            longest = max(longest, run_len)
        out["longest_outage_s"] = longest
    samples = read_jsonl(os.path.join(run_dir, "pods.jsonl"))
    samples = [s for s in samples if t_action <= s["t"] <= t_action + dur and "ready" in s]
    out["zero_ready_s"] = sum(b["t"] - a["t"] for a, b in zip(samples, samples[1:]) if a["ready"] == 0)
    out["min_ready"] = min((s["ready"] for s in samples), default=None)
    return out


def analyze_run(meta, events, run_dir):
    run = meta["run"]
    t_action = meta.get("t_action")
    row = {k: meta.get(k) for k in ("run", "mechanism", "scenario", "ok", "target_pod")}
    if not meta.get("ok") or t_action is None:
        row["error"] = meta.get("error")
        return row

    # Only the observation window: the re-compromise probe afterwards raises its own alerts.
    t_end = t_action + meta.get("observe_s", 120)
    mine = [e for e in events if e.get("run") == run and t_action <= e["t"] <= t_end]
    alerts = sorted((e for e in mine if e["type"] == "alert"), key=lambda e: e["t"])
    actions = sorted((e for e in mine if e["type"] == "action"), key=lambda e: e["t"])
    row["alerts"] = len(alerts)
    if alerts:
        row["L_detect_s"] = alerts[0]["t"] - t_action
        evt = parse_falco_time(alerts[0].get("evt_time"))
        row["alert_pipeline_s"] = alerts[0]["t"] - evt if evt else None
        row["first_rule"] = alerts[0].get("rule")
    if actions:
        row["L_talon_notify_s"] = actions[0]["t"] - t_action
    if "abuse_requests" in meta:
        row.update(abuse_metrics(meta, actions, run_dir, t_action))
        return row

    # Attack progress
    total = scenario_steps(meta["scenario"])
    if "http_steps" in meta:
        # Completed = reached the app and not blocked (see harness http_step_ran).
        done = [s for s in meta["http_steps"] if http_step_ran(s["status"], s.get("body"))]
        times = [s["t"] for s in done]
        first_t = meta["http_steps"][0]["t"] if meta["http_steps"] else None
        blocked = [s for s in meta["http_steps"] if s["status"] == 403]
        if blocked:
            row["t_rasp_block_s"] = blocked[0]["t"] - t_action
        refused = [s["t"] for s in meta["http_steps"] if not http_step_ran(s["status"], s.get("body"))]
        if refused and "body" in meta["http_steps"][0]:
            row["L_first_blocked_s"] = min(refused) - t_action
        reached_times = times
    else:
        # A beacon = the attacker's shell was alive after the step. The step itself took
        # effect unless its exit code says it was killed or could not run (M3/M4).
        beacons = [e for e in events if e["type"] == "beacon" and e.get("run") == run]
        first_t = min((e["t"] for e in beacons if e["step"] == "0"), default=None)
        reached = {e["step"]: e for e in beacons if e["step"] not in (None, "0")}
        reached_times = [e["t"] for e in reached.values()]
        times = [e["t"] for e in reached.values() if e.get("rc") not in BLOCKED_RC]
        row["steps_reached"] = len(reached)
        refused = [e["t"] for e in reached.values() if e.get("rc") in BLOCKED_RC]
        if refused:
            row["L_first_blocked_s"] = min(refused) - t_action
        recheck = [e for e in events if e["type"] == "beacon" and e.get("run") == f"{run}-recheck"
                   and e["step"] == "1" and e.get("rc") not in BLOCKED_RC]
        if "recheck_run" in meta:
            row["recompromised"] = bool(recheck)
    if "recheck_http" in meta:
        row["recompromised"] = http_step_ran(meta["recheck_http"]["status"], meta["recheck_http"].get("body"))
    row["steps_completed"] = len(times)
    row["steps_total"] = total
    if reached_times and first_t is not None:
        row["attack_window_s"] = max(reached_times) - first_t

    row.update(tetragon_metrics(run_dir, meta, t_action))
    row.update(kubearmor_metrics(run_dir, t_action))

    # Response timing. Primary: Talon's own completion notification (collector clock,
    # ms precision) for m1/m2, first 403 for m5. Secondary: when the watcher saw the
    # change in the Kubernetes API (upper bound, ~0.3 s resolution).
    tl = meta.get("timeline") or {}
    api_seen = tl.get("target_deleting") or tl.get("target_gone") or tl.get("netpol_seen")
    if api_seen:
        row["L_api_visible_s"] = api_seen - t_action
    if meta["mechanism"] == "m5":
        if "t_rasp_block_s" in row:
            row["L_response_s"] = row["t_rasp_block_s"]
    elif meta["mechanism"] == "m3":
        if "L_kernel_kill_s" in row:
            row["L_response_s"] = row["L_kernel_kill_s"]
    elif meta["mechanism"] == "m4":
        # KubeArmor raises no alert when it refuses /bin/busybox started as /bin/sh, so the
        # first refused step counts too (an upper bound: the step's report time).
        cands = [row[k] for k in ("L_block_alert_s", "L_first_blocked_s") if k in row]
        if cands:
            row["L_response_s"] = min(cands)
    elif actions:
        row["L_response_s"] = actions[0]["t"] - t_action
    if tl.get("new_pod_ready"):
        row["recovery_s"] = tl["new_pod_ready"] - t_action
    row["target_logs_available"] = meta.get("target_logs_available")

    # Disruption of benign traffic
    load_path = os.path.join(run_dir, "load.csv")
    if os.path.exists(load_path):
        with open(load_path) as f:
            rows = [(float(r["t_send"]), float(r["latency_ms"]), int(r["status"])) for r in csv.DictReader(f)]
        err0, p99_0 = load_window_stats(rows, t_action - meta.get("warmup_s", 60), t_action)
        err1, p99_1 = load_window_stats(rows, t_action, t_action + meta.get("observe_s", 120))
        row.update({"err_rate_baseline": err0, "err_rate_response": err1,
                    "p99_ms_baseline": p99_0, "p99_ms_response": p99_1})
    return row


def summarize(rows):
    groups = defaultdict(list)
    for r in rows:
        if r.get("ok"):
            groups[(r["mechanism"], r["scenario"])].append(r)
    out = []
    for (mech, scen), rs in sorted(groups.items()):
        s = {"mechanism": mech, "scenario": scen, "n": len(rs)}
        for key in ("L_detect_s", "L_response_s", "L_api_visible_s", "attack_window_s", "steps_completed",
                    "steps_reached", "L_session_end_s", "L_kernel_kill_s", "L_app_killed_s", "L_block_alert_s", "L_first_blocked_s",
                    "alert_pipeline_s", "err_rate_response", "p99_ms_response", "recovery_s",
                    "terminations", "terminations_skipped", "restarts_total", "err_rate_abuse", "unavail_s",
                    "longest_outage_s", "zero_ready_s", "min_ready"):
            vals = [r[key] for r in rs if r.get(key) is not None]
            if vals:
                lo, hi = bootstrap_ci(vals)
                s[f"{key}_median"] = median(vals)
                s[f"{key}_p95"] = percentile(vals, 95)
                s[f"{key}_ci_lo"], s[f"{key}_ci_hi"] = lo, hi
        rec = [r["recompromised"] for r in rs if r.get("recompromised") is not None]
        if rec:
            s["recompromise_rate"] = sum(rec) / len(rec)
        ev = [r["target_logs_available"] for r in rs if r.get("target_logs_available") is not None]
        if ev:
            s["evidence_logs_rate"] = sum(ev) / len(ev)
        s["detection_rate"] = sum(1 for r in rs if r.get("alerts")) / len(rs)
        out.append(s)
    return out


def write_csv(path, rows):
    keys = []
    for r in rows:
        keys += [k for k in r if k not in keys]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    session = sys.argv[1]
    events = []
    ev_path = os.path.join(session, "events.jsonl")
    if os.path.exists(ev_path):
        with open(ev_path) as f:
            events = [json.loads(line) for line in f if line.strip()]
    rows = []
    runs_dir = os.path.join(session, "runs")
    for name in sorted(os.listdir(runs_dir)):
        meta_path = os.path.join(runs_dir, name, "meta.json")
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                rows.append(analyze_run(json.load(f), events, os.path.join(runs_dir, name)))
    write_csv(os.path.join(session, "runs.csv"), rows)
    summary = summarize(rows)
    write_csv(os.path.join(session, "summary.csv"), summary)
    failed = sum(1 for r in rows if not r.get("ok"))
    print(f"{len(rows)} runs ({failed} failed). Wrote runs.csv and summary.csv in {session}")
    for s in summary:
        print(f"  {s['mechanism']:>3} {s['scenario']:<20} n={s['n']:<3} "
              f"detect={s.get('L_detect_s_median')} response={s.get('L_response_s_median')} "
              f"steps={s.get('steps_completed_median')} recompromise={s.get('recompromise_rate')}")


if __name__ == "__main__":
    main()
