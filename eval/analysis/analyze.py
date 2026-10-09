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


def analyze_run(meta, events, run_dir):
    run = meta["run"]
    t_action = meta.get("t_action")
    row = {k: meta.get(k) for k in ("run", "mechanism", "scenario", "ok", "target_pod")}
    if not meta.get("ok") or t_action is None:
        row["error"] = meta.get("error")
        return row

    mine = [e for e in events if e.get("run") == run]
    alerts = sorted((e for e in mine if e["type"] == "alert" and e["t"] >= t_action), key=lambda e: e["t"])
    actions = sorted((e for e in mine if e["type"] == "action" and e["t"] >= t_action), key=lambda e: e["t"])
    row["alerts"] = len(alerts)
    if alerts:
        row["L_detect_s"] = alerts[0]["t"] - t_action
        evt = parse_falco_time(alerts[0].get("evt_time"))
        row["alert_pipeline_s"] = alerts[0]["t"] - evt if evt else None
        row["first_rule"] = alerts[0].get("rule")
    if actions:
        row["L_talon_notify_s"] = actions[0]["t"] - t_action

    # Attack progress
    total = scenario_steps(meta["scenario"])
    if "http_steps" in meta:
        # Completed = reached the app and not blocked (see harness http_step_ran).
        done = [s for s in meta["http_steps"] if s["status"] not in (0, 403)]
        times = [s["t"] for s in done]
        first_t = meta["http_steps"][0]["t"] if meta["http_steps"] else None
        blocked = [s for s in meta["http_steps"] if s["status"] == 403]
        if blocked:
            row["t_rasp_block_s"] = blocked[0]["t"] - t_action
    else:
        beacons = [e for e in events if e["type"] == "beacon" and e.get("run") == run]
        first_t = min((e["t"] for e in beacons if e["step"] == "0"), default=None)
        done = {e["step"]: e["t"] for e in beacons if e["step"] not in (None, "0")}
        times = list(done.values())
        recheck = [e for e in events if e["type"] == "beacon" and e.get("run") == f"{run}-recheck" and e["step"] == "1"]
        if "recheck_run" in meta:
            row["recompromised"] = bool(recheck)
    if "recheck_http" in meta:
        row["recompromised"] = meta["recheck_http"]["status"] not in (0, 403)
    row["steps_completed"] = len(times)
    row["steps_total"] = total
    if times and first_t is not None:
        row["attack_window_s"] = max(times) - first_t

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
        for key in ("L_detect_s", "L_response_s", "L_api_visible_s", "attack_window_s", "steps_completed", "alert_pipeline_s",
                    "err_rate_response", "p99_ms_response"):
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
