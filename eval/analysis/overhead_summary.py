#!/usr/bin/env python3
"""Summarise an overhead session (RQ5) per stack and load level.

Usage: python3 eval/analysis/overhead_summary.py eval/results/overhead-<stamp>
Reads windows.csv and each window's load CSV; writes windows_full.csv (one row per window,
with latency) and summary.csv (median and bootstrap 95% CI per stack and rate, plus the
difference of medians against the c0 baseline at the same rate).
"""
import csv
import os
import sys

from analyze import bootstrap_ci, median, percentile, write_csv

METRICS = ("achieved_rps", "err_rate", "p50_ms", "p95_ms", "p99_ms", "cpu_agents", "mem_mb_agents",
           "cpu_backend", "host_cpu_busy", "cpu_falco", "cpu_tetragon", "cpu_kubearmor")


def load_stats(path):
    with open(path) as f:
        rows = [(float(r["t_send"]), float(r["latency_ms"]), int(r["status"])) for r in csv.DictReader(f)]
    if not rows:
        return {}
    ts = [r[0] for r in rows]
    ok = [r[1] for r in rows if r[2] == 200]
    span = max(ts) - min(ts)
    return {"achieved_rps": len(rows) / span if span else None,
            "err_rate": sum(1 for r in rows if r[2] != 200) / len(rows),
            "p50_ms": percentile(ok, 50), "p95_ms": percentile(ok, 95), "p99_ms": percentile(ok, 99)}


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    session = sys.argv[1]
    with open(os.path.join(session, "windows.csv")) as f:
        wins = [w for w in csv.DictReader(f) if not w.get("error")]
    for w in wins:
        for k, v in list(w.items()):
            try:
                w[k] = float(v) if k not in ("stack",) else v
            except (TypeError, ValueError):
                pass
        w["rate"], w["rep"] = int(w["rate"]), int(w["rep"])
        if w["rate"]:
            path = os.path.join(session, f"{w['stack']}-r{w['rep']:02d}",
                                f"load-{w['stack']}-r{w['rep']:02d}-{w['rate']}.csv")
            if os.path.exists(path):
                w.update(load_stats(path))
    write_csv(os.path.join(session, "windows_full.csv"), wins)

    groups = {}
    for w in wins:
        groups.setdefault((w["stack"], w["rate"]), []).append(w)
    summary = []
    for (stack, rate), ws in sorted(groups.items()):
        s = {"stack": stack, "rate": rate, "n": len(ws)}
        for m in METRICS:
            vals = [w[m] for w in ws if isinstance(w.get(m), float)]
            if vals:
                s[f"{m}_median"] = median(vals)
                s[f"{m}_ci_lo"], s[f"{m}_ci_hi"] = bootstrap_ci(vals)
        summary.append(s)
    base = {s["rate"]: s for s in summary if s["stack"] == "c0"}
    for s in summary:
        b = base.get(s["rate"])
        if b:
            for m in ("p50_ms", "p99_ms", "host_cpu_busy", "cpu_backend"):
                if f"{m}_median" in s and f"{m}_median" in b:
                    s[f"{m}_delta_vs_c0"] = s[f"{m}_median"] - b[f"{m}_median"]
    write_csv(os.path.join(session, "summary.csv"), summary)

    fmt = lambda v, p=3: "-" if v is None else f"{v:.{p}f}"  # noqa: E731
    print(f"{len(wins)} windows. Wrote windows_full.csv and summary.csv in {session}")
    print(f"{'stack':<6}{'rate':>6}{'n':>4}{'agents cores':>14}{'agents MB':>11}{'backend':>9}"
          f"{'host':>7}{'p50 ms':>8}{'p99 ms':>9}{'err':>7}")
    for s in summary:
        g = s.get
        print(f"{s['stack']:<6}{s['rate']:>6}{s['n']:>4}{fmt(g('cpu_agents_median')):>14}"
              f"{fmt(g('mem_mb_agents_median'), 0):>11}{fmt(g('cpu_backend_median')):>9}"
              f"{fmt(g('host_cpu_busy_median')):>7}{fmt(g('p50_ms_median'), 2):>8}"
              f"{fmt(g('p99_ms_median'), 2):>9}{fmt(g('err_rate_median')):>7}")


if __name__ == "__main__":
    main()
