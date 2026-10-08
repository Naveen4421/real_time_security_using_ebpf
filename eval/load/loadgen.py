#!/usr/bin/env python3
"""Open-loop HTTP load generator (stdlib only).

Sends GET requests at a fixed rate regardless of response time, so a stalled or
killed backend shows up as errors and latency rather than as a lower send rate.
Writes one CSV row per request: t_send (Unix s), latency_ms, status (0 = error).
"""
import argparse
import csv
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor


def one_request(url, timeout):
    t0 = time.time()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            r.read()
            status = r.status
    except urllib.error.HTTPError as e:
        status = e.code
    except Exception:
        status = 0
    return t0, (time.time() - t0) * 1000.0, status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--rate", type=float, default=50.0, help="requests per second")
    ap.add_argument("--duration", type=float, required=True, help="seconds")
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    rows, lock = [], threading.Lock()

    def done(fut):
        with lock:
            rows.append(fut.result())

    interval = 1.0 / args.rate
    workers = max(4, int(args.rate * args.timeout) + 1)
    start = time.time()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        n = 0
        while True:
            due = start + n * interval
            if due - start >= args.duration:
                break
            delay = due - time.time()
            if delay > 0:
                time.sleep(delay)
            pool.submit(one_request, args.url, args.timeout).add_done_callback(done)
            n += 1

    rows.sort()
    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["t_send", "latency_ms", "status"])
        w.writerows((f"{t:.6f}", f"{lat:.3f}", s) for t, lat, s in rows)


if __name__ == "__main__":
    main()
