#!/usr/bin/env python3
"""Out-of-cluster event collector: the single clock for every timestamp in a run.

Endpoints (all record a receive time `t` in Unix seconds, host clock):
  GET  /beacon?run=<id>&step=<n>  attack-step beacon sent from inside the target pod
  POST /falco                     Falcosidekick webhook output (one Falco alert)
  POST /talon                     Falco Talon webhook notifier (one response action)
  GET  /run?id=<id>               harness marks the current run; alerts are tagged with it
  GET  /health                    liveness check
Records are appended as JSON lines to <out>/events.jsonl.
"""
import argparse
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

_lock = threading.Lock()
_state = {"run": None, "out": None}


def record(rec):
    rec.setdefault("run", _state["run"])
    line = json.dumps(rec, separators=(",", ":"))
    with _lock:
        with open(_state["out"], "a") as f:
            f.write(line + "\n")


class Handler(BaseHTTPRequestHandler):
    def _reply(self, code=200, body=b"ok"):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        t = time.time()
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.path == "/beacon":
            record({"t": t, "type": "beacon", "run": q.get("run"), "step": q.get("step")})
        elif url.path == "/run":
            _state["run"] = q.get("id")
            record({"t": t, "type": "run_start"})
        elif url.path != "/health":
            return self._reply(404, b"not found")
        self._reply()

    def do_POST(self):
        t = time.time()
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {"unparsed": raw.decode(errors="replace")}
        path = urlparse(self.path).path
        if path == "/falco":
            fields = body.get("output_fields") or {}
            record({
                "t": t,
                "type": "alert",
                "rule": body.get("rule"),
                "priority": body.get("priority"),
                "evt_time": body.get("time"),
                "pod": fields.get("k8s.pod.name"),
                "namespace": fields.get("k8s.ns.name"),
            })
        elif path == "/talon":
            record({"t": t, "type": "action", "body": body})
        else:
            return self._reply(404, b"not found")
        self._reply()

    def log_message(self, fmt, *args):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--out", required=True, help="directory for events.jsonl")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    _state["out"] = os.path.join(args.out, "events.jsonl")
    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"collector listening on :{args.port}, writing {_state['out']}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
