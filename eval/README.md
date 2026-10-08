# Containment Study: Experiment Harness

Runs the experiments from [docs/containment_study_plan.md](../docs/containment_study_plan.md) on a
single-node k3s cluster. Implemented so far: the four mechanisms that act through Kubernetes or the
app (M0, M1, M2, M5). Tetragon (M3) and KubeArmor (M4) come later.

> **Safety:** run this only on a dedicated machine. It loads eBPF probes into the host kernel, kills
> pods and runs attack-like commands. `00-preflight.sh` refuses to continue if other Docker
> containers are running.

## What gets measured

| Mechanism | What happens on a detection |
|---|---|
| `m0` | Nothing (detect-only baseline) |
| `m1` | Falco Talon deletes the pod (`kubernetes:terminate`, grace period 0); the Deployment recreates it |
| `m2` | Falco Talon creates a NetworkPolicy blocking **egress** for **all replicas** of the Deployment (`kubernetes:networkpolicy`) |
| `m5` | The app's own RASP returns 403 on threat routes for 30 s after 3 threat requests |

| Scenario | What it does |
|---|---|
| `s0-benign` | Normal traffic only. Measures false positives |
| `s1-exec-discovery` | `kubectl exec` into the target pod, then 8 benign discovery and sensitive-path steps, 1 s apart |
| `s2-http-triggers` | 8 calls to the app's `/api/threat/*` endpoints. The only scenario `m5` reacts to |

Every attack step sends a beacon to a collector running on the host, outside the cluster. Falco
alerts (via Falcosidekick) and Talon actions are sent to the same collector, so all times come from
one clock. A benign load of 50 requests/s runs through the Service during every run.

## Run it on the demo machine

Requirements: Ubuntu 22.04 or 24.04, 4+ CPUs, 8+ GB RAM, 30+ GB free disk, sudo, internet access.

```bash
git clone -b containment-eval https://github.com/Naveen4421/real_time_security_using_ebpf.git
cd real_time_security_using_ebpf

bash eval/setup/00-preflight.sh       # checks hardware, kernel, and that the machine is dedicated
bash eval/setup/01-install.sh         # Docker, k3s, Helm (about 5 min)
bash eval/setup/02-build-images.sh    # builds the backend image and loads it into k3s
bash eval/setup/03-install-stack.sh   # Falco + Falcosidekick + Talon, wired to the collector
```

### 1. Smoke test (about 5 minutes)

```bash
python3 eval/harness/run.py --mechanisms m0,m1 --scenarios s1-exec-discovery \
  --runs 1 --warmup 10 --observe 30
python3 eval/analysis/analyze.py eval/results/<session printed above>
```

Check the printed summary:
- both rows show `detect=` with a number (Falco alerts arrive),
- the `m1` row shows `response=` with a number (Talon deleted the pod),
- `m0` completes all 8 steps, `m1` fewer.

If any of these fail, see Troubleshooting before running the full set.

### 2. Full runs (overnight)

Each run takes about 3.5 minutes (deploy, 60 s warm-up, 120 s observation, teardown). Run inside
`tmux` so it survives a dropped SSH session:

```bash
tmux new -s eval
python3 eval/harness/run.py --mechanisms m0,m1,m2 --scenarios s1-exec-discovery --runs 20       # ~3.5 h
python3 eval/harness/run.py --mechanisms m0,m1,m2,m5 --scenarios s2-http-triggers --runs 20     # ~4.7 h
python3 eval/harness/run.py --mechanisms m0 --scenarios s0-benign --runs 4 --observe 1800       # ~2 h, false positives
```

Detach with `Ctrl-b d`, reattach with `tmux attach -t eval`.

### 3. Analyse

```bash
python3 eval/analysis/analyze.py eval/results/<session>
```

Produces `runs.csv` (one row per run) and `summary.csv` (per mechanism and scenario: median, p95 and
bootstrap 95% CI). Results are git-ignored; copy the session folders off the machine, or commit them
deliberately with `git add -f` when they are final.

## Output layout

```
eval/results/<session>/
  session.json          kernel, k3s, Helm release versions, LSMs, CPU count
  plan.json             arguments and the shuffled run order
  events.jsonl          every beacon, Falco alert and Talon action (collector receive time)
  runs/<run>/meta.json  run timings, pod/NetworkPolicy timeline, re-compromise and evidence checks
  runs/<run>/load.csv   every benign request: send time, latency, status
  runs/<run>/pods.jsonl raw watcher samples (every 0.25 s)
  runs.csv, summary.csv written by analyze.py
```

## Metric notes

- `L_detect_s`: attack start to the first Falco alert reaching the collector.
- `alert_pipeline_s`: Falco's kernel event time to collector receive time.
- `L_response_s`: attack start to the response being visible (pod marked for deletion, NetworkPolicy
  present, or first 403 from RASP). Watcher resolution is about 0.25 to 0.5 s.
- `steps_completed`: attack steps whose beacon reached the collector. Under `m2` a missing beacon
  means the step's outbound traffic was blocked, which is what network isolation is meant to do.
- `recompromised`: after the observation window, the first attack step is tried again against a
  live backend pod.
- `target_logs_available`: whether the original pod's logs can still be read after the response.
- Talon de-duplicates identical events within 5 s by default (`config.deduplication`); this is left
  at the chart default and should be stated in the paper.

## Troubleshooting

| Symptom | Fix |
|---|---|
| "Pods cannot reach the collector" | Firewall: `sudo ufw allow from 10.42.0.0/16 to any port 9999 proto tcp` |
| No alerts at all | `kubectl logs -n falco ds/falco -c falco \| tail -50`; check the eval rules loaded and the driver started |
| Alerts but `m1` never deletes | `kubectl logs -n falco deploy/falco-talon`; check the Falco rule names match `eval/mechanisms/*.yaml` |
| Image pull errors in namespace `eval` | Re-run `bash eval/setup/02-build-images.sh` |
