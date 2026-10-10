# Containment Study: Experiment Harness

Runs the experiments from [docs/containment_study_plan.md](../docs/containment_study_plan.md) on a
single-node k3s cluster. Six mechanisms: detect only (M0), two Kubernetes-level responses through
Falco Talon (M1, M2), two in-kernel enforcers (Tetragon M3, KubeArmor M4) and the app's own RASP (M5).

> **Safety:** run this only on a dedicated machine. It loads eBPF probes into the host kernel, kills
> pods and runs attack-like commands. `00-preflight.sh` refuses to continue if other Docker
> containers are running.

## What gets measured

| Mechanism | What happens on a detection |
|---|---|
| `m0` | Nothing (detect-only baseline) |
| `m1` | Falco Talon deletes the pod (`kubernetes:terminate`, grace period 0); the Deployment recreates it |
| `m2` | Falco Talon creates a NetworkPolicy blocking **egress** for **all replicas** of the Deployment (`kubernetes:networkpolicy`) |
| `m3` | Tetragon kills (SIGKILL, in the kernel) any process in the backend that starts a shell or opens `/etc/shadow` or `/bin/hack` (`mechanisms/tetragon-kill.yaml`) |
| `m4` | KubeArmor (AppArmor enforcer) refuses to run `/bin/busybox` and to open `/etc/shadow` or `/bin/hack` in the backend (`mechanisms/kubearmor-block.yaml`) |
| `m5` | The app's own RASP returns 403 on threat routes for 30 s after 3 threat requests |

M3 and M4 enforce the same two behaviours the Falco eval rules detect, as policies applied before
the pods start; Falco keeps detecting under every mechanism. Two limits found on the lab PC shape M4:
- `/bin/sh` in the Alpine image is a symlink to `/bin/busybox`, and AppArmor matches the resolved
  path, so a policy listing `/bin/sh` blocks nothing. Blocking shells means blocking BusyBox, which
  also blocks `cat`, `ls`, `wget` and every other BusyBox tool.
- The first program started by `kubectl exec` runs before the container's AppArmor profile applies,
  so the attacker's entry shell starts; only the programs it then runs are refused.

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

# Each step runs only if the previous one succeeded
bash eval/setup/00-preflight.sh &&      # checks hardware, kernel, and that the machine is dedicated
bash eval/setup/01-install.sh &&        # Docker (if missing), k3s, Helm (about 5 min)
bash eval/setup/02-build-images.sh &&   # builds the backend image and loads it into k3s
bash eval/setup/03-install-stack.sh &&  # Falco + Falcosidekick + Talon, wired to the collector
bash eval/setup/04-install-tetragon.sh  # Tetragon: M3, and exact process exit times for every run
```

KubeArmor (M4) is installed only for the M4 batch and removed afterwards
(`bash eval/setup/kubearmor.sh install|uninstall`; `run_phase2.sh` does both). Its admission webhook
attaches an AppArmor profile to every new pod, and under such a profile Tetragon fails to restart.
Tetragon's pods carry the `kubearmor-app` label that the webhook skips; Falco Talon's chart cannot
set it.

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
- `L_detect_s`: for `s1` this includes `kubectl exec` start-up (about 0.09 s); report
  `alert_pipeline_s` (kernel event to alert, about 1 to 2 ms) as Falco's detection latency.
- `L_response_s`: attack start to the response action completing: Talon's notification for `m1`/`m2`
  (millisecond precision, collector clock), first HTTP 403 for `m5`.
- `L_api_visible_s`: attack start to the watcher seeing the change in the Kubernetes API (upper
  bound, about 0.3 s resolution). The pod being gone from the API does not mean its processes have
  stopped; use `attack_window_s` and `steps_completed` for what the attacker could still do.
- `steps_completed`: exec steps whose beacon reached the collector and whose exit code does not say
  the step was killed or could not run (137, 126, 127), or HTTP steps not blocked (status other than
  403 or no response; `spawn-shell` returns 500 because `whoami` fails for UID 10001, and the body
  then says "unknown uid"; a 500 without it means the shell was killed or never started). Under `m2`
  a missing beacon means the step's outbound traffic was blocked, which is what network isolation
  is meant to do. Beacons are sent with `node`, not BusyBox `wget`, so M4 cannot silence them.
- `steps_reached`: exec steps after which the attacker's shell was still alive (beacon received,
  whatever the exit code). Under `m4` the shell lives on with every step refused.
- `L_session_end_s` (Tetragon): attack start to the exit of the attacker's `sh -s`, to the
  nanosecond, or to its kill at start under `m3`. `L_kernel_kill_s`: first `m3` kill.
  `L_app_killed_s` (HTTP): first exit of the target pod's `node server.js`.
- `L_block_alert_s` (`m4`): first KubeArmor block alert, read from the relay's stdout.
- `recompromised`: after the observation window, the first attack step is tried again against a
  live backend pod.
- `target_logs_available`: whether the original pod's logs can still be read after the response.
- Talon de-duplicates identical events within 5 s by default (`config.deduplication`); this is left
  at the chart default and should be stated in the paper.

## Risks and cleanup

- Falco runs privileged and sees every process on the PC, including other users' commands. Its alert
  logs stay on the PC; clear them by uninstalling (below).
- k3s changes iptables and adds network interfaces (flannel, cni0). This can disturb Docker
  networking or a VPN until k3s is removed.
- The collector (port 9999) has no authentication. Anyone on the LAN could send fake events into a
  results session. Restrict it with the firewall if the lab network is shared.
- Setup downloads and runs install scripts and images from the internet as root (k3s, Helm, Falco
  charts). Versions are recorded per session in `session.json`.

Remove everything when finished:

```bash
bash eval/setup/kubearmor.sh uninstall
helm uninstall tetragon -n kube-system
helm uninstall falco falco-talon -n falco
/usr/local/bin/k3s-uninstall.sh      # removes k3s, its containers, iptables rules and interfaces
rm -f ~/.kube/config
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| "Pods cannot reach the collector" | Firewall: `sudo ufw allow from 10.42.0.0/16 to any port 9999 proto tcp` |
| No alerts at all | `kubectl logs -n falco ds/falco -c falco \| tail -50`; check the eval rules loaded and the driver started |
| Alerts but `m1` never deletes | `kubectl logs -n falco deploy/falco-talon`; check the Falco rule names match `eval/mechanisms/*.yaml` |
| Image pull errors in namespace `eval` | Re-run `bash eval/setup/02-build-images.sh` |
