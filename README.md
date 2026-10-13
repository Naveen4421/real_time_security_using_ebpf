# Automated Containment of Compromised Kubernetes Workloads

A measurement study of automated runtime-security responses for a compromised
container in Kubernetes, built on eBPF tooling. The project asks a question that
detection-focused work usually skips: once an alert fires, **what should the
system do in the next few seconds, and what does each option actually cost?**

Six responses are compared on one application under the same attacks, on a
dedicated single-node testbed, with every claim backed by released data. The
measurements are complete; the accompanying IEEE paper is in
[`docs/paper/`](docs/paper/).

---

## The question

An attacker who exploits a workload typically tries to spawn a shell inside the
container and move on from there. Detection (Falco) sees this in about 2 ms. The
open question is the **response**: terminate the pod, cut its network, kill the
process in the kernel, block each action, or defend from inside the app. Each
trades off differently on speed, durability, forensic evidence, resistance to
abuse, and running cost. This repository measures those trade-offs.

## Mechanisms compared

| ID  | Response on detection | Tool / layer |
|-----|-----------------------|--------------|
| M0  | Detect only (baseline) | Falco (eBPF) |
| M1  | Delete the pod; the Deployment recreates it | Falco Talon |
| M1g | M1 with a minimum-healthy-replicas guard | Falco Talon |
| M2  | Apply an egress-blocking NetworkPolicy | Falco Talon + Kubernetes |
| M3  | `SIGKILL` the offending process in the kernel | Tetragon (eBPF kprobe) |
| M4  | Refuse each dangerous action; process stays alive | KubeArmor (AppArmor LSM) |
| M5  | Return 403 from inside the app on threat routes | In-app RASP (`app/backend/server.js`) |

## What the measurements show

580 attack and abuse runs plus 200 overhead windows, none discarded. The central
result: **no mechanism wins on speed, durability, evidence, abuse-resistance, and
cost together, which argues for a layered response chosen per workload.**

| Experiment | Runs | One-line result |
|---|---|---|
| Detection + containment (s1, s2) | ~320 | Falco alerts in ~2 ms; M1 returns from the API in 0.02-0.10 s but the attacker's process lives ~2 s and re-compromises the replacement pod every time; M3 kills the shell in 0.09 s with no step completed; M4 refuses every command but the shell stays alive |
| Abuse of the response (RQ4) | 60 | At 6 triggers/min, in-kernel termination (M3) kept the service unavailable 225 of 300 s; the M1g replica guard removes the outage entirely (0 s down) |
| Steady-state overhead (RQ5) | 200 windows | At 2,500 req/s, Tetragon adds under 0.1 ms p99; KubeArmor at default visibility uses about 1.2 extra cores |
| Realistic attacks (RQ6) | 100 | 13 MITRE ATT&CK-tagged actions from Falco's `event-generator`: M3 kills the shell on spawn before any technique runs; M5 is blind to syscall-level attacks |

A per-mechanism scorecard across all five dimensions is in the paper (Table V)
and in [`docs/containment_progress.md`](docs/containment_progress.md).

## Testbed

Single-node k3s on an HP 280 Pro G6, Ubuntu 22.04 (kernel 6.8). Falco, Falco
Talon, Tetragon, and KubeArmor (AppArmor back end) as the response layers; a
`node:18-alpine` backend running non-root with two replicas as the target. All
timestamps come from one host clock. Experiments ran only on this dedicated lab
machine, never on a shared or production host.

## Reproducing the measurements

The harness, scenarios, mechanism configs, and analysis live in
[`eval/`](eval/README.md).

```bash
cd eval
# one-time: install the stack and build the static event-generator binary
ls setup/                     # 0x-*.sh install scripts
bash setup/05-build-eventgen.sh

# run the suites (each writes raw per-run data under eval/results/)
bash run_full.sh              # detection + containment (s1, s2)
bash run_phase2.sh            # Tetragon / KubeArmor exit-time detail
bash run_abuse.sh             # RQ4 abuse
bash run_realistic.sh         # RQ6 realistic MITRE-tagged suite
# overhead (RQ5) lives under eval/overhead/

# analyse
python3 analysis/analyze.py
```

## Repository layout

| Path | Contents |
|---|---|
| [`eval/`](eval/README.md) | Measurement harness, attack scenarios, mechanism configs, analysis scripts, raw results |
| [`app/`](app/) | Target full-stack app; the backend also implements the M5 in-app RASP |
| [`docs/paper/`](docs/paper/) | IEEE paper (PDF + DOCX), figures, and LaTeX sources |
| [`docs/containment_progress.md`](docs/containment_progress.md) | Running write-up of every experiment and result |
| [`docs/containment_study_plan.md`](docs/containment_study_plan.md) | Study plan and mechanism definitions |
| [`ml_pipeline/`](ml_pipeline/) | Prototype learned-scoring layer (future work; see below) |
| [`configs/`](configs/) | Local and Kubernetes infrastructure manifests |

## Learned-scoring layer (future work)

`ml_pipeline/` contains a design for a machine-learning layer meant to flag
behaviour no hand-written rule anticipates: a 14-feature per-container window fed
to an isolation forest and a PyTorch autoencoder, combined into an anomaly score.

This layer is **future work and is not part of the measured results.** The code
has only been exercised on synthetic data (105 samples), has not run on live
Falco telemetry, and no accuracy is claimed for it. The planned path to make it
real: capture benign telemetry from live Falco events, build a labeled
attack/benign set from the `eval/` scenarios, fit a feature scaler at training
time, then measure precision, recall, and false-positive rate under the same
protocol before it is ever allowed to trigger automated enforcement.

## Paper

- [`docs/paper/eBPF_Containment_Measurement_IEEE.pdf`](docs/paper/) and the
  editable `.docx` alongside it.
- Title: *A Measurement Study of Automated Containment for Compromised Kubernetes
  Workloads: An eBPF-Based Cross-Layer Comparison.*

## License

See [LICENSE](LICENSE).
