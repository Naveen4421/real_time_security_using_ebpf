# Research Plan: Measuring Automated Runtime Containment in Kubernetes

Status: draft v1, 2026-10-08. Replaces the "integrated framework" framing of the current manuscript.

## 1. Research question

Existing work measures whether eBPF tools *detect* attacks (Her et al. 2025; Syairozi & Arizal 2025).
This study measures what happens *after* detection: how fast, how disruptive, how lossy and how
abusable the automated response mechanisms are, compared side by side on the same attacks.

- **RQ1 (speed):** How long does each mechanism take from the kernel event to effective containment, and how many attack steps complete before it acts?
- **RQ2 (durability):** After containment, is the workload re-compromised (for example, when a deleted pod is recreated from the same vulnerable image)?
- **RQ3 (cost):** How much service disruption and forensic evidence loss does each mechanism cause?
- **RQ4 (abuse):** Can an attacker use the response itself as a denial-of-service lever, and at what cost to the attacker?
- **RQ5 (overhead):** What is the steady-state CPU, memory, throughput and latency overhead of each stack?

Hypotheses to test (not assume):
- H1: In-kernel actions (Tetragon, KubeArmor) contain an attack in less time than API-level actions (Talon) by at least an order of magnitude.
- H2: Pod deletion has the highest re-compromise rate and the highest evidence loss.
- H3: Pod deletion is the cheapest mechanism for an attacker to abuse.

## 2. Mechanisms compared

| ID | Mechanism | Layer | Tool and action |
|---|---|---|---|
| M0 | Detect only (baseline) | none | Falco alerts, no response |
| M1 | Pod termination | Kubernetes API | Falco + Falcosidekick + Talon `kubernetes:terminate` (current setup) |
| M2 | Network isolation | Kubernetes API | Talon `kubernetes:networkpolicy` (blocks egress only, for every replica of the Deployment) |
| M3 | Process kill in kernel | Kernel | Tetragon TracingPolicy with `Sigkill` action |
| M4 | LSM block | Kernel | KubeArmor policy with `Block` action |
| M5 | In-app lockdown | Application | Existing RASP in `app/backend/server.js` |

Optional M6: M1 combined with `kubernetes:label` or `kubernetes:tcpdump` to preserve evidence before deletion.

All of these are existing, documented features. Pin and record every tool version used.

## 3. Testbed

### Facts about the current lab machine (checked 2026-10-08)

| Item | Value | Impact |
|---|---|---|
| CPU / RAM | 8 cores / 78 GB | Enough for one node or small VMs |
| Free disk | 9.6 GB (99% full) | **Blocker.** Free at least 60 GB before starting |
| `/dev/kvm` | Not present | Cannot run local VMs for separate-kernel nodes |
| `minikube`, `kind`, `kubectl`, `helm` | Not installed | Must be installed |
| Kernel / LSMs | 6.8.0, `apparmor` active, `bpf` LSM **not** enabled | KubeArmor will use AppArmor, not BPF-LSM. State this in the paper |
| Shared host | Many unrelated production containers run here | Do not run experiments on this host; overhead numbers would be contaminated |

### Minimum viable setup (use this if resources are limited)

- **1 dedicated machine with its own kernel,** not shared with other workloads: 4+ cores, 8 to 16 GB RAM, 50+ GB free disk, Ubuntu 24.04, single-node k3s or kubeadm with containerd.
- All of RQ1 to RQ5 are measured on the node where the attack runs, so a single node answers them. State "single node" as a limitation; multi-node becomes future work.
- Bare metal (a spare lab PC) is preferred over a cloud VM, because noisy neighbours on shared cloud hosts add variance to the overhead numbers.
- Development can happen on any laptop with kind. Only the final measurement runs (weeks 6 to 8) need the dedicated machine.

### Recommended setup (if resources allow)

- **3 nodes, each with its own kernel:** 3 lab PCs or 3 cloud VMs (for example 4 vCPU / 8 GB each), Ubuntu 24.04, kubeadm, containerd.
- **Do not use kind for the main results.** kind nodes share one host kernel, so each node's eBPF agent can see the other nodes' syscalls. This distorts both detection and overhead. kind is fine for developing the harness.
- **Agent installation:** Falco, Tetragon and KubeArmor each installed as a DaemonSet via Helm. Only the stack under test runs during a measurement run.
- **Clock synchronisation:** chrony on all nodes. Record the measured offset before each run.
- **Record:** hardware, kernel version and config (`CONFIG_BPF_LSM`, `CONFIG_BPF_KPROBE_OVERRIDE`), container runtime, and every tool version.

## 4. Workload and attack set

### Workload
- The existing demo app (frontend + backend), with 2 replicas so disruption can be measured.
- A load generator (k6 or wrk) at 3 fixed request rates. Load runs during every attack run.

### Attack set
- Use established, publicly documented adversary-emulation test suites instead of hand-written endpoints:
  - Falco `event-generator`
  - Atomic Red Team container tests
- Map every scenario to a MITRE ATT&CK for Containers technique ID.
- Target 10 to 15 multi-step scenarios covering:
  - execution
  - credential access
  - persistence
  - discovery
  - privilege escalation
  - escape attempts
- Run all attack material only inside the isolated lab cluster.
- Keep the three `/api/threat/*` endpoints only as a smoke test, not as evaluation data.

### Ground truth
- Each attack step sends a small timestamped beacon to a collector **outside** the cluster.
- The number of beacons received is the number of steps that completed before containment.
- This needs no data from the pod, so it still works after the pod is killed.

## 5. Metrics (exact definitions)

| Metric | Definition | Answers |
|---|---|---|
| `L_kern` | Enforcement time minus kernel event time (Falco `evt.time` or Tetragon/KubeArmor event time) | RQ1 |
| `L_cont` | Time of the last beacon received minus the first attack beacon | RQ1 |
| Steps completed | Beacons received per run, out of the scenario's total steps | RQ1 |
| Re-compromise rate | Share of runs where the same attack succeeds again on the replacement or isolated pod within 60 s | RQ2 |
| Evidence retained | Checklist per run: process tree, file changes, network capture, container logs available after the response | RQ3 |
| Disruption | Error rate and p99 latency of benign traffic in the 60 s after the response, compared with the baseline | RQ3 |
| Abuse cost | Attacker requests needed to cause N restarts per minute, and the resulting availability of benign traffic | RQ4 |
| Overhead | Node CPU and memory, app throughput, p99 latency at 3 load levels, with and without each stack | RQ5 |
| Event loss | Falco drop counters, and events generated vs. received at increasing syscall rates | RQ5 |
| Detection | Per-scenario detection rate, plus false positives during a 2-hour benign-only run | context |

- **Unit of a true positive:** one scenario run, counted as detected if at least one alert fires within 10 s of the first step.
- **False positives:** alerts during benign-only runs, reported per hour.

## 6. Procedure

1. For each (mechanism, scenario) pair: N = 20 runs. Randomise run order across mechanisms.
2. For each run:
   - Deploy fresh pods and wait for readiness.
   - Run a 60 s warm-up under load.
   - Start the attack.
   - Collect data for 120 s.
   - Tear everything down.
3. Count failed runs and never discard them.
4. Statistics:
   - Report median, p95 and p99 with bootstrap 95% confidence intervals.
   - Compare mechanisms with Kruskal-Wallis, followed by pairwise Mann-Whitney U tests with a Holm correction.
5. Store raw data (CSV, JSON) in the repo, and archive it with the code on Zenodo for a DOI.

## 7. Repository work

New `eval/` directory (M0, M1, M2 and M5 implemented; see `eval/README.md`):

```
eval/
  cluster/        kubeadm notes, Helm values for Falco/Tetragon/KubeArmor, version pins
  mechanisms/     one folder per M0..M6 with its policies and a switch script
  scenarios/      scenario definitions, ATT&CK IDs, step lists
  collector/      out-of-cluster beacon and timestamp collector
  load/           k6/wrk scripts
  harness/        run orchestrator (loops, randomisation, teardown, data capture)
  analysis/       notebook/scripts producing every figure and table in the paper
  data/           raw results (or a link to the Zenodo archive)
```

Fixes to existing code (from the review and our own repo check):
- Fix the `/bin/hack` quarantine logic, or remove the claim (`app/backend/server.js:302`).
- Restrict the shell rule to shell binaries (`configs/falco_rules.local.yaml`).
- Pin the Trivy action and gate the build on fixable CRITICAL findings (`.github/workflows/ci.yml`).
- Remove the hardcoded kubeconfig path (`configs/talon-config.yaml`).
- Decide on Jenkins: add a `Jenkinsfile` or remove it from the paper.
- Remove the ML layer from the paper and keep the code in the repo, labelled as future work.

## 8. Paper outline (target 10 to 12 pages)

1. Introduction: the gap is response, not detection. RQ1 to RQ5. Contributions phrased as findings.
2. Related work: 35 to 50 references, ending with a comparison table.
3. Threat model, including the attacker abusing the response.
4. Mechanisms and testbed.
5. Methodology (Sections 4 to 6 of this plan).
6. Results: one subsection per RQ, each with a figure or table.
7. Discussion: when to use which mechanism, a recommended layered response, and limitations.
8. Conclusion, plus code and data availability.

Working title: *Measuring Automated Runtime Containment in Kubernetes: Latency, Disruption, and Abuse of eBPF-Based Response Mechanisms.*

## 9. Timeline (about 12 weeks)

| Weeks | Work |
|---|---|
| 1 | Literature check (IEEE Xplore, Scopus, Scholar) to confirm the gap. Free disk space and get 3 nodes |
| 2 to 3 | Build the cluster, install and pin the stacks, apply the code fixes above |
| 3 to 5 | Build the harness, collector, load scripts and scenarios. Pilot runs on kind |
| 6 to 8 | Full measurement runs on the 3-node cluster |
| 9 | Analysis and figures |
| 10 to 11 | Write the paper, including the related-work rewrite and IEEE template |
| 12 | Internal review, similarity check, declarations, submission |

## 10. Risks

| Risk | Mitigation |
|---|---|
| A similar study appears during the work | Week-1 literature check, then re-check before submission. Our angle (abuse plus re-compromise plus evidence) is still distinct |
| No separate-kernel nodes available | Use the single-node minimum setup (Section 3) and state it as a limitation |
| Tool-version differences skew comparisons | Pin versions, use equivalent policies per mechanism, publish all policies |
| Kernel lacks features (BPF-LSM, kprobe override) | Record the kernel config. Use the AppArmor enforcer and Sigkill, which do not need them |
| Clock skew corrupts latency | Measure latency at the single collector where possible, and log the chrony offset per run |

## 11. Decisions needed from the team

1. Which dedicated machine runs the measurements: a spare lab PC (preferred) or a student-credit cloud VM? 3 nodes are optional.
2. Who owns each part: cluster, harness, scenarios, analysis, writing?
3. Target journal. This affects page limit and template.
4. Confirm that the ML layer is dropped from this paper.
