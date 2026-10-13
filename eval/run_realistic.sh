#!/usr/bin/env bash
# Realistic-attack measurement set (RQ6), about 3 to 4 hours with RUNS=20.
# A curated suite of Falco event-generator syscall actions (eval/scenarios/s4-realistic.json),
# each tagged with a MITRE ATT&CK technique, is run inside the target container under each
# mechanism. This replaces the hand-written attacks for the detection/response comparison.
#   m0  detect only (control)   m1  Talon pod termination   m3  Tetragon in-kernel kill
#   m4  KubeArmor block         m5  in-app RASP lockdown
# Needs the static binary (eval/setup/05-build-eventgen.sh), Tetragon (m3) and KubeArmor (m4).
# KubeArmor is installed only for the m4 batch, as in run_phase2.sh. Run inside tmux.
set -uo pipefail
cd "$(dirname "$0")/.."
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
RUNS="${RUNS:-20}"
stamp=$(date +%Y%m%d-%H%M)

batch() {
  local name=$1; shift
  local out="eval/results/realistic-$stamp-$name"
  echo "=== $(date '+%F %T') start $name"
  python3 eval/harness/run.py "$@" --scenarios s4-realistic --runs "$RUNS" \
    --warmup 20 --observe 120 --out "$out" && python3 eval/analysis/analyze.py "$out"
  echo "=== $(date '+%F %T') end $name (exit $?)"
}

# Mechanisms that need no KubeArmor first (its webhook disrupts Tetragon restarts).
bash eval/setup/kubearmor.sh uninstall >/dev/null 2>&1
batch main --mechanisms m0,m1,m3,m5

# KubeArmor batch last, then remove it.
bash eval/setup/kubearmor.sh install
batch m4 --mechanisms m4
bash eval/setup/kubearmor.sh uninstall
echo "=== $(date '+%F %T') all batches finished"
