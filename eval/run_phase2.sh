#!/usr/bin/env bash
# Phase 2 measurement set (about 9.5 hours): the in-kernel mechanisms and exact kill times.
#   A: Tetragon installed, KubeArmor absent: m0, m1, m3 on both attacks (Tetragon also
#      records when the attacker's shell exits under m0 and m1)
#   B: KubeArmor installed for m4 only, then removed again
# Needs eval/setup/04-install-tetragon.sh first. Run from anywhere: bash eval/run_phase2.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
stamp=$(date +%Y%m%d-%H%M)

batch() {
  local name=$1; shift
  local out="eval/results/p2-$stamp-$name"
  echo "=== $(date '+%F %T') start $name"
  python3 eval/harness/run.py "$@" --out "$out" && python3 eval/analysis/analyze.py "$out"
  echo "=== $(date '+%F %T') end $name (exit $?)"
}

bash eval/setup/kubearmor.sh uninstall >/dev/null 2>&1   # batch A must run without KubeArmor
batch a-s1 --mechanisms m0,m1,m3 --scenarios s1-exec-discovery --runs 20      # ~3.5 h
batch a-s2 --mechanisms m0,m1,m3 --scenarios s2-http-triggers --runs 20       # ~3.5 h

echo "=== $(date '+%F %T') installing KubeArmor"
if bash eval/setup/kubearmor.sh install; then
  batch b-s1 --mechanisms m4 --scenarios s1-exec-discovery --runs 20          # ~1.2 h
  batch b-s2 --mechanisms m4 --scenarios s2-http-triggers --runs 20           # ~1.2 h
else
  echo "=== KubeArmor install failed; batch B skipped"
fi
bash eval/setup/kubearmor.sh uninstall
echo "=== $(date '+%F %T') all batches finished"
