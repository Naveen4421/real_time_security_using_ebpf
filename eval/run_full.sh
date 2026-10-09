#!/usr/bin/env bash
# Full measurement set for the containment study (about 10 hours).
# Run from anywhere: bash eval/run_full.sh
# Each batch writes its own session folder under eval/results/full-<stamp>-<batch>.
set -uo pipefail
cd "$(dirname "$0")/.."
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
stamp=$(date +%Y%m%d-%H%M)

batch() {
  local name=$1; shift
  local out="eval/results/full-$stamp-$name"
  echo "=== $(date '+%F %T') start $name"
  python3 eval/harness/run.py "$@" --out "$out" && python3 eval/analysis/analyze.py "$out"
  echo "=== $(date '+%F %T') end $name (exit $?)"
}

batch s1 --mechanisms m0,m1,m2 --scenarios s1-exec-discovery --runs 20             # ~3.5 h
batch s2 --mechanisms m0,m1,m2,m5 --scenarios s2-http-triggers --runs 20           # ~4.7 h
batch s0 --mechanisms m0 --scenarios s0-benign --runs 4 --observe 1800             # ~2 h, false positives
echo "=== $(date '+%F %T') all batches finished"
