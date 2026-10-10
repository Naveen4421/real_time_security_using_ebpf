#!/usr/bin/env bash
# Response abuse measurement set (RQ4), about 8 hours with RUNS=5.
# An outside attacker calls a public endpoint that makes the app open /etc/shadow, through
# the Service, at 6, 30 or 120 triggers per minute for 300 s; 60 s of recovery is observed after.
#   m0  detect only (control)        m1  Talon pod termination
#   m1g m1 with min_healthy_replicas m3  Tetragon in-kernel kill (kills the server process)
# m2 (egress policy), m4 (block, no kill) and m5 (lockdown of threat routes only) cannot
# take normal traffic down by design, so they are not run here.
# Needs Tetragon (setup/04-install-tetragon.sh) and no KubeArmor. Run inside tmux.
set -uo pipefail
cd "$(dirname "$0")/.."
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
RUNS="${RUNS:-5}"
stamp=$(date +%Y%m%d-%H%M)

batch() {
  local name=$1; shift
  local out="eval/results/abuse-$stamp-$name"
  echo "=== $(date '+%F %T') start $name"
  python3 eval/harness/run.py "$@" --out "$out" && python3 eval/analysis/analyze.py "$out"
  echo "=== $(date '+%F %T') end $name (exit $?)"
}

bash eval/setup/kubearmor.sh uninstall >/dev/null 2>&1
batch 6pm  --mechanisms m0,m1,m1g,m3 --scenarios s3-abuse-6pm  --runs "$RUNS" --warmup 60 --observe 360
batch 30pm --mechanisms m0,m1,m1g,m3 --scenarios s3-abuse-30pm --runs "$RUNS" --warmup 60 --observe 360
batch 120pm --mechanisms m0,m1,m1g,m3 --scenarios s3-abuse-120pm --runs "$RUNS" --warmup 60 --observe 360
echo "=== $(date '+%F %T') all batches finished"
