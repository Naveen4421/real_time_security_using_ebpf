#!/usr/bin/env bash
# Checks that this machine is suitable and safe for the experiments.
# Run from the repo root: bash eval/setup/00-preflight.sh
set -uo pipefail
fail=0
echo "Kernel: $(uname -r)"
echo "CPUs: $(nproc)   RAM: $(free -g | awk '/Mem:/{print $2}') GB   Free disk: $(df -BG --output=avail / | tail -1 | tr -d ' ')"
[ "$(nproc)" -ge 4 ] || { echo "WARN: fewer than 4 CPUs"; }
[ "$(df -BG --output=avail / | tail -1 | tr -dc 0-9)" -ge 30 ] || { echo "FAIL: need at least 30 GB free disk"; fail=1; }
echo "Virtualization: $(systemd-detect-virt 2>/dev/null || echo unknown)"
grep -qE 'CONFIG_BPF_SYSCALL=y' "/boot/config-$(uname -r)" 2>/dev/null || { echo "FAIL: kernel lacks BPF syscall support"; fail=1; }
echo "Active LSMs: $(cat /sys/kernel/security/lsm 2>/dev/null)"

# Safety guard: experiments load kernel probes and kill pods. Refuse to continue
# on a host that already runs other workloads.
if command -v docker >/dev/null 2>&1; then
  others=$(sudo docker ps -q 2>/dev/null | wc -l)
  if [ "$others" -gt 0 ]; then
    echo "FAIL: $others Docker containers are already running. Use a dedicated machine for experiments."
    fail=1
  fi
fi
[ $fail -eq 0 ] && echo "Preflight OK" || { echo "Preflight FAILED"; exit 1; }
