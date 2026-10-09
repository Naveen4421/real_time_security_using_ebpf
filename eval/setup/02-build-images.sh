#!/usr/bin/env bash
# Builds the backend image and imports it into k3s's containerd.
# Run from the repo root after every backend code change: bash eval/setup/02-build-images.sh
set -euo pipefail
command -v k3s >/dev/null 2>&1 || { echo "k3s not installed: run eval/setup/01-install.sh first"; exit 1; }
tmp=$(mktemp --suffix=.tar)
trap 'sudo rm -f "$tmp"' EXIT   # docker save (as root) replaces the file
sudo docker build -t ebpf-demo-backend:eval app/backend
sudo docker save ebpf-demo-backend:eval -o "$tmp"
sudo k3s ctr images import "$tmp"
sudo k3s ctr images ls | grep ebpf-demo-backend
