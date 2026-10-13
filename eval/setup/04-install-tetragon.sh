#!/usr/bin/env bash
# Installs Tetragon (M3, and exact process exec/exit times for every run).
# Run from the repo root: bash eval/setup/04-install-tetragon.sh
set -euo pipefail
source eval/config.env
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
command -v helm >/dev/null 2>&1 || { echo "helm not found: run eval/setup/01-install.sh first"; exit 1; }

charts=eval/stack/charts
mkdir -p "$charts"
if ! ls $charts/tetragon-*.tgz >/dev/null 2>&1; then
  for i in 1 2 3 4 5; do helm repo add cilium https://helm.cilium.io >/dev/null 2>&1 && break; sleep 10; done
  helm repo update cilium
  for i in 1 2 3 4 5; do
    helm pull cilium/tetragon ${TETRAGON_CHART_VERSION:+--version "$TETRAGON_CHART_VERSION"} -d "$charts" && break
    echo "Download failed (attempt $i/5), retrying in 10 s..."; sleep 10
  done
fi
chart=$(ls $charts/tetragon-*.tgz | head -1)
echo "Chart: $chart"

helm upgrade --install tetragon "$chart" -n kube-system -f eval/stack/tetragon-values.yaml --wait --timeout 10m
kubectl rollout status -n kube-system ds/tetragon --timeout=180s
kubectl get pods -n kube-system -l app.kubernetes.io/name=tetragon
