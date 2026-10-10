#!/usr/bin/env bash
# Installs or removes KubeArmor (M4). Install it only for the M4 batch: its admission
# webhook attaches an AppArmor profile to every new pod (Falco Talon included, whose chart
# cannot set the exclusion label), and Tetragon fails to restart under such a profile.
# Run from the repo root: bash eval/setup/kubearmor.sh install|uninstall
set -euo pipefail
source eval/config.env
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
charts=eval/stack/charts

case "${1:-}" in
install)
  mkdir -p "$charts"
  if ! ls $charts/kubearmor-operator-*.tgz >/dev/null 2>&1; then
    for i in 1 2 3 4 5; do helm repo add kubearmor https://kubearmor.github.io/charts >/dev/null 2>&1 && break; sleep 10; done
    helm repo update kubearmor
    for i in 1 2 3 4 5; do
      helm pull kubearmor/kubearmor-operator ${KUBEARMOR_CHART_VERSION:+--version "$KUBEARMOR_CHART_VERSION"} -d "$charts" && break
      echo "Download failed (attempt $i/5), retrying in 10 s..."; sleep 10
    done
  fi
  chart=$(ls $charts/kubearmor-operator-*.tgz | head -1)
  echo "Chart: $chart"
  helm upgrade --install kubearmor-operator "$chart" -n kubearmor --create-namespace \
    -f eval/stack/kubearmor-values.yaml --wait --timeout 10m
  # The operator then creates the agent, controller (webhook) and relay.
  for i in $(seq 1 60); do
    kubectl get deploy -n kubearmor kubearmor-relay >/dev/null 2>&1 && \
      kubectl get mutatingwebhookconfiguration kubearmor-controller-mutating-webhook-configuration >/dev/null 2>&1 && break
    sleep 5
  done
  kubectl wait -n kubearmor --for=condition=Available deploy --all --timeout=300s
  kubectl rollout status -n kubearmor ds --timeout=300s 2>/dev/null || true
  kubectl get pods -n kubearmor
  ;;
uninstall)
  kubectl delete kubearmorconfig --all -A --wait=true --timeout=120s 2>/dev/null || true
  sleep 10
  helm uninstall kubearmor-operator -n kubearmor --wait --timeout 3m 2>/dev/null || true
  # The operator does not remove its webhook; left behind it would block pod creation.
  kubectl delete mutatingwebhookconfiguration kubearmor-controller-mutating-webhook-configuration --ignore-not-found
  kubectl delete ns kubearmor --ignore-not-found --wait=true --timeout=180s
  echo "KubeArmor removed. Its AppArmor profiles stay loaded on the host until reboot (unused)."
  ;;
*)
  echo "usage: bash eval/setup/kubearmor.sh install|uninstall"; exit 1 ;;
esac
