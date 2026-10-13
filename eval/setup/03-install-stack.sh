#!/usr/bin/env bash
# Installs Falco + Falcosidekick + Falco Talon with Helm, wired to the collector.
# Run from the repo root: bash eval/setup/03-install-stack.sh
set -euo pipefail
source eval/config.env
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found: run eval/setup/01-install.sh first"; exit 1; }

node_ip=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
collector="http://${node_ip}:${COLLECTOR_PORT}"
echo "Collector URL (must be reachable from pods): $collector"

helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1 || true
helm repo update

# Download each chart once (with retries, for slow networks) into eval/stack/charts/.
# The harness reuses these files, so every run uses exactly the same chart version.
charts=eval/stack/charts
mkdir -p "$charts"
pull() {  # pull <chart> <version-or-empty> <glob>
  ls $charts/$3 >/dev/null 2>&1 && return 0
  for i in 1 2 3 4 5; do
    helm pull "falcosecurity/$1" ${2:+--version "$2"} -d "$charts" && return 0
    echo "Download of $1 failed (attempt $i/5), retrying in 10 s..."
    sleep 10
  done
  echo "Could not download chart $1. Check the internet connection and re-run this script."
  exit 1
}
pull falco-talon "$TALON_CHART_VERSION" 'falco-talon-*.tgz'
pull falco "$FALCO_CHART_VERSION" 'falco-[0-9]*.tgz'
talon_chart=$(ls $charts/falco-talon-*.tgz | head -1)
falco_chart=$(ls $charts/falco-[0-9]*.tgz | head -1)
echo "Charts: $talon_chart $falco_chart"

helm upgrade --install falco-talon "$talon_chart" -n falco --create-namespace \
  -f eval/stack/talon-values.yaml \
  --set config.notifiers.webhook.url="${collector}/talon" \
  --set-file config.rulesOverride=eval/mechanisms/talon-none.yaml \
  --wait --timeout 5m

talon_svc=$(kubectl get svc -n falco -o name | grep talon | head -1 | cut -d/ -f2)
[ -n "$talon_svc" ] || { echo "Talon service not found"; exit 1; }
echo "Talon service: $talon_svc"

helm upgrade --install falco "$falco_chart" -n falco \
  -f eval/stack/falco-values.yaml \
  --set falcosidekick.config.webhook.address="${collector}/falco" \
  --set falcosidekick.config.talon.address="http://${talon_svc}.falco.svc:2803" \
  --wait --timeout 10m

kubectl get pods -n falco
helm list -n falco
echo
echo "If a firewall (ufw) is active, allow pods to reach the collector, e.g.:"
echo "  sudo ufw allow from 10.42.0.0/16 to any port ${COLLECTOR_PORT} proto tcp"
