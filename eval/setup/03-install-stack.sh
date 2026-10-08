#!/usr/bin/env bash
# Installs Falco + Falcosidekick + Falco Talon with Helm, wired to the collector.
# Run from the repo root: bash eval/setup/03-install-stack.sh
set -euo pipefail
source eval/config.env

node_ip=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
collector="http://${node_ip}:${COLLECTOR_PORT}"
echo "Collector URL (must be reachable from pods): $collector"

helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1 || true
helm repo update

helm upgrade --install falco-talon falcosecurity/falco-talon -n falco --create-namespace \
  ${TALON_CHART_VERSION:+--version "$TALON_CHART_VERSION"} \
  -f eval/stack/talon-values.yaml \
  --set config.notifiers.webhook.url="${collector}/talon" \
  --set-file config.rulesOverride=eval/mechanisms/talon-none.yaml \
  --wait --timeout 5m

talon_svc=$(kubectl get svc -n falco -o name | grep talon | head -1 | cut -d/ -f2)
[ -n "$talon_svc" ] || { echo "Talon service not found"; exit 1; }
echo "Talon service: $talon_svc"

helm upgrade --install falco falcosecurity/falco -n falco \
  ${FALCO_CHART_VERSION:+--version "$FALCO_CHART_VERSION"} \
  -f eval/stack/falco-values.yaml \
  --set falcosidekick.config.webhook.address="${collector}/falco" \
  --set falcosidekick.config.talon.address="http://${talon_svc}.falco.svc:2803" \
  --wait --timeout 10m

kubectl get pods -n falco
helm list -n falco
echo
echo "If a firewall (ufw) is active, allow pods to reach the collector, e.g.:"
echo "  sudo ufw allow from 10.42.0.0/16 to any port ${COLLECTOR_PORT} proto tcp"
