#!/usr/bin/env bash
# Installs Docker (image builds), k3s (single-node Kubernetes) and Helm.
# Run from the repo root: bash eval/setup/01-install.sh
set -euo pipefail
source eval/config.env

# Install only what is missing. An existing Docker (apt docker-ce or snap) is
# kept: installing docker.io on top of docker-ce causes package conflicts.
need=()
command -v python3 >/dev/null 2>&1 || need+=(python3)
command -v curl >/dev/null 2>&1 || need+=(curl)
command -v docker >/dev/null 2>&1 || need+=(docker.io)
if [ ${#need[@]} -gt 0 ]; then
  # A broken third-party apt source on the machine must not stop the setup.
  sudo apt-get update || echo "WARN: apt-get update reported errors; continuing"
  sudo apt-get install -y "${need[@]}"
fi

# k3s bundles containerd, kubectl and a NetworkPolicy controller (needed for M2).
# The admin kubeconfig stays root-only (k3s default); a private copy goes to
# ~/.kube/config so only this user can control the cluster.
# Traefik is disabled: the experiments do not use it, and it would claim ports
# 80/443 (clashing with e.g. Apache) and add background load.
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="$K3S_VERSION" sh -s - --disable traefik
mkdir -p "$HOME/.kube"
sudo install -m 600 -o "$(id -u)" -g "$(id -g)" /etc/rancher/k3s/k3s.yaml "$HOME/.kube/config"
export KUBECONFIG="$HOME/.kube/config"
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
  [ -f "$rc" ] && { grep -q 'KUBECONFIG=' "$rc" || echo 'export KUBECONFIG="$HOME/.kube/config"' >> "$rc"; }
done

if ! command -v helm >/dev/null 2>&1; then
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

kubectl wait --for=condition=Ready node --all --timeout=180s
kubectl get nodes -o wide
helm version
