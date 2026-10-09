#!/usr/bin/env bash
# Installs Docker (image builds), k3s (single-node Kubernetes) and Helm.
# Run from the repo root: bash eval/setup/01-install.sh
set -euo pipefail
source eval/config.env

sudo apt-get update
sudo apt-get install -y docker.io python3 curl

# k3s bundles containerd, kubectl and a NetworkPolicy controller (needed for M2).
# The admin kubeconfig stays root-only (k3s default); a private copy goes to
# ~/.kube/config so only this user can control the cluster.
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="$K3S_VERSION" sh -s -
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
