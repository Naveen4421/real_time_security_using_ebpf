#!/usr/bin/env bash
# Installs Docker (image builds), k3s (single-node Kubernetes) and Helm.
# Run from the repo root: bash eval/setup/01-install.sh
set -euo pipefail
source eval/config.env

sudo apt-get update
sudo apt-get install -y docker.io python3 curl

# k3s bundles containerd, kubectl and a NetworkPolicy controller (needed for M2).
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="$K3S_VERSION" sh -s - --write-kubeconfig-mode 644
mkdir -p "$HOME/.kube"
cp /etc/rancher/k3s/k3s.yaml "$HOME/.kube/config"
chmod 600 "$HOME/.kube/config"

if ! command -v helm >/dev/null 2>&1; then
  curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

kubectl wait --for=condition=Ready node --all --timeout=180s
kubectl get nodes -o wide
helm version
