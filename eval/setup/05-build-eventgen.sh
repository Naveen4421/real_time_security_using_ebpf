#!/usr/bin/env bash
# Builds a STATIC Falco event-generator binary for the realistic-attack scenario (RQ6, s4).
# The upstream release binary is dynamically linked against glibc and will not run in the
# Alpine (musl) backend container, so we build it CGO-free from the pinned source tag.
# Output: eval/attack/event-generator (git-ignored). Needs Docker (preferred) or Go >= 1.26.
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION="${EVENTGEN_VERSION:-v0.13.0}"
REPO="https://github.com/falcosecurity/event-generator"
out="eval/attack"
mkdir -p "$out"

build_in_docker() {
  # One container: fetch source at the tag, generate the embedded bundle, build static.
  docker run --rm -v "$PWD/$out:/out" golang:1.26 bash -euc "
    git clone --depth 1 --branch $VERSION $REPO /src && cd /src
    GOOS= GOARCH= go run ./tools/file-bundler/ events/k8saudit/yaml
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-s -w' -o /out/event-generator .
  "
}

build_with_go() {
  local src
  src="$(mktemp -d)"
  git clone --depth 1 --branch "$VERSION" "$REPO" "$src"
  ( cd "$src"
    GOTOOLCHAIN=auto GOOS= GOARCH= go run ./tools/file-bundler/ events/k8saudit/yaml
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=auto \
      go build -ldflags '-s -w' -o "$OLDPWD/$out/event-generator" . )
  rm -rf "$src"
}

if docker info >/dev/null 2>&1; then
  echo "Building event-generator $VERSION (static) with Docker..."
  build_in_docker
elif command -v go >/dev/null 2>&1; then
  echo "Building event-generator $VERSION (static) with the local Go toolchain..."
  build_with_go
else
  echo "Need Docker or Go (>= 1.26) to build event-generator. Install one and re-run." >&2
  exit 1
fi

chmod +x "$out/event-generator"
file "$out/event-generator" | grep -q "statically linked" \
  || { echo "Built binary is not static; it will not run in the Alpine container." >&2; exit 1; }
echo "Built $out/event-generator"
"$out/event-generator" list 2>/dev/null | grep -c "syscall\." | xargs echo "syscall actions available:"
