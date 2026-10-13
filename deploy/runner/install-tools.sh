#!/usr/bin/env bash
# Installs the scanning tools at pinned versions into $TOOLS_DIR (default
# /opt/sectestgen-runner/tools). Every download is checked against its SHA-256.
set -euo pipefail

TOOLS_DIR=${TOOLS_DIR:-/opt/sectestgen-runner/tools}
[[ $(uname -m) == x86_64 ]] || { echo "Only x86_64 is supported." >&2; exit 1; }

GITLEAKS=8.30.1
OSV_SCANNER=2.7.0
TRIVY=0.75.0
CARGO_AUDIT=0.22.2
SEMGREP=1.180.0

declare -A SHA256=(
  [gitleaks]=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
  [osv-scanner]=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
  [trivy]=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
  [cargo-audit]=7fb9497f8594b389e5fce5ef9b92db08432996895b2e0c5a0167a69ed445c428
)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$TOOLS_DIR/bin"

fetch() { # name url
  local file="$tmp/$1.download"
  echo "Downloading $1"
  curl -fsSL --retry 3 -o "$file" "$2"
  echo "${SHA256[$1]}  $file" | sha256sum --check --quiet || { echo "Checksum mismatch for $1" >&2; exit 1; }
}

fetch gitleaks "https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS/gitleaks_${GITLEAKS}_linux_x64.tar.gz"
tar -xzf "$tmp/gitleaks.download" -C "$tmp" gitleaks
install -m 755 "$tmp/gitleaks" "$TOOLS_DIR/bin/gitleaks"

fetch osv-scanner "https://github.com/google/osv-scanner/releases/download/v$OSV_SCANNER/osv-scanner_linux_amd64"
install -m 755 "$tmp/osv-scanner.download" "$TOOLS_DIR/bin/osv-scanner"

fetch trivy "https://github.com/aquasecurity/trivy/releases/download/v$TRIVY/trivy_${TRIVY}_Linux-64bit.tar.gz"
tar -xzf "$tmp/trivy.download" -C "$tmp" trivy
install -m 755 "$tmp/trivy" "$TOOLS_DIR/bin/trivy"

fetch cargo-audit "https://github.com/rustsec/rustsec/releases/download/cargo-audit%2Fv$CARGO_AUDIT/cargo-audit-x86_64-unknown-linux-musl-v$CARGO_AUDIT.tgz"
tar -xzf "$tmp/cargo-audit.download" -C "$tmp"
install -m 755 "$(find "$tmp" -type f -name cargo-audit | head -n1)" "$TOOLS_DIR/bin/cargo-audit"

echo "Installing semgrep $SEMGREP"
python3 -m venv "$TOOLS_DIR/semgrep"
"$TOOLS_DIR/semgrep/bin/pip" install --quiet --disable-pip-version-check "semgrep==$SEMGREP"
ln -sf "$TOOLS_DIR/semgrep/bin/semgrep" "$TOOLS_DIR/bin/semgrep"

for tool in gitleaks osv-scanner trivy cargo-audit semgrep; do
  printf '%-12s ' "$tool"; "$TOOLS_DIR/bin/$tool" --version 2>&1 | head -n1
done
