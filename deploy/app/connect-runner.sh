#!/usr/bin/env bash
# Points the app at a runner. Usage: connect-runner.sh <runner-url> <runner-token>
# Expects the runner's certificate at /etc/sectestgen/runner-ca.pem.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ $# -eq 2 ]] || { echo "Usage: $0 https://<runner-ip>:9090 <token>" >&2; exit 1; }
ENV_FILE=/etc/sectestgen/sectestgen.env
CA=/etc/sectestgen/runner-ca.pem
[[ -f $ENV_FILE ]] || { echo "Run install.sh first." >&2; exit 1; }
[[ -f $CA ]] || { echo "Copy the runner's cert.pem to $CA first." >&2; exit 1; }
[[ $1 == https://* ]] || { echo "The runner URL must use https://" >&2; exit 1; }

chgrp sectestgen "$CA" && chmod 640 "$CA"
sed -i '/^RUNNER_URL=/d;/^RUNNER_TOKEN=/d;/^RUNNER_CA_CERT=/d' "$ENV_FILE"
printf 'RUNNER_URL=%s\nRUNNER_TOKEN=%s\nRUNNER_CA_CERT=%s\n' "$1" "$2" "$CA" >> "$ENV_FILE"
systemctl restart sectestgen-app
echo "App restarted and connected to $1"
