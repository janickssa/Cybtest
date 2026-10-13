#!/usr/bin/env bash
# Installs the SecTestGen runner in a Debian 12 / Ubuntu 24.04 LXC container.
# Expects /usr/local/bin/sectestgen-runner and /opt/sectestgen-runner/{catalog,runner}
# to be copied in first (see README, "Install the runner container").
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
BIN=/usr/local/bin/sectestgen-runner
OPT=/opt/sectestgen-runner
CONF=/etc/sectestgen-runner
DATA=/var/lib/sectestgen-runner

for path in "$BIN" "$OPT/catalog" "$OPT/runner/sectestgen-runner.service" "$OPT/runner/install-tools.sh"; do
  [[ -e $path ]] || { echo "Missing $path; copy it in first." >&2; exit 1; }
done

apt-get update -qq
apt-get install -y -qq ca-certificates curl openssl python3-venv >/dev/null
TOOLS_DIR=$OPT/tools bash "$OPT/runner/install-tools.sh"

id sectestgen-runner &>/dev/null || useradd --system --home "$DATA" --shell /usr/sbin/nologin sectestgen-runner
install -d -o sectestgen-runner -g sectestgen-runner -m 750 "$DATA" "$DATA/workspaces" "$DATA/cache"
install -d -m 755 "$CONF"
install -d -m 750 -g sectestgen-runner "$CONF/tls"
chmod 755 "$BIN"

ip=$(hostname -I | awk '{print $1}')
if [[ ! -f $CONF/tls/cert.pem ]]; then
  # A plain server certificate (not a CA): the app trusts exactly this one.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=sectestgen-runner" \
    -addext "subjectAltName=IP:$ip,DNS:$(hostname)" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=serverAuth" \
    -keyout "$CONF/tls/key.pem" -out "$CONF/tls/cert.pem" 2>/dev/null
  chgrp sectestgen-runner "$CONF/tls/key.pem" && chmod 640 "$CONF/tls/key.pem"
fi

if [[ ! -f $CONF/runner.env ]]; then
  umask 077
  cat > "$CONF/runner.env" <<CONFIG
BIND_ADDR=0.0.0.0:9090
RUNNER_TOKEN=$(openssl rand -hex 32)
TLS_CERT=$CONF/tls/cert.pem
TLS_KEY=$CONF/tls/key.pem
WORKSPACE_DIR=$DATA/workspaces
CACHE_DIR=$DATA/cache
CATALOG_DIR=$OPT/catalog
TOOLS_PATH=$OPT/tools/bin:/usr/local/bin:/usr/bin:/bin
MAX_UPLOAD_MB=200
MAX_UNPACKED_MB=2048
MAX_FILES=50000
MAX_PARALLEL_JOBS=2
WORKSPACE_RETENTION_DAYS=7
CONFIG
  chmod 600 "$CONF/runner.env"
fi

install -m 644 "$OPT/runner/sectestgen-runner.service" /etc/systemd/system/sectestgen-runner.service
systemctl daemon-reload
systemctl enable --now sectestgen-runner
systemctl restart sectestgen-runner
sleep 1
systemctl --no-pager --lines=5 status sectestgen-runner

token=$(grep '^RUNNER_TOKEN=' "$CONF/runner.env" | cut -d= -f2)
cat <<NEXT

Runner is listening on https://$ip:9090

Connect the app container to it:
  1. Copy the runner certificate to the app:
       scp $CONF/tls/cert.pem root@<app-ip>:/etc/sectestgen/runner-ca.pem
  2. On the app container, run:
       bash /opt/sectestgen/app/connect-runner.sh https://$ip:9090 $token
  3. Allow only the app container to reach port 9090 (Proxmox/LXC firewall).
NEXT
