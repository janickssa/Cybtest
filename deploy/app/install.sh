#!/usr/bin/env bash
# Installs the SecTestGen app in a Debian 12 / Ubuntu 24.04 LXC container.
# Expects /usr/local/bin/sectestgen-app and /opt/sectestgen/{dist,rules,catalog,app}
# to be copied in first (see README, "Install the app container").
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
BIN=/usr/local/bin/sectestgen-app
OPT=/opt/sectestgen
ENV_FILE=/etc/sectestgen/sectestgen.env

for path in "$BIN" "$OPT/dist/index.html" "$OPT/rules/tags.yaml" "$OPT/catalog" "$OPT/app/sectestgen-app.service"; do
  [[ -e $path ]] || { echo "Missing $path; copy it in first." >&2; exit 1; }
done

id sectestgen &>/dev/null || useradd --system --home /var/lib/sectestgen --shell /usr/sbin/nologin sectestgen
install -d -o sectestgen -g sectestgen -m 750 /var/lib/sectestgen
install -d -m 755 /etc/sectestgen
chmod 755 "$BIN"

if [[ ! -f $ENV_FILE ]]; then
  read -rsp "Choose a login password: " password; echo
  [[ ${#password} -ge 12 ]] || { echo "Use at least 12 characters." >&2; exit 1; }
  hash=$("$BIN" hash-password "$password")
  read -rp "Will you reach it over HTTPS (reverse proxy such as Caddy)? [y/N] " https
  # Browsers drop Secure cookies on plain HTTP, so login only works with this matching.
  cookie_secure=false; [[ $https =~ ^[Yy] ]] && cookie_secure=true
  umask 077
  cat > "$ENV_FILE" <<CONF
BIND_ADDR=0.0.0.0:8080
AUTH_PASSWORD_HASH='$hash'
# true when the app is reached over HTTPS; false for plain HTTP on a trusted LAN.
COOKIE_SECURE=$cookie_secure
RULES_DIR=$OPT/rules
CATALOG_DIR=$OPT/catalog
FRONTEND_DIR=$OPT/dist
DATA_DIR=/var/lib/sectestgen
CONF
  chmod 600 "$ENV_FILE"
  echo "Wrote $ENV_FILE"
fi

install -m 644 "$OPT/app/sectestgen-app.service" /etc/systemd/system/sectestgen-app.service
systemctl daemon-reload
systemctl enable --now sectestgen-app
systemctl restart sectestgen-app
sleep 1
systemctl --no-pager --lines=5 status sectestgen-app
echo
echo "SecTestGen is running on port 8080. Put it behind HTTPS (e.g. Caddy) and restrict access with the firewall."
