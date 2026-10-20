#!/usr/bin/env bash
# Install or upgrade ISE Certificate Utility on Debian 12+ or Ubuntu 22.04+.
# Run from a checkout of the repository: sudo ./install.sh
set -euo pipefail
# The service account must be able to read the virtualenv, whatever umask root's shell uses.
umask 022

PREFIX=/opt/ise-cert-utility
SERVICE_USER=ise-cert
ETC=/etc/ise-cert-utility
VAR=/var/lib/ise-cert-utility
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIND="${ISE_CERT_UTILITY_BIND:-0.0.0.0:8443}"

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo ./install.sh)"
[[ -f "$SRC/pyproject.toml" ]] || die "run install.sh from the repository checkout"
command -v systemctl >/dev/null || die "systemd is required"

say "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv openssl ca-certificates >/dev/null

PY_OK=$(python3 -c 'import sys; print(int(sys.version_info >= (3, 11)))')
[[ $PY_OK == 1 ]] || die "Python 3.11 or newer is required (Debian 12 or later)"

say "Creating service account '$SERVICE_USER'"
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$VAR" --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi
install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_USER" "$ETC" "$VAR"

say "Installing application into $PREFIX"
install -d -m 0755 "$PREFIX"
[[ -x "$PREFIX/venv/bin/python" ]] || python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --quiet --upgrade pip
"$PREFIX/venv/bin/pip" install --quiet --upgrade "$SRC"

say "Installing command wrapper"
cat > /usr/local/bin/ise-cert-utility <<'WRAP'
#!/bin/sh
# Runs ise-cert-utility as the service account so file ownership stays correct.
BIN=/opt/ise-cert-utility/venv/bin/ise-cert-utility
if [ "$(id -u)" -eq 0 ] && [ "$1" != "migrate-legacy" ]; then
    exec runuser -u ise-cert -- "$BIN" "$@"
fi
exec "$BIN" "$@"
WRAP
chmod 0755 /usr/local/bin/ise-cert-utility

say "Installing systemd units"
install -m 0644 "$SRC"/packaging/systemd/*.service "$SRC"/packaging/systemd/*.timer /etc/systemd/system/
if [[ ! -f /etc/default/ise-cert-utility ]]; then
    printf '# Address and port for the web console\nISE_CERT_UTILITY_BIND=%s\n' "$BIND" > /etc/default/ise-cert-utility
fi
systemctl daemon-reload

if [[ -f /etc/ise-cert-sync/config.json && ! -f "$ETC/config.json" ]]; then
    say "Found a 1.x installation; importing its settings"
    "$PREFIX/venv/bin/ise-cert-utility" migrate-legacy || say "Migration skipped; configure settings in the console"
fi

say "Initialising the console"
extra_sans=()
for ip in $(hostname -I 2>/dev/null); do extra_sans+=(--san "$ip"); done
if [[ -r /dev/tty ]] && { : </dev/tty; } 2>/dev/null; then
    runuser -u "$SERVICE_USER" -- "$PREFIX/venv/bin/ise-cert-utility" init "${extra_sans[@]}" </dev/tty
else
    runuser -u "$SERVICE_USER" -- "$PREFIX/venv/bin/ise-cert-utility" init --generate-password "${extra_sans[@]}"
fi

# 1.x's console listens on the same port and its timer would deploy alongside the new scheduler.
legacy_units=()
for unit in ise-cert-web.service ise-cert-web-scheduler.timer ise-cert-sync.timer; do
    if systemctl is-enabled "$unit" >/dev/null 2>&1 || systemctl is-active "$unit" >/dev/null 2>&1; then
        legacy_units+=("$unit")
    fi
done
if (( ${#legacy_units[@]} )); then
    say "Stopping 1.x units: ${legacy_units[*]}"
    systemctl disable --now "${legacy_units[@]}" >/dev/null 2>&1 || true
fi

say "Starting services"
systemctl enable --now ise-cert-utility-web.service ise-cert-utility-scheduler.timer >/dev/null
systemctl restart ise-cert-utility-web.service

if systemctl is-enabled certbot.timer >/dev/null 2>&1; then
    say "Note: the distribution certbot.timer is enabled. It does not manage this utility's certificate."
fi

port="${BIND##*:}"
fp=$(openssl x509 -in "$ETC/tls/console.crt" -noout -fingerprint -sha256 | cut -d= -f2)
echo
echo "ISE Certificate Utility is running."
echo "  Console:      https://$(hostname -f 2>/dev/null || hostname):$port/"
echo "  Fingerprint:  $fp"
echo "  Status:       ise-cert-utility status"
if (( ${#legacy_units[@]} )); then
    echo "  Roll back:    systemctl disable --now ise-cert-utility-web.service ise-cert-utility-scheduler.timer"
    echo "                systemctl enable --now ${legacy_units[*]}"
fi
echo
