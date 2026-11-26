#!/bin/bash
# Полная установка на чистый Raspberry Pi (Raspberry Pi OS / Debian 12-13, arm64):
#   Wi-Fi — интернет, Ethernet — телевизор; весь трафик телевизора идёт через Xray (VPN) с блокировкой рекламы.
#
#   sudo bash pi/setup_pi.sh [--relay user@host[:port]]
#
# Повторный запуск безопасен.
set -euo pipefail
cd "$(dirname "$0")/.."
RELAY=""
[ "${1:-}" = "--relay" ] && RELAY="${2:?укажи user@host[:port]}"

echo "== зависимости =="
# TVWP/2: ML-KEM-1024 нужен OpenSSL >= 3.5, ChaCha20-Poly1305 — python3-cryptography
command -v openssl >/dev/null && python3 -c "import cryptography" 2>/dev/null || apt-get install -y openssl python3-cryptography
openssl list -kem-algorithms | grep -q ML-KEM-1024 || { echo "нужен OpenSSL 3.5+ с ML-KEM (Debian 13 trixie)"; exit 1; }

echo "== Xray =="
if ! command -v xray >/dev/null; then
  T=$(mktemp -d)
  curl -fsSL -o "$T/x.zip" https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm64-v8a.zip
  curl -fsSL -o "$T/x.dgst" https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm64-v8a.zip.dgst
  want=$(grep -i "^SHA2-256" "$T/x.dgst" | awk '{print $2}')
  [ "$want" = "$(sha256sum "$T/x.zip" | cut -d' ' -f1)" ] || { echo "контрольная сумма Xray не совпала"; exit 1; }
  python3 -c "import zipfile,sys;zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$T/x.zip" "$T"
  install -m 755 "$T/xray" /usr/local/bin/xray
  install -d /usr/local/share/xray
  install -m 644 "$T/geoip.dat" "$T/geosite.dat" /usr/local/share/xray/
  rm -rf "$T"
fi
xray version | head -1

echo "== базовый конфиг Xray =="
install -d -m 755 /usr/local/etc/xray
if [ ! -f /usr/local/etc/xray/config.json ]; then
  install -o root -g nogroup -m 640 pi/xray-base.json /usr/local/etc/xray/config.json
fi
install -m 644 pi/tv-tproxy.nft /usr/local/etc/xray/tv-tproxy.nft
install -m 644 pi/xray.service pi/tv-tproxy.service /etc/systemd/system/
modprobe nft_tproxy

echo "== раздача интернета телевизору по Ethernet =="
if ! nmcli -t -f NAME con show | grep -qx tv-share; then
  for c in $(nmcli -t -f NAME,TYPE con show | awk -F: '$2=="802-3-ethernet"{print $1}'); do
    nmcli con mod "$c" connection.autoconnect no || true
  done
  nmcli con add type ethernet ifname eth0 con-name tv-share \
    ipv4.method shared ipv4.addresses 10.42.0.1/24 ipv6.method disabled \
    connection.autoconnect yes connection.autoconnect-priority 100 >/dev/null
fi

echo "== агент TV Watch =="
bash agent/install.sh

if [ -n "$RELAY" ]; then
  echo "== сервер-ретранслятор подписки =="
  D=/usr/local/etc/tvwatch
  [ -f $D/relay_ed25519 ] || ssh-keygen -q -t ed25519 -N "" -C "tvwatch-pi" -f $D/relay_ed25519
  python3 - "$RELAY" <<'PY'
import json, os, sys
user, _, hp = sys.argv[1].partition("@")
host, _, port = hp.partition(":")
p = "/usr/local/etc/tvwatch/agent.json"
try: c = json.load(open(p))
except Exception: c = {}
c["relay"] = {"host": host, "port": int(port or 22), "user": user}
c.setdefault("profile", ""); c.setdefault("refresh_hours", 6)
fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f: json.dump(c, f, ensure_ascii=False, indent=2)
PY
  systemctl restart tvwatch-agent
  echo "Публичный ключ Pi для install_relay.sh на сервере:"
  cat $D/relay_ed25519.pub
fi

systemctl enable --now tv-tproxy >/dev/null
echo
echo "Готово. Ключ для приложения TV Watch (вставь в «Подписка и серверы → Ключ TVWP»):"
echo "  sudo cat /usr/local/etc/tvwatch/key"
