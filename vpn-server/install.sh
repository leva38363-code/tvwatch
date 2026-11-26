#!/bin/bash
# Свой VPN-сервер на Xray. Запуск от root на сервере за пределами РФ:
#   bash install.sh <публичный-IP-или-домен> [имя-первого-пользователя]
set -euo pipefail
HOST="${1:?укажи публичный адрес сервера}"
FIRST="${2:-me}"
cd "$(dirname "$0")"
B=/opt/vpn

if [ ! -x $B/xray ]; then
  A=$(uname -m); case $A in x86_64) F=Xray-linux-64.zip;; aarch64) F=Xray-linux-arm64-v8a.zip;; *) echo "арх $A?"; exit 1;; esac
  T=$(mktemp -d)
  curl -fsSL -o $T/x.zip https://github.com/XTLS/Xray-core/releases/latest/download/$F
  curl -fsSL -o $T/x.dgst https://github.com/XTLS/Xray-core/releases/latest/download/$F.dgst
  [ "$(grep -i '^SHA2-256' $T/x.dgst | awk '{print $2}')" = "$(sha256sum $T/x.zip | cut -d' ' -f1)" ] || { echo "контрольная сумма"; exit 1; }
  python3 -c "import zipfile,sys;zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" $T/x.zip $T/x
  install -d -m 755 $B $B/share
  install -m 755 $T/x/xray $B/xray
  install -m 644 $T/x/geoip.dat $T/x/geosite.dat $B/share/
  rm -rf $T
fi

id xrayvpn >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin xrayvpn
chmod 750 $B; chgrp xrayvpn $B
install -m 755 vpnctl.py $B/vpnctl.py
ln -sf $B/vpnctl.py /usr/local/bin/vpnctl

cat > /etc/systemd/system/xray-vpn.service <<'EOF'
[Unit]
Description=Xray VPN server (vpnctl)
After=network-online.target
Wants=network-online.target

[Service]
User=xrayvpn
Group=xrayvpn
Environment=XRAY_LOCATION_ASSET=/opt/vpn/share
ExecStart=/opt/vpn/xray run -c /opt/vpn/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/opt/vpn

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

[ -f $B/state.json ] || vpnctl init "$HOST"
vpnctl list | grep -q "^$FIRST " || vpnctl add "$FIRST" >/dev/null
vpnctl apply >/dev/null
systemctl enable --now xray-vpn >/dev/null
sleep 1
systemctl is-active xray-vpn
echo "ссылки: vpnctl links $FIRST"
