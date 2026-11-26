#!/bin/bash
# Установка tvwatch-agent на Raspberry Pi. Запуск: sudo bash install.sh
set -euo pipefail
cd "$(dirname "$0")"
install -d -m 755 /usr/local/lib/tvwatch
install -d -m 700 /usr/local/etc/tvwatch
install -m 644 tvwatch_agent.py /usr/local/lib/tvwatch/tvwatch_agent.py
install -m 644 ../pi/xray.service tvwatch-agent.service /etc/systemd/system/
cp -p /usr/local/etc/xray/config.json "/usr/local/etc/xray/config.before-tvwatch.$(date +%s).json"
python3 /usr/local/lib/tvwatch/tvwatch_agent.py --setup-xray   # меняет конфиг и проверяет его
systemctl daemon-reload
systemctl restart xray
systemctl enable --now tvwatch-agent
systemctl restart tvwatch-agent
sleep 2
systemctl is-active xray tvwatch-agent
