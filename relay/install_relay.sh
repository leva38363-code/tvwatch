#!/bin/bash
# Установка tvwatch-relay на свой сервер (Ubuntu/Debian). Запуск от root:
#   sudo bash install_relay.sh "<публичный ключ Pi: ssh-ed25519 AAAA... tvwatch-pi>"
set -euo pipefail
PUBKEY="${1:?нужен публичный ключ Pi}"
case "$PUBKEY" in ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*) ;; *) echo "это не похоже на публичный SSH-ключ"; exit 1;; esac
cd "$(dirname "$0")"

# отдельный пользователь без пароля и без доступа к остальному серверу
id tvwatch-relay >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/tvwatch-relay --shell /bin/sh tvwatch-relay
passwd -l tvwatch-relay >/dev/null

install -d -m 755 /opt/tvwatch-relay
install -m 755 tvwatch_relay.py /opt/tvwatch-relay/tvwatch_relay.py
install -d -m 700 -o tvwatch-relay -g tvwatch-relay /etc/tvwatch-relay /var/cache/tvwatch-relay
if [ ! -f /etc/tvwatch-relay/config.json ]; then
  install -m 600 -o tvwatch-relay -g tvwatch-relay /dev/null /etc/tvwatch-relay/config.json
  echo '{}' > /etc/tvwatch-relay/config.json
fi

# ключ Pi умеет только запускать relay с --restricted (fetch/ping)
H=/var/lib/tvwatch-relay
install -d -m 700 -o tvwatch-relay -g tvwatch-relay "$H/.ssh"
OPTS='command="/usr/bin/python3 /opt/tvwatch-relay/tvwatch_relay.py --restricted",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,no-user-rc'
echo "$OPTS $PUBKEY" > "$H/.ssh/authorized_keys"
chown tvwatch-relay:tvwatch-relay "$H/.ssh/authorized_keys"; chmod 600 "$H/.ssh/authorized_keys"

echo "готово. Задай подписку и HWID:"
echo "  sudo -u tvwatch-relay python3 /opt/tvwatch-relay/tvwatch_relay.py set-url"
echo "  sudo -u tvwatch-relay python3 /opt/tvwatch-relay/tvwatch_relay.py set-hwid"
