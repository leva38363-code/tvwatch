#!/usr/bin/env python3
"""tvwatch-relay: скачивает VPN-подписку с HWID на сервере и отдаёт её Raspberry Pi по SSH.

Pi подключается по SSH ключом, у которого в authorized_keys стоит
    command="/usr/bin/python3 /opt/tvwatch-relay/tvwatch_relay.py",no-pty,no-port-forwarding,...
поэтому ключ умеет только то, что разрешено здесь:

    fetch   — JSON: {"ok", "fetched_at", "userinfo", "profiles": [полные конфиги Xray]}
    ping    — проверка связи

Администратор на сервере (не через ключ Pi):
    tvwatch_relay.py set-hwid   — ввести HWID (скрытый ввод)
    tvwatch_relay.py set-url    — ввести адрес подписки
    tvwatch_relay.py show       — показать настройки (секреты замаскированы)

Только стандартная библиотека Python 3.8+.
"""
import getpass
import json
import os
import sys
import time
import urllib.error
import urllib.request

CONF = os.environ.get("TVWATCH_RELAY_CONF", "/etc/tvwatch-relay/config.json")
CACHE = os.environ.get("TVWATCH_RELAY_CACHE", "/var/cache/tvwatch-relay/sub.json")
DEFAULTS = {
    "sub_url": "",
    "hwid": "",
    "user_agent": "Happ/1.0",
    "device_os": "macOS",
    "ver_os": "15",
    "device_model": "Mac",
    "min_interval": 60,      # не чаще раза в минуту ходить к провайдеру
    "timeout": 30,
}


def load():
    try:
        with open(CONF) as f:
            c = json.load(f)
    except (OSError, ValueError):
        c = {}
    return {**DEFAULTS, **c}


def save(c):
    os.makedirs(os.path.dirname(CONF), exist_ok=True)
    tmp = CONF + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(c, f, indent=2, ensure_ascii=False)
    os.replace(tmp, CONF)


def out(obj, code=0):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False))
    sys.stdout.flush()
    sys.exit(code)


def mask(s):
    return (s[:4] + "…" + s[-2:]) if len(s) > 8 else ("…" if s else "")


def fetch(c):
    if not c["sub_url"]:
        out({"ok": False, "error": "на сервере не задан адрес подписки (tvwatch_relay.py set-url)"}, 1)
    if not c["hwid"]:
        out({"ok": False, "error": "на сервере не задан HWID (tvwatch_relay.py set-hwid)"}, 1)

    # кэш: защищает подписку от частых запросов
    try:
        if time.time() - os.path.getmtime(CACHE) < c["min_interval"]:
            with open(CACHE) as f:
                cached = json.load(f)
            cached["cached"] = True
            out(cached)
    except (OSError, ValueError):
        pass

    req = urllib.request.Request(c["sub_url"], headers={
        "User-Agent": c["user_agent"],
        "X-HWID": c["hwid"],
        "X-Device-OS": c["device_os"],
        "X-Ver-OS": c["ver_os"],
        "X-Device-model": c["device_model"],
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=c["timeout"]) as r:
            body = r.read()
            userinfo = r.headers.get("subscription-userinfo", "")
    except urllib.error.HTTPError as e:
        out({"ok": False, "error": f"подписка ответила {e.code}"}, 1)
    except Exception as e:
        out({"ok": False, "error": f"подписка недоступна: {e}"}, 1)

    try:
        profiles = json.loads(body)
        assert isinstance(profiles, list)
    except (ValueError, AssertionError):
        out({"ok": False, "error": "подписка вернула не JSON-конфиги — провайдер не принял HWID или формат"}, 1)
    profiles = [p for p in profiles if isinstance(p, dict) and p.get("outbounds")]
    if not profiles:
        out({"ok": False, "error": "в подписке нет серверов"}, 1)

    res = {"ok": True, "fetched_at": int(time.time()), "userinfo": userinfo, "profiles": profiles}
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    fd = os.open(CACHE + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(res, f, ensure_ascii=False)
    os.replace(CACHE + ".tmp", CACHE)
    out(res)


def main():
    args = sys.argv[1:]
    restricted = "--restricted" in args          # так запускает ключ Pi (forced command)
    if restricted:
        # команду, которую прислал Pi, берём из SSH_ORIGINAL_COMMAND; всё лишнее отбрасываем
        cmd = (os.environ.get("SSH_ORIGINAL_COMMAND") or "fetch").split()[:1]
    else:
        cmd = args[:1] or ["help"]
    c = load()
    if cmd[0] == "ping":
        out({"ok": True, "pong": int(time.time())})
    if cmd[0] == "fetch":
        fetch(c)
    if restricted:   # ключ Pi не может менять настройки
        out({"ok": False, "error": f"команда '{cmd[0]}' запрещена"}, 2)
    if cmd[0] == "set-hwid":
        c["hwid"] = getpass.getpass("HWID: ").strip()
        save(c)
        print("HWID сохранён")
    elif cmd[0] == "set-url":
        c["sub_url"] = getpass.getpass("Адрес подписки: ").strip()
        save(c)
        print("адрес сохранён")
    elif cmd[0] == "show":
        print(json.dumps({**c, "hwid": mask(c["hwid"]), "sub_url": mask(c["sub_url"])}, indent=2, ensure_ascii=False))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
