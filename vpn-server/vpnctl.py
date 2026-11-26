#!/usr/bin/env python3
"""vpnctl — свой VPN-сервер на Xray: несколько протоколов, пользователи, ссылки для Happ / v2RayTun / Hiddify.

    vpnctl init <публичный-адрес-сервера>   — создать ключи (один раз)
    vpnctl add <имя>                        — добавить человека
    vpnctl del <имя>                        — удалить
    vpnctl off <имя> / on <имя>             — временно отключить / включить
    vpnctl list                             — список
    vpnctl links <имя>                      — ссылки для импорта в клиент
    vpnctl sub <имя>                        — подписка (base64) для импорта целиком
    vpnctl apply                            — пересобрать конфиг и перезапустить Xray

Протоколы (все через TLS 1.3 / AEAD; REALITY маскируется под настоящий сайт):
    443/tcp   VLESS + Vision + REALITY (www.scaleway.com)       — самый совместимый (внутри 2443)
    2053/tcp  VLESS + XHTTP + REALITY + ML-KEM-768 (microsoft) — постквантовый
    2083/tcp  Trojan + REALITY (dl.google.com)
    2087/tcp  VLESS + Vision + REALITY (max.ru)                — маскировка под белый список
    2096/tcp  VLESS + XHTTP + REALITY + ML-KEM-768 (ozon.ru)   — белый список + постквантовый
    443/udp   Hysteria 2 (QUIC), сертификат vpn.invalid (внутри 8443/udp)
"""
import base64, datetime, json, os, secrets, subprocess, sys, urllib.parse

BASE = os.environ.get("VPN_HOME", "/opt/vpn")
XRAY = f"{BASE}/xray"
STATE = f"{BASE}/state.json"
CONFIG = f"{BASE}/config.json"
CERT, KEY = f"{BASE}/hy2.crt", f"{BASE}/hy2.key"
SERVICE = "xray-vpn"

INBOUNDS = [
    # tag,          port, proto,    net,     sni,                  pq_enc, flow
    ("fi-vision",   2443, "vless",  "raw",   "www.scaleway.com",   False, "xtls-rprx-vision"),
    ("fi-pq",       2053, "vless",  "xhttp", "www.microsoft.com",  True,  ""),
    ("fi-trojan",   2083, "trojan", "raw",   "dl.google.com",      False, ""),
    ("wl-vision",   2087, "vless",  "raw",   "max.ru",             False, "xtls-rprx-vision"),
    ("wl-pq",       2096, "vless",  "xhttp", "www.ozon.ru",        True,  ""),
]
TITLES = {
    "fi-vision": "🇫🇮 Финляндия · Vision",
    "fi-pq": "🇫🇮 Финляндия · постквантовый",
    "fi-trojan": "🇫🇮 Финляндия · Trojan",
    "wl-vision": "🇷🇺 Белый список · max.ru",
    "wl-pq": "🇷🇺 Белый список · ozon PQ",
    "hy2": "🇫🇮 Hysteria 2 (UDP)",
}
HY2_PORT = 8443
# внешний порт → внутренний: на выделенном IP 443/tcp и 443/udp перенаправлены фаерволом
PUBLIC = {"fi-vision": 443, "hy2": 443}
XHTTP_PATH = "/api/v2/stream"


def sh(*args):
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout


def load():
    with open(STATE) as f:
        return json.load(f)


def save(st):
    tmp = STATE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(st, f, indent=2, ensure_ascii=False)
    os.replace(tmp, STATE)


def kv(out, label):
    for line in out.splitlines():
        if line.strip().lower().startswith(label.lower()):
            return line.split(":", 1)[1].strip()
    raise RuntimeError(f"нет '{label}' в выводе xray")


def init(host):
    if os.path.exists(STATE):
        sys.exit("уже инициализировано: " + STATE)
    x = sh(XRAY, "x25519")
    m = sh(XRAY, "mldsa65")
    enc = sh(XRAY, "vlessenc")
    pq = enc.split("ML-KEM-768, Post-Quantum", 1)[1]
    dec_s = pq.split('"decryption": "', 1)[1].split('"', 1)[0]
    enc_s = pq.split('"encryption": "', 1)[1].split('"', 1)[0]
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-nodes", "-days", "3650", "-subj", "/CN=vpn.invalid", "-keyout", KEY, "-out", CERT],
                   check=True, capture_output=True)
    os.chmod(KEY, 0o640)
    try:
        import grp
        os.chown(KEY, 0, grp.getgrnam("xrayvpn").gr_gid)   # ключ сертификата читает только Xray
    except KeyError:
        pass
    pin = sh("openssl", "x509", "-in", CERT, "-noout", "-fingerprint", "-sha256").split("=", 1)[1].strip()
    st = {
        "host": host,
        "reality_private": kv(x, "PrivateKey"), "reality_public": kv(x, "Password"),
        "mldsa65_seed": kv(m, "Seed"), "mldsa65_verify": kv(m, "Verify"),
        "short_ids": [secrets.token_hex(4) for _ in range(3)],
        "vless_decryption": dec_s, "vless_encryption": enc_s,
        "hy2_pin_sha256": pin.replace(":", "").lower(), "hy2_obfs": secrets.token_urlsafe(16),
        "users": [],
    }
    save(st)
    print("ключи созданы:", STATE)


def build(st):
    users = [u for u in st["users"] if u.get("enabled", True)]
    reality = lambda sni: {"target": f"{sni}:443", "serverNames": [sni], "privateKey": st["reality_private"],
                           "shortIds": st["short_ids"], "mldsa65Seed": st["mldsa65_seed"]}
    sniff = {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}
    inbounds = []
    for tag, port, proto, net, sni, pq, flow in INBOUNDS:
        ss = {"network": net, "security": "reality", "realitySettings": reality(sni)}
        if net == "xhttp":
            ss["xhttpSettings"] = {"path": XHTTP_PATH, "mode": "auto"}
        if proto == "vless":
            settings = {"clients": [{"id": u["uuid"], "email": f"{u['name']}@{tag}", **({"flow": flow} if flow else {})}
                                    for u in users],
                        "decryption": st["vless_decryption"] if pq else "none"}
        else:
            settings = {"clients": [{"password": u["trojan"], "email": f"{u['name']}@{tag}"} for u in users]}
        inbounds.append({"tag": tag, "port": port, "protocol": proto, "settings": settings,
                         "streamSettings": ss, "sniffing": sniff})
    inbounds.append({"tag": "hy2", "port": HY2_PORT, "protocol": "hysteria", "sniffing": sniff,
                     "settings": {"version": 2, "clients": [{"auth": u["uuid"], "email": f"{u['name']}@hy2"} for u in users]},
                     "streamSettings": {"network": "hysteria", "security": "tls",
                                        "tlsSettings": {"alpn": ["h3"], "certificates": [
                                            {"certificateFile": CERT, "keyFile": KEY}]}}})
    return {
        "log": {"loglevel": "warning", "access": "none"},          # не храним историю посещений
        "inbounds": inbounds,
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"},
                       **({"sendThrough": st["host"]} if st["host"].replace(".", "").isdigit() else {})},  # выход с выделенного IP
                      {"tag": "block", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
            # к внутренним службам сервера (MySQL, Ollama, …) и локальным сетям через VPN — нельзя
            {"type": "field", "ip": ["geoip:private", "127.0.0.0/8", "::1/128"], "outboundTag": "block"},
            {"type": "field", "domain": ["localhost", "full:localhost"], "outboundTag": "block"},
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
            {"type": "field", "port": "25,465,587", "outboundTag": "block"},      # без рассылки спама
        ]},
        "policy": {"levels": {"0": {"handshake": 4, "connIdle": 300}}},
    }


def apply(st):
    cfg = build(st)
    tmp = CONFIG.replace(".json", ".new.json")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    r = subprocess.run([XRAY, "run", "-test", "-c", tmp], capture_output=True, text=True,
                       env={**os.environ, "XRAY_LOCATION_ASSET": f"{BASE}/share"})
    if "Configuration OK" not in r.stdout + r.stderr:
        os.unlink(tmp)
        sys.exit("Xray отверг конфиг:\n" + (r.stdout + r.stderr)[-800:])
    try:
        import grp
        os.chown(tmp, 0, grp.getgrnam("xrayvpn").gr_gid)
    except KeyError:
        pass
    os.replace(tmp, CONFIG)
    subprocess.run(["systemctl", "restart", SERVICE], check=False)
    print("применено:", len([u for u in st["users"] if u.get("enabled", True)]), "активных пользователей")


def find(st, name):
    u = next((u for u in st["users"] if u["name"] == name), None)
    if not u:
        sys.exit(f"нет пользователя {name}")
    return u


def links(st, u):
    h = st["host"]
    out = []
    for tag, port, proto, net, sni, pq, flow in INBOUNDS:
        q = {"security": "reality", "sni": sni, "fp": "chrome", "pbk": st["reality_public"],
             "sid": st["short_ids"][0], "pqv": st["mldsa65_verify"], "type": "tcp" if net == "raw" else net}
        if net == "xhttp":
            q.update(path=XHTTP_PATH, mode="auto")
        if proto == "vless":
            q["encryption"] = st["vless_encryption"] if pq else "none"
            if flow:
                q["flow"] = flow
            cred = u["uuid"]
        else:
            cred = urllib.parse.quote(u["trojan"], safe="")
        out.append(f"{proto}://{cred}@{h}:{PUBLIC.get(tag, port)}?{urllib.parse.urlencode(q)}#{urllib.parse.quote(TITLES[tag])}")
    hq = {"sni": "vpn.invalid", "insecure": "1", "pinSHA256": st["hy2_pin_sha256"], "alpn": "h3"}
    out.append(f"hysteria2://{u['uuid']}@{h}:{PUBLIC.get('hy2', HY2_PORT)}?{urllib.parse.urlencode(hq)}#{urllib.parse.quote(TITLES['hy2'])}")
    return out


def client_outbounds(st, u):
    """Клиентские outbounds Xray для каждого протокола (для проверки и для клиентов на Xray)."""
    h, outs = st["host"], []
    for tag, port, proto, net, sni, pq, flow in INBOUNDS:
        ss = {"network": net, "security": "reality",
              "realitySettings": {"serverName": sni, "fingerprint": "chrome", "password": st["reality_public"],
                                  "shortId": st["short_ids"][0], "mldsa65Verify": st["mldsa65_verify"]}}
        if net == "xhttp":
            ss["xhttpSettings"] = {"path": XHTTP_PATH, "mode": "auto"}
        if proto == "vless":
            settings = {"vnext": [{"address": h, "port": PUBLIC.get(tag, port), "users": [
                {"id": u["uuid"], "encryption": st["vless_encryption"] if pq else "none", "flow": flow}]}]}
        else:
            settings = {"servers": [{"address": h, "port": PUBLIC.get(tag, port), "password": u["trojan"]}]}
        outs.append({"tag": tag, "protocol": proto, "settings": settings, "streamSettings": ss})
    outs.append({"tag": "hy2", "protocol": "hysteria", "settings": {"version": 2, "address": h, "port": PUBLIC.get("hy2", HY2_PORT)},
                 "streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "auth": u["uuid"]},
                                    "security": "tls", "tlsSettings": {
                                        "serverName": "vpn.invalid", "alpn": ["h3"],
                                        "pinnedPeerCertSha256": st["hy2_pin_sha256"]}}})
    return outs


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help", "help"):
        print(__doc__); return
    cmd = a[0]
    if cmd == "init":
        init(a[1]); return
    st = load()
    if cmd == "add":
        name = a[1]
        if any(u["name"] == name for u in st["users"]):
            sys.exit("уже есть " + name)
        st["users"].append({"name": name, "uuid": sh(XRAY, "uuid").strip(), "trojan": secrets.token_urlsafe(24),
                            "enabled": True,
                            "created": datetime.date.today().isoformat()})
        save(st); apply(st)
        print("\n".join(links(st, st["users"][-1])))
    elif cmd == "del":
        st["users"] = [u for u in st["users"] if u["name"] != a[1]]; save(st); apply(st)
    elif cmd in ("on", "off"):
        find(st, a[1])["enabled"] = cmd == "on"; save(st); apply(st)
    elif cmd == "list":
        for u in st["users"]:
            print(f"{u['name']:20} {'вкл' if u.get('enabled', True) else 'выкл'}  с {u['created']}")
    elif cmd == "links":
        print("\n".join(links(st, find(st, a[1]))))
    elif cmd == "sub":
        print(base64.b64encode("\n".join(links(st, find(st, a[1]))).encode()).decode())
    elif cmd == "outbounds":
        print(json.dumps(client_outbounds(st, find(st, a[1])), ensure_ascii=False, indent=2))
    elif cmd == "sethost":
        st["host"] = a[1]; save(st); print("адрес для ссылок:", a[1])
    elif cmd == "apply":
        apply(st)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
