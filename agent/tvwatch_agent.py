#!/usr/bin/env python3
"""tvwatch-agent: следит за соединениями телевизора через Xray и отдаёт их по протоколу TVWP/1.

Только стандартная библиотека Python 3.11+. Запускается от root (systemd).
"""
import asyncio
import collections
import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import subprocess
import sys
import tempfile
import time
import zlib

XRAY_CFG = "/usr/local/etc/xray/config.json"
STATE_DIR = "/usr/local/etc/tvwatch"
KEY_FILE = f"{STATE_DIR}/key"
LISTS_FILE = f"{STATE_DIR}/lists.json"
ACTIVE_FILE = f"{STATE_DIR}/active.json"
SERVER_FILE = f"{STATE_DIR}/server.json"
AGENT_CONF = f"{STATE_DIR}/agent.json"         # {"relay": {"host", "port", "user"}, "profile", "refresh_hours"}
RELAY_KEY = f"{STATE_DIR}/relay_ed25519"       # ключ, которым Pi ходит на свой сервер-ретранслятор
RELAY_KH = f"{STATE_DIR}/relay_known_hosts"
SUB_CACHE = f"{STATE_DIR}/sub_cache.json"     # последняя подписка (полные конфиги, доступ 600)
TEST_URL = "http://www.gstatic.com/generate_204"
LOG_DIR = "/run/xray"
ERR_LOG = f"{LOG_DIR}/error.log"
ACC_LOG = f"{LOG_DIR}/access.log"
API = "127.0.0.1:10085"
PORT = 7878
LOG_MAX = 16 * 1024 * 1024
BACKLOG = 3000
LIST_NAMES = ("block", "direct", "vpn")
TV_INBOUND = "tv-tproxy"

# ---------------------------------------------------------------- протокол
MAGIC = b"TW"
VER = 1
HDR = struct.Struct(">2sBBBBII")
TAG_LEN = 16
MAX_LEN = 8 * 1024 * 1024
T = dict(HELLO=0x01, AUTH=0x02, AUTH_OK=0x03, AUTH_FAIL=0x04, ACK=0x05, ERROR=0x06,
         SUBSCRIBE=0x10, EVENT=0x11, EVENT_BATCH=0x12, UNSUBSCRIBE=0x13,
         LISTS_GET=0x20, LISTS=0x21, LIST_EDIT=0x22,
         STATUS_GET=0x30, STATUS=0x31, CONFIG_PUSH=0x40,
         SERVERS_GET=0x50, SERVERS=0x51, SERVER_SELECT=0x52, SERVER_TEST=0x53, SERVER_TEST_RESULT=0x54,
         SUB_GET=0x60, SUB_PROFILES=0x61, SUB_REFRESH=0x62, SUB_SELECT=0x63,
         PING=0x7E, PONG=0x7F)
FLAG_ZLIB = 0x01


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def hm(key, *parts):
    return hmac.new(key, b"".join(parts), hashlib.sha256).digest()


class Conn:
    """Одно соединение по TVWP/1."""

    def __init__(self, reader, writer, agent):
        self.r, self.w, self.agent = reader, writer, agent
        self.skey = None
        self.tx_seq = 0
        self.rx_seq = -1
        self.subscribed = False
        self.lock = asyncio.Lock()
        self.peer = writer.get_extra_info("peername")

    async def send(self, mtype, obj):
        raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
        flags = 0
        if len(raw) > 4096:
            raw, flags = zlib.compress(raw, 6), FLAG_ZLIB
        async with self.lock:
            self.tx_seq += 1
            hdr = HDR.pack(MAGIC, VER, mtype, flags, 0, self.tx_seq, len(raw))
            tag = hm(self.skey, hdr, raw)[:TAG_LEN] if self.skey else bytes(TAG_LEN)
            self.w.write(hdr + raw + tag)
            await self.w.drain()
        return self.tx_seq

    async def recv(self):
        hdr = await self.r.readexactly(HDR.size)
        magic, ver, mtype, flags, _, seq, ln = HDR.unpack(hdr)
        if magic != MAGIC or ver != VER or ln > MAX_LEN:
            raise ValueError("bad frame")
        raw = await self.r.readexactly(ln)
        tag = await self.r.readexactly(TAG_LEN)
        if self.skey:
            if not hmac.compare_digest(tag, hm(self.skey, hdr, raw)[:TAG_LEN]):
                raise ValueError("bad tag")
            if seq <= self.rx_seq:
                raise ValueError("replay")
        self.rx_seq = seq
        if flags & FLAG_ZLIB:
            raw = zlib.decompress(raw)
        return mtype, seq, (json.loads(raw) if raw else {})

    async def handshake(self):
        ns = secrets.token_bytes(16)
        await self.send(T["HELLO"], {"server": "tvwatch-agent", "ver": VER, "nonce": ns.hex()})
        mtype, _, m = await asyncio.wait_for(self.recv(), 10)
        if mtype != T["AUTH"]:
            raise ValueError("expected AUTH")
        nc = bytes.fromhex(m["nonce"])
        key = self.agent.key
        if len(nc) != 16 or not hmac.compare_digest(bytes.fromhex(m["mac"]), hm(key, b"TVWP1-client|", ns, nc)):
            await self.send(T["AUTH_FAIL"], {"reason": "bad mac"})
            raise ValueError("auth failed")
        await self.send(T["AUTH_OK"], {"proof": hm(key, b"TVWP1-server|", nc, ns).hex()})
        self.skey = hm(key, b"TVWP1-session|", ns, nc)

    async def run(self):
        try:
            await self.handshake()
            log("client", self.peer, "authenticated")
            while True:
                mtype, seq, m = await self.recv()
                try:
                    await self.dispatch(mtype, seq, m)
                except Exception as e:  # ошибка запроса не рвёт соединение
                    log("request error", hex(mtype), e)
                    await self.send(T["ERROR"], {"ref": seq, "code": "fail", "msg": str(e)})
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError):
            pass
        except Exception as e:
            log("client", self.peer, "dropped:", e)
        finally:
            self.agent.clients.discard(self)
            self.w.close()

    async def dispatch(self, mtype, seq, m):
        a = self.agent
        if mtype == T["PING"]:
            await self.send(T["PONG"], {"t": m.get("t")})
        elif mtype == T["SUBSCRIBE"]:
            n = max(0, min(int(m.get("backlog", 500)), BACKLOG))
            evs = list(a.events)[-n:] if n else []
            for i in range(0, len(evs), 500):
                await self.send(T["EVENT_BATCH"], {"events": evs[i:i + 500]})
            self.subscribed = True
            await self.send(T["ACK"], {"ref": seq, "ok": True, "msg": f"subscribed, {len(evs)} past events"})
        elif mtype == T["UNSUBSCRIBE"]:
            self.subscribed = False
            await self.send(T["ACK"], {"ref": seq, "ok": True})
        elif mtype == T["LISTS_GET"]:
            await self.send(T["LISTS"], a.lists)
        elif mtype == T["LIST_EDIT"]:
            msg = await a.edit_list(m["list"], m["op"], m.get("items", []))
            await self.send(T["ACK"], {"ref": seq, "ok": True, "msg": msg})
            await a.broadcast(T["LISTS"], a.lists, subscribed_only=False)
        elif mtype == T["STATUS_GET"]:
            await self.send(T["STATUS"], await a.status())
        elif mtype == T["SERVERS_GET"]:
            await self.send(T["SERVERS"], a.servers())
        elif mtype == T["SERVER_SELECT"]:
            msg = await a.select_server(str(m.get("tag", "")))
            await self.send(T["ACK"], {"ref": seq, "ok": True, "msg": msg})
            await a.broadcast(T["SERVERS"], a.servers(), subscribed_only=False)
        elif mtype == T["SERVER_TEST"]:
            if a.testing:
                raise RuntimeError("проверка уже идёт")
            asyncio.create_task(a.test_servers(m.get("tags") or []))
            await self.send(T["ACK"], {"ref": seq, "ok": True, "msg": "test started"})
        elif mtype == T["SUB_GET"]:
            await self.send(T["SUB_PROFILES"], a.sub_summary())
        elif mtype == T["SUB_REFRESH"]:
            msg = await a.sub_refresh()
            await self.send(T["ACK"], {"ref": seq, "ok": True, "msg": msg})
        elif mtype == T["SUB_SELECT"]:
            msg = await a.sub_select(str(m.get("remarks", "")))
            await self.send(T["ACK"], {"ref": seq, "ok": True, "msg": msg})
        elif mtype == T["CONFIG_PUSH"]:
            res = await a.push_config(m.get("remarks", ""), m["config"])
            await self.send(T["ACK"], {"ref": seq, "ok": True, **res})
        else:
            await self.send(T["ERROR"], {"ref": seq, "code": "unknown", "msg": f"type {mtype:#x}"})


# ---------------------------------------------------------------- журнал Xray
RE_INFO = re.compile(r"^\S+ \S+ \[\w+\] \[(\d+)\] (.*)$")
RE_RECV = re.compile(r"proxy/dokodemo: received request for (\S+)")
RE_SNIFF = re.compile(r"app/dispatcher: sniffed domain: (\S+)")
RE_HIT = re.compile(r"app/dispatcher: Hit route rule: \[([^\]]*)\] so taking detour \[([^\]]+)\] for \[(\w+):(.+):(\d+)\]")
RE_DET = re.compile(r"app/dispatcher: taking detour \[([^\]]+)\] for \[(\w+):(.+):(\d+)\]")
RE_DEF = re.compile(r"app/dispatcher: default route for \[(\w+):(.+):(\d+)\]")
RE_ACC = re.compile(r"^\S+ \S+ from (?:(?:tcp|udp):)?(\S+) accepted (tcp|udp):(\S+):(\d+) \[(\S+) (?:->|>>) (\S+)\]")


def split_hostport(s):
    host, _, port = s.rpartition(":")
    return host.strip("[]"), int(port) if port.isdigit() else 0


class LogTail:
    def __init__(self, path):
        self.path, self.f, self.ino, self.buf = path, None, None, b""

    def read_lines(self):
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return []
        if self.f is None or st.st_ino != self.ino:
            if self.f:
                self.f.close()
            self.f, self.ino, self.buf = open(self.path, "rb"), st.st_ino, b""
            self.f.seek(0, os.SEEK_END)
        if st.st_size < self.f.tell():  # файл обрезан
            self.f.seek(0)
            self.buf = b""
        data = self.f.read()
        if not data:
            return []
        self.buf += data
        *lines, self.buf = self.buf.split(b"\n")
        return [ln.decode("utf-8", "replace") for ln in lines]


# ---------------------------------------------------------------- агент
class Agent:
    def __init__(self):
        os.makedirs(STATE_DIR, exist_ok=True)
        self.key = self.load_key()
        self.lists = self.load_lists()
        self.events = collections.deque(maxlen=BACKLOG)
        self.clients = set()
        self.pending = {}           # id -> черновик события
        self.acc = {}               # "src:port" -> (ip, port, net, inbound, out, ts)
        self.total_events = 0
        self.started = time.time()
        self.cfg_lock = asyncio.Lock()
        self.latency = {}
        self.testing = False
        self.sub_busy = False
        self.sub_error = ""

    # --- состояние
    @staticmethod
    def load_key():
        if not os.path.exists(KEY_FILE):
            with open(os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                f.write(secrets.token_hex(32))
        return bytes.fromhex(open(KEY_FILE).read().strip())

    @staticmethod
    def load_lists():
        try:
            d = json.load(open(LISTS_FILE))
        except (OSError, ValueError):
            d = {}
        return {n: sorted(set(d.get(n, []))) for n in LIST_NAMES}

    def save_json(self, path, obj, mode=0o600, group=None):
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        os.chmod(tmp, mode)
        if group is not None:
            os.chown(tmp, 0, group)
        os.replace(tmp, path)

    # --- правила Xray
    @staticmethod
    def valid_item(s):
        return bool(re.fullmatch(r"(full|domain|keyword|regexp):[^\s\"]{1,253}|geosite:[\w!@.-]{1,64}", s))

    def user_rules(self, balancers):
        rules = []
        if self.lists["block"]:
            rules.append({"ruleTag": "u-block", "type": "field", "domain": self.lists["block"], "outboundTag": "block"})
        if self.lists["direct"]:
            rules.append({"ruleTag": "u-direct", "type": "field", "domain": self.lists["direct"], "outboundTag": "direct"})
        if self.lists["vpn"]:
            r = {"ruleTag": "u-vpn", "type": "field", "domain": self.lists["vpn"]}
            if any(b.get("tag") == "auto" for b in balancers):
                r["balancerTag"] = "auto"
            else:
                r["outboundTag"] = "proxy"
            rules.append(r)
        return rules

    @staticmethod
    def base_rules(cfg):
        out = []
        for i, r in enumerate(cfg.get("routing", {}).get("rules", [])):
            if str(r.get("ruleTag", "")).startswith("u-"):
                continue
            r = dict(r)
            r.setdefault("ruleTag", f"base-{i}")
            out.append(r)
        return out

    def compose(self, cfg):
        cfg = copy.deepcopy(cfg)
        rt = cfg.setdefault("routing", {})
        rt["rules"] = self.user_rules(rt.get("balancers", [])) + self.base_rules(cfg)
        return cfg

    @staticmethod
    def nogroup():
        import grp
        return grp.getgrnam("nogroup").gr_gid

    async def run(self, *args, timeout=30):
        p = await asyncio.create_subprocess_exec(*args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            out, _ = await asyncio.wait_for(p.communicate(), timeout)
        except asyncio.TimeoutError:
            p.kill()
            return 124, "timeout"
        return p.returncode, out.decode("utf-8", "replace")

    async def xray_test(self, cfg):
        cfg = dict(cfg)
        cfg["log"] = {"loglevel": "warning"}   # проверка не должна создавать файлы журнала
        cfg.pop("api", None)                   # и занимать порт API
        fd, tmp = tempfile.mkstemp(suffix=".json", dir=STATE_DIR)
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f, ensure_ascii=False)
        os.chmod(tmp, 0o644)
        try:
            env = ["env", "XRAY_LOCATION_ASSET=/usr/local/share/xray"]
            rc, out = await self.run(*env, "xray", "run", "-test", "-config", tmp)
        finally:
            os.unlink(tmp)
        if rc != 0 or "Configuration OK" not in out:
            raise RuntimeError("xray rejected config: " + out.strip().splitlines()[-1][:300])

    async def write_cfg(self, cfg):
        self.save_json(XRAY_CFG, cfg, mode=0o640, group=self.nogroup())

    async def apply_rules_live(self, cfg):
        """Заменяет правила в работающем Xray через API; при неудаче — перезапуск."""
        rt = cfg.get("routing", {})
        payload = {"routing": {"rules": rt.get("rules", [])}}
        if rt.get("balancers"):
            payload["routing"]["balancers"] = rt["balancers"]
        fd, tmp = tempfile.mkstemp(suffix=".json", dir=STATE_DIR)
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, ensure_ascii=False)
        try:
            rc, out = await self.run("xray", "api", "adrules", "-s", API, tmp, timeout=10)
        finally:
            os.unlink(tmp)
        if rc == 0 and "failed" not in out:
            return "applied live"
        log("live apply failed, restarting xray:", out.strip()[:200])
        await self.run("systemctl", "restart", "xray")
        return "applied with xray restart"

    async def edit_list(self, name, op, items):
        if name not in LIST_NAMES or op not in ("add", "remove"):
            raise ValueError("bad list/op")
        items = [i.strip().lower() for i in items if i.strip()]
        bad = [i for i in items if not self.valid_item(i)]
        if bad:
            raise ValueError(f"bad items: {bad[:3]}")
        async with self.cfg_lock:
            old = copy.deepcopy(self.lists)
            new = copy.deepcopy(self.lists)
            if op == "add":
                new[name] = sorted(set(new[name]) | set(items))
                for other in LIST_NAMES:  # домен может быть только в одном списке
                    if other != name:
                        new[other] = sorted(set(new[other]) - set(items))
            else:
                new[name] = sorted(set(new[name]) - set(items))
            self.lists = new
            try:
                cfg = self.compose(json.load(open(XRAY_CFG)))
                await self.xray_test(cfg)
            except Exception:
                self.lists = old      # Xray не принял — ничего не меняем
                raise
            self.save_json(LISTS_FILE, self.lists)
            await self.write_cfg(cfg)
            how = await self.apply_rules_live(cfg)
        log(f"list {name} {op} {items} -> {how}")
        return how

    def ensure_xray_setup(self):
        """Подключает API и журнал в RAM к конфигу Xray. Возвращает True, если конфиг изменён."""
        cfg = json.load(open(XRAY_CFG))
        before = json.dumps(cfg, sort_keys=True)
        cfg["api"] = {"tag": "api", "listen": API, "services": ["RoutingService", "StatsService"]}
        cfg["log"] = {"loglevel": "info", "access": ACC_LOG, "error": ERR_LOG, "dnsLog": False}
        cfg = self.compose(cfg)
        if json.dumps(cfg, sort_keys=True) != before:
            self.save_json(XRAY_CFG, cfg, mode=0o640, group=self.nogroup())
            return True
        return False

    async def push_config(self, remarks, sub):
        """Берёт серверы и маршрутизацию из конфига подписки, сохраняет свои входы, API, журнал и блок рекламы."""
        if not isinstance(sub, dict) or not sub.get("outbounds"):
            raise ValueError("config without outbounds")
        async with self.cfg_lock:
            cur = json.load(open(XRAY_CFG))
            ads = next((r for r in cur.get("routing", {}).get("rules", []) if r.get("ruleTag") == "ads"), None)
            new = {k: copy.deepcopy(sub[k]) for k in ("dns", "policy", "outbounds", "observatory", "burstObservatory") if k in sub}
            srt = sub.get("routing", {})
            rules = [r for r in copy.deepcopy(srt.get("rules", []))
                     if not str(r.get("ruleTag", "")).startswith("u-") and r.get("ruleTag") != "ads"]
            for i, r in enumerate(rules):
                r.setdefault("ruleTag", f"base-{i}")
            if ads:
                pos = 1 if rules and rules[0].get("protocol") == ["bittorrent"] else 0
                rules.insert(pos, ads)
            new["routing"] = {k: v for k, v in copy.deepcopy(srt).items() if k != "rules"}
            new["routing"]["rules"] = rules
            new["inbounds"] = cur["inbounds"]
            new["api"] = cur.get("api")
            new["log"] = cur.get("log")
            new = self.compose(new)
            same = json.dumps(new, sort_keys=True) == json.dumps(cur, sort_keys=True)
            if same:
                msg = "unchanged"
            else:
                await self.xray_test(new)
                old_core = {k: cur.get(k) for k in ("outbounds", "dns", "policy", "observatory", "burstObservatory")}
                new_core = {k: new.get(k) for k in ("outbounds", "dns", "policy", "observatory", "burstObservatory")}
                await self.write_cfg(new)
                if old_core == new_core and cur.get("routing", {}).get("balancers") == new["routing"].get("balancers"):
                    msg = await self.apply_rules_live(new)
                else:
                    await self.run("systemctl", "restart", "xray")
                    msg = "applied with xray restart"
            self.save_json(ACTIVE_FILE, {"remarks": remarks, "updated": int(time.time()),
                                         "outbounds": len(new["outbounds"])})
        log("config push:", remarks, "->", msg)
        return {"msg": msg, "outbounds": len(new["outbounds"]), "remarks": remarks}

    # --- подписка через свой сервер (relay)
    def agent_conf(self):
        try:
            c = json.load(open(AGENT_CONF))
        except (OSError, ValueError):
            c = {}
        c.setdefault("relay", {})
        c.setdefault("profile", "")
        c.setdefault("refresh_hours", 6)
        return c

    def sub_cache(self):
        try:
            return json.load(open(SUB_CACHE))
        except (OSError, ValueError):
            return {}

    def sub_summary(self):
        cache, conf = self.sub_cache(), self.agent_conf()
        profiles = []
        for p in cache.get("profiles", []):
            outs = p.get("outbounds", [])
            protos = sorted({o.get("protocol", "") for o in outs} - {"freedom", "blackhole", "dns", ""})
            profiles.append({"remarks": (p.get("remarks") or "без названия").strip(), "protocols": protos,
                             "servers": sum(1 for o in outs if o.get("protocol") not in ("freedom", "blackhole", "dns"))})
        r = conf["relay"]
        return {"profiles": profiles, "selected": conf["profile"], "fetched_at": cache.get("fetched_at", 0),
                "userinfo": cache.get("userinfo", ""), "error": self.sub_error, "busy": self.sub_busy,
                "relay": f"{r.get('user', '')}@{r.get('host', '')}" if r.get("host") else ""}

    async def sub_refresh(self):
        if self.sub_busy:
            return "обновление уже идёт"
        r = self.agent_conf()["relay"]
        if not r.get("host"):
            raise RuntimeError("не настроен сервер-ретранслятор (agent.json → relay)")
        self.sub_busy = True
        await self.broadcast(T["SUB_PROFILES"], self.sub_summary(), subscribed_only=False)
        try:
            rc, out = await self.run(
                "ssh", "-i", RELAY_KEY, "-p", str(r.get("port", 22)),
                "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "IdentitiesOnly=yes",
                "-o", f"UserKnownHostsFile={RELAY_KH}", "-o", "StrictHostKeyChecking=accept-new",
                f"{r.get('user', 'tvwatch-relay')}@{r['host']}", "fetch", timeout=90)
            try:
                res = json.loads(out[out.find("{"):]) if "{" in out else {}
            except ValueError:
                res = {}
            if not res.get("ok"):
                self.sub_error = res.get("error") or ("сервер недоступен: " + out.strip()[-200:])
                raise RuntimeError(self.sub_error)
            self.sub_error = ""
            self.save_json(SUB_CACHE, {k: res[k] for k in ("fetched_at", "userinfo", "profiles") if k in res})
            msg = await self.sub_select(self.agent_conf()["profile"], refreshed=True)
            n = len(res["profiles"])
            return f"получено профилей: {n}{' (из кэша сервера)' if res.get('cached') else ''}; {msg}"
        finally:
            self.sub_busy = False
            await self.broadcast(T["SUB_PROFILES"], self.sub_summary(), subscribed_only=False)

    async def sub_select(self, remarks, refreshed=False):
        profiles = self.sub_cache().get("profiles", [])
        if not profiles:
            raise RuntimeError("подписка ещё не загружена — нажми «Обновить»")
        pick = next((p for p in profiles if (p.get("remarks") or "").strip() == remarks.strip()), None)
        if pick is None:
            if remarks and not refreshed:
                raise ValueError(f"нет профиля «{remarks}»")
            pick = profiles[0]       # выбранного профиля больше нет — берём первый
        name = (pick.get("remarks") or "без названия").strip()
        conf = self.agent_conf()
        conf["profile"] = name
        self.save_json(AGENT_CONF, conf)
        res = await self.push_config(name, pick)
        await self.broadcast(T["SERVERS"], self.servers(), subscribed_only=False)
        if not refreshed:
            await self.broadcast(T["SUB_PROFILES"], self.sub_summary(), subscribed_only=False)
        return f"профиль «{name}»: {res['msg']}"

    async def refresh_loop(self):
        """Обновляет подписку сама раз в N часов (по умолчанию 6)."""
        await asyncio.sleep(60)
        while True:
            conf = self.agent_conf()
            hours = float(conf.get("refresh_hours") or 0)
            age = time.time() - self.sub_cache().get("fetched_at", 0)
            if hours > 0 and conf["relay"].get("host") and age > hours * 3600:
                try:
                    log("auto refresh:", await self.sub_refresh())
                except Exception as e:
                    log("auto refresh failed:", e)
            await asyncio.sleep(600)

    # --- выбор сервера
    def selected(self):
        try:
            return json.load(open(SERVER_FILE)).get("tag", "")
        except (OSError, ValueError):
            return ""

    def servers(self):
        try:
            cfg = json.load(open(XRAY_CFG))
        except (OSError, ValueError):
            cfg = {}
        out = []
        for o in cfg.get("outbounds", []):
            if o.get("protocol") in ("freedom", "blackhole", "dns"):
                continue
            st, ss = o.get("settings", {}), o.get("streamSettings", {})
            if "vnext" in st:
                addr, port = st["vnext"][0].get("address", ""), st["vnext"][0].get("port", 0)
            elif "servers" in st:
                addr, port = st["servers"][0].get("address", ""), st["servers"][0].get("port", 0)
            else:
                addr, port = st.get("address", ""), st.get("port", 0)
            sec = ss.get("security", "none")
            sni = (ss.get("tlsSettings") or ss.get("realitySettings") or {}).get("serverName", "")
            out.append({"tag": o.get("tag", ""), "protocol": o.get("protocol", ""), "address": addr, "port": port,
                        "network": ss.get("network", "tcp"), "security": sec, "sni": sni,
                        "latency": self.latency.get(o.get("tag", ""))})
        auto = any(b.get("tag") == "auto" for b in cfg.get("routing", {}).get("balancers", []))
        try:
            profile = json.load(open(ACTIVE_FILE)).get("remarks", "")
        except (OSError, ValueError):
            profile = ""
        return {"servers": out, "selected": self.selected(), "auto": auto, "profile": profile, "testing": self.testing}

    async def apply_override(self):
        tag = self.selected()
        if tag:
            rc, out = await self.run("xray", "api", "bo", "-s", API, "-b", "auto", tag, timeout=5)
        else:
            rc, out = await self.run("xray", "api", "bo", "-s", API, "-b", "auto", "-r", timeout=5)
        return rc == 0 and "failed" not in out, out.strip()

    async def select_server(self, tag):
        info = self.servers()
        if not info["auto"]:
            raise RuntimeError("в этом профиле нет автовыбора — выбери другой профиль в подписке")
        if tag and tag not in {s["tag"] for s in info["servers"]}:
            raise ValueError(f"нет сервера {tag}")
        self.save_json(SERVER_FILE, {"tag": tag})
        ok, out = await self.apply_override()
        if not ok:
            raise RuntimeError("xray: " + out[:200])
        log("server ->", tag or "auto")
        return f"сервер {tag}" if tag else "автовыбор"

    async def test_servers(self, tags):
        """Задержка каждого сервера: тестовый socks-вход временно идёт через нужный сервер; телевизор не затронут."""
        self.testing = True
        await self.broadcast(T["SERVERS"], self.servers(), subscribed_only=False)
        try:
            async with self.cfg_lock:
                base = json.load(open(XRAY_CFG))
                all_tags = [s["tag"] for s in self.servers()["servers"]]
                for tag in [t for t in all_tags if not tags or t in tags]:
                    cfg = self.compose(base)
                    cfg["routing"]["rules"].insert(0, {"ruleTag": "t-test", "type": "field",
                                                       "inboundTag": ["socks"], "outboundTag": tag})
                    await self.apply_rules_live(cfg)
                    best, err = None, ""
                    for _ in range(2):
                        rc, out = await self.run("curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}",
                                                 "--max-time", "4", "-x", "socks5h://127.0.0.1:10808", TEST_URL, timeout=8)
                        parts = out.split()
                        if rc == 0 and parts and parts[0] in ("204", "200"):
                            ms = int(float(parts[1]) * 1000)
                            best = ms if best is None else min(best, ms)
                        else:
                            err = "нет ответа" if rc == 28 else f"ошибка {rc}"
                            if rc == 28:
                                break          # не ждать второй раз мёртвый сервер
                    self.latency[tag] = best
                    await self.broadcast(T["SERVER_TEST_RESULT"], {"tag": tag, "ms": best, "error": "" if best else err,
                                                                   "done": False}, subscribed_only=False)
                await self.apply_rules_live(self.compose(base))   # вернуть правила как были
        except Exception as e:
            log("server test failed:", e)
        finally:
            self.testing = False
            await self.broadcast(T["SERVER_TEST_RESULT"], {"tag": "", "done": True}, subscribed_only=False)
            await self.broadcast(T["SERVERS"], self.servers(), subscribed_only=False)

    # --- статус
    async def status(self):
        def rd(p):
            try:
                return int(open(p).read())
            except (OSError, ValueError):
                return 0
        rc, act = await self.run("systemctl", "is-active", "xray", timeout=5)
        _, temp = await self.run("vcgencmd", "measure_temp", timeout=5)
        _, bi = await self.run("xray", "api", "bi", "-s", API, "auto", timeout=5)
        try:
            active = json.load(open(ACTIVE_FILE))
        except (OSError, ValueError):
            active = {}
        try:
            n_out = len(json.load(open(XRAY_CFG)).get("outbounds", []))
        except (OSError, ValueError):
            n_out = 0
        up = float(open("/proc/uptime").read().split()[0])
        return {
            "uptime": int(up), "agent_uptime": int(time.time() - self.started),
            "xray": act.strip(), "temp": temp.strip().replace("temp=", ""),
            "to_tv": rd("/sys/class/net/eth0/statistics/tx_bytes"),
            "from_tv": rd("/sys/class/net/eth0/statistics/rx_bytes"),
            "profile": active.get("remarks", ""), "profile_updated": active.get("updated", 0),
            "outbounds": n_out, "balancer": " ".join(bi.split())[:600],
            "lists": {n: len(v) for n, v in self.lists.items()}, "events": self.total_events,
        }

    # --- события
    async def broadcast(self, mtype, obj, subscribed_only=True):
        for c in list(self.clients):
            if c.skey and (c.subscribed or not subscribed_only):
                try:
                    await c.send(mtype, obj)
                except Exception:
                    self.clients.discard(c)

    def handle_info(self, line):
        m = RE_INFO.match(line)
        if not m:
            return None
        cid, msg = int(m.group(1)), m.group(2)
        if (r := RE_RECV.search(msg)):
            src, sport = split_hostport(r.group(1))
            self.pending[cid] = {"id": cid, "ts": int(time.time() * 1000), "src": src, "sport": sport}
            return None
        ev = self.pending.get(cid)
        if ev is None:
            return None
        if (r := RE_SNIFF.search(msg)):
            ev["host"] = r.group(1)
            return None
        rule, out = "", None
        if (r := RE_HIT.search(msg)):
            rule, out, net, host, port = r.groups()
        elif (r := RE_DET.search(msg)):
            out, net, host, port = r.groups()
        elif (r := RE_DEF.search(msg)):
            out = "default"
            net, host, port = r.groups()
        if out is None:
            return None
        ev.update(net=net, port=int(port), out=out, rule=rule)
        ev.setdefault("host", host)
        ev["kind"] = "block" if out == "block" else "direct" if out in ("direct", "default") else "vpn"
        return self.pending.pop(cid)

    def handle_access(self, line):
        m = RE_ACC.match(line)
        if m:
            src, net, ip, port, inb, out = m.groups()
            self.acc[src] = (ip, int(port), net, inb)

    async def tail_loop(self):
        err, acc = LogTail(ERR_LOG), LogTail(ACC_LOG)
        ready = []      # (deadline, event) — ждём строку access.log с IP назначения
        while True:
            for ln in acc.read_lines():
                self.handle_access(ln)
            for ln in err.read_lines():
                ev = self.handle_info(ln)
                if ev:
                    ready.append((time.monotonic() + 0.4, ev))
            for ln in acc.read_lines():
                self.handle_access(ln)
            now, out, keep = time.monotonic(), [], []
            for dl, ev in ready:
                a = self.acc.get(f"{ev['src']}:{ev['sport']}")
                if a or dl <= now:
                    if a:
                        ev["ip"] = a[0]
                        ev.setdefault("port", a[1])
                    ev.setdefault("ip", "")
                    out.append(ev)
                else:
                    keep.append((dl, ev))
            ready = keep
            if out:
                self.events.extend(out)
                self.total_events += len(out)
                if len(out) == 1:
                    await self.broadcast(T["EVENT"], out[0])
                else:
                    await self.broadcast(T["EVENT_BATCH"], {"events": out})
            if len(self.acc) > 5000:
                self.acc = dict(list(self.acc.items())[-1000:])
            if len(self.pending) > 5000:
                for k in list(self.pending)[:4000]:
                    self.pending.pop(k, None)
            await asyncio.sleep(0.15)

    async def override_loop(self):
        """После перезапуска Xray заново применяет выбранный вручную сервер."""
        last_pid = None
        while True:
            _, pid = await self.run("systemctl", "show", "-p", "MainPID", "--value", "xray", timeout=5)
            pid = pid.strip()
            if pid and pid != "0" and pid != last_pid:
                await asyncio.sleep(2)   # дать Xray поднять API
                if self.selected():
                    tags = {s["tag"] for s in self.servers()["servers"]}
                    if self.selected() not in tags:      # сервера больше нет в профиле
                        self.save_json(SERVER_FILE, {"tag": ""})
                    ok, out = await self.apply_override()
                    log("override reapplied:", self.selected() or "auto", "ok" if ok else out[:120])
                last_pid = pid
            await asyncio.sleep(10)

    async def rotate_loop(self):
        while True:
            for p in (ERR_LOG, ACC_LOG):
                try:
                    if os.path.getsize(p) > LOG_MAX:
                        os.truncate(p, 0)
                except OSError:
                    pass
            await asyncio.sleep(30)

    async def serve(self):
        async def on_client(r, w):
            c = Conn(r, w, self)
            self.clients.add(c)
            await c.run()
        srv = await asyncio.start_server(on_client, "0.0.0.0", PORT)
        log(f"TVWP/1 listening on :{PORT}")
        async with srv:
            await asyncio.gather(srv.serve_forever(), self.tail_loop(), self.rotate_loop(), self.override_loop(),
                                 self.refresh_loop())


def main():
    agent = Agent()
    if "--setup-xray" in sys.argv:
        changed = agent.ensure_xray_setup()
        asyncio.run(agent.xray_test(json.load(open(XRAY_CFG))))
        print("xray config", "updated" if changed else "already set up", "- test OK")
        return
    asyncio.run(agent.serve())


if __name__ == "__main__":
    main()
