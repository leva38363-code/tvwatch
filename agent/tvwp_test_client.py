#!/usr/bin/env python3
"""Тестовый клиент TVWP/1: проверяет рукопожатие, подпись кадров и все запросы."""
import hashlib, hmac, json, os, secrets, socket, struct, subprocess, sys, time, zlib

HDR = struct.Struct(">2sBBBBII")
T = dict(HELLO=1, AUTH=2, AUTH_OK=3, AUTH_FAIL=4, ACK=5, ERROR=6, SUBSCRIBE=0x10, EVENT=0x11,
         EVENT_BATCH=0x12, LISTS_GET=0x20, LISTS=0x21, LIST_EDIT=0x22, STATUS_GET=0x30, STATUS=0x31,
         CONFIG_PUSH=0x40, SERVERS_GET=0x50, SERVERS=0x51, SERVER_SELECT=0x52, SERVER_TEST=0x53,
         SERVER_TEST_RESULT=0x54, SUB_GET=0x60, SUB_PROFILES=0x61, SUB_REFRESH=0x62, SUB_SELECT=0x63,
         PING=0x7E, PONG=0x7F)
N = {v: k for k, v in T.items()}
hm = lambda k, *p: hmac.new(k, b"".join(p), hashlib.sha256).digest()


class Client:
    def __init__(self, host, key):
        self.s = socket.create_connection((host, 7878), timeout=10)
        self.key, self.skey, self.seq, self.f = key, None, 0, self.s.makefile("rb")

    def send(self, t, obj):
        raw = json.dumps(obj).encode(); fl = 0
        if len(raw) > 4096: raw, fl = zlib.compress(raw), 1
        self.seq += 1
        h = HDR.pack(b"TW", 1, t, fl, 0, self.seq, len(raw))
        self.s.sendall(h + raw + (hm(self.skey, h, raw)[:16] if self.skey else bytes(16)))
        return self.seq

    def recv(self):
        h = self.f.read(HDR.size); _, _, t, fl, _, seq, ln = HDR.unpack(h)
        raw = self.f.read(ln); tag = self.f.read(16)
        if self.skey: assert hmac.compare_digest(tag, hm(self.skey, h, raw)[:16]), "bad server tag"
        if fl & 1: raw = zlib.decompress(raw)
        return N.get(t, t), json.loads(raw)

    def auth(self, key=None):
        t, m = self.recv(); assert t == "HELLO", t
        ns, nc = bytes.fromhex(m["nonce"]), secrets.token_bytes(16)
        k = key or self.key
        self.send(T["AUTH"], {"client": "test", "ver": 1, "nonce": nc.hex(), "mac": hm(k, b"TVWP1-client|", ns, nc).hex()})
        t, m = self.recv()
        if t != "AUTH_OK": return t
        assert hmac.compare_digest(bytes.fromhex(m["proof"]), hm(self.key, b"TVWP1-server|", nc, ns)), "server proof"
        self.skey = hm(self.key, b"TVWP1-session|", ns, nc)
        return t

    def until(self, want, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            t, m = self.recv()
            if t in want: return t, m
        raise TimeoutError(want)


def tv(cmd):
    return subprocess.run(["ip", "netns", "exec", "tvt", "sh", "-c", cmd], capture_output=True, text=True).stdout


if __name__ == "__main__":
    key = bytes.fromhex(open("/usr/local/etc/tvwatch/key").read().strip())
    ok = lambda name, cond: print(("PASS " if cond else "FAIL ") + name) or cond

    c = Client("127.0.0.1", key)
    ok("wrong key rejected", c.auth(key=secrets.token_bytes(32)) == "AUTH_FAIL")

    c = Client("127.0.0.1", key)
    ok("handshake + server proof", c.auth() == "AUTH_OK")
    c.send(T["PING"], {"t": 42}); t, m = c.until({"PONG"}); ok("ping/pong", m["t"] == 42)
    c.send(T["STATUS_GET"], {}); t, st = c.until({"STATUS"})
    ok(f"status (xray={st['xray']}, outbounds={st['outbounds']}, to_tv={st['to_tv']//1048576} MB)", st["xray"] == "active")
    c.send(T["LISTS_GET"], {}); t, ls = c.until({"LISTS"}); ok(f"lists {ls}", set(ls) == {"block", "direct", "vpn"})

    c.send(T["SUBSCRIBE"], {"backlog": 50}); t, m = c.until({"ACK"}); ok("subscribe: " + m["msg"], m["ok"])
    tv("curl -4 -s -o /dev/null --max-time 10 https://example.com/")
    t, ev = c.until({"EVENT", "EVENT_BATCH"})
    evs = ev["events"] if t == "EVENT_BATCH" else [ev]
    e = next((x for x in evs if x.get("host") == "example.com"), evs[-1])
    ok(f"live event: {e.get('src')} -> {e.get('host')} ip={e.get('ip')} out={e.get('out')} kind={e.get('kind')} rule={e.get('rule')}",
       e.get("host") == "example.com" and e.get("src") == "10.43.0.2" and e.get("ip"))

    seq = c.send(T["LIST_EDIT"], {"list": "block", "op": "add", "items": ["full:example.com"]})
    t, m = c.until({"ACK", "ERROR"}); ok("block example.com: " + m.get("msg", ""), t == "ACK")
    code = tv("curl -4 -s -o /dev/null -w '%{http_code}' --max-time 8 https://example.com/")
    e, end = {}, time.time() + 15
    while time.time() < end and e.get("kind") != "block":
        t, ev = c.until({"EVENT", "EVENT_BATCH"})
        for x in (ev["events"] if t == "EVENT_BATCH" else [ev]):
            if x.get("host") == "example.com":
                e = x
    ok(f"blocked live (http={code}, kind={e.get('kind')}, rule={e.get('rule')})", e.get("kind") == "block" and e.get("rule") == "u-block")

    c.send(T["LIST_EDIT"], {"list": "block", "op": "remove", "items": ["full:example.com"]})
    t, m = c.until({"ACK", "ERROR"}); ok("unblock: " + m.get("msg", ""), t == "ACK")
    code = tv("curl -4 -s -o /dev/null -w '%{http_code}' --max-time 10 https://example.com/")
    ok(f"works again (http={code})", code == "200")

    c.send(T["LIST_EDIT"], {"list": "block", "op": "add", "items": ["bad item!"]})
    t, m = c.until({"ACK", "ERROR"}); ok("invalid item rejected: " + m.get("msg", ""), t == "ERROR")

    cfg = json.load(open("/usr/local/etc/xray/config.json"))
    c.send(T["CONFIG_PUSH"], {"remarks": "test-same", "config": cfg})
    t, m = c.until({"ACK", "ERROR"}, 60); ok(f"config push of current config: {m.get('msg')}", t == "ACK" and m.get("msg") == "unchanged")
