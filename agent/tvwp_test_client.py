#!/usr/bin/env python3
"""Тестовый клиент TVWP/2 (рукопожатие PSK + ML-KEM-1024, кадры ChaCha20-Poly1305) и функциональные тесты.

    sudo python3 tvwp_test_client.py           # на Pi; для живых событий нужен netns «tvt» с имитацией ТВ
"""
import json, os, secrets, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tvwp_crypto as C  # noqa: E402

T = dict(HELLO=1, AUTH=2, AUTH_OK=3, AUTH_FAIL=4, ACK=5, ERROR=6, SUBSCRIBE=0x10, EVENT=0x11,
         EVENT_BATCH=0x12, LISTS_GET=0x20, LISTS=0x21, LIST_EDIT=0x22, STATUS_GET=0x30, STATUS=0x31,
         CONFIG_PUSH=0x40, SERVERS_GET=0x50, SERVERS=0x51, SERVER_SELECT=0x52, SERVER_TEST=0x53,
         SERVER_TEST_RESULT=0x54, SUB_GET=0x60, SUB_PROFILES=0x61, SUB_REFRESH=0x62, SUB_SELECT=0x63,
         PING=0x7E, PONG=0x7F)
N = {v: k for k, v in T.items()}


class Client:
    def __init__(self, host, key, port=7878):
        self.s = socket.create_connection((host, port), timeout=15)
        self.f = self.s.makefile("rb")
        self.key, self.chan, self.seq, self.rseq = key, None, 0, 0

    def send(self, t, obj):
        raw = json.dumps(obj).encode()
        self.seq += 1
        self.s.sendall(self.chan.seal(t, self.seq, raw) if self.chan else C.plain_frame(t, self.seq, raw))
        return self.seq

    def recv(self):
        h = self.f.read(C.HDR.size)
        if len(h) < C.HDR.size:
            raise ConnectionError("closed")
        _, _, t, fl, _, seq, ln = C.HDR.unpack(h)
        body = self.f.read(ln)
        assert seq > self.rseq, "server replayed a frame"
        self.rseq = seq
        if self.chan:
            assert fl & C.FLAG_ENC, "plaintext frame after auth"
            body = self.chan.open(h, seq, body)
        return N.get(t, t), json.loads(body or b"{}")

    def auth(self, key=None):
        t, m = self.recv(); assert t == "HELLO", t
        ns, nc, kem = C.unb64(m["nonce"]), secrets.token_bytes(32), C.KemClient()
        k = key or self.key
        self.send(T["AUTH"], {"client": "test", "ver": 2, "nonce": C.b64(nc), "kem_pub": C.b64(kem.pub),
                              "mac": C.b64(C.client_mac(k, ns, nc, kem.pub))})
        t, m = self.recv()
        if t != "AUTH_OK":
            return t
        ct = C.unb64(m["ct"])
        assert C.unb64(m["proof"]) == C.server_proof(self.key, ns, nc, kem.pub, ct), "server proof"
        ss = kem.decapsulate(ct)
        c2s, s2c = C.session_keys(self.key, ss, ns, nc, kem.pub, ct)
        self.chan = C.Channel(k_send=c2s, k_recv=s2c)
        self.ns, self.nc, self.kem_pub, self.ct = ns, nc, kem.pub, ct
        return t

    def until(self, want, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            t, m = self.recv()
            if t in want:
                return t, m
        raise TimeoutError(want)


def tv(cmd):
    return subprocess.run(["ip", "netns", "exec", "tvt", "sh", "-c", cmd], capture_output=True, text=True).stdout


if __name__ == "__main__":
    key = bytes.fromhex(open("/usr/local/etc/tvwatch/key").read().strip())
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    ok = lambda name, cond: print(("PASS " if cond else "FAIL ") + name) or cond

    c = Client(host, key)
    ok("wrong key rejected", c.auth(key=secrets.token_bytes(32)) == "AUTH_FAIL")

    c = Client(host, key)
    t0 = time.time()
    r = c.auth()
    ok(f"handshake ML-KEM-1024 + server proof ({(time.time()-t0)*1000:.0f} ms)", r == "AUTH_OK")
    c.send(T["PING"], {"t": 42}); t, m = c.until({"PONG"}); ok("ping/pong (encrypted)", m["t"] == 42)
    c.send(T["STATUS_GET"], {}); t, st = c.until({"STATUS"})
    ok(f"status (xray={st['xray']}, outbounds={st['outbounds']})", st["xray"] == "active")
    c.send(T["LISTS_GET"], {}); t, ls = c.until({"LISTS"}); ok(f"lists {ls}", set(ls) == {"block", "direct", "vpn"})
    c.send(T["SERVERS_GET"], {}); t, sv = c.until({"SERVERS"}); ok(f"servers: {len(sv['servers'])}", len(sv["servers"]) > 0)
    c.send(T["SUBSCRIBE"], {"backlog": 3000}); t, m = c.until({"ACK"}, 30); ok("subscribe (big backlog frames): " + m["msg"], m["ok"])

    if "tvt" in subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout:
        tv("curl -4 -s -o /dev/null --max-time 10 https://example.com/")
        e, end = {}, time.time() + 15
        while time.time() < end and e.get("host") != "example.com":
            t, ev = c.until({"EVENT", "EVENT_BATCH"})
            for x in (ev["events"] if t == "EVENT_BATCH" else [ev]):
                if x.get("host") == "example.com":
                    e = x
        ok(f"live event: {e.get('src')} -> {e.get('host')} kind={e.get('kind')}", e.get("host") == "example.com")
        c.send(T["LIST_EDIT"], {"list": "block", "op": "add", "items": ["full:example.com"]})
        t, m = c.until({"ACK", "ERROR"}); ok("block example.com: " + m.get("msg", ""), t == "ACK")
        code = tv("curl -4 -s -o /dev/null -w '%{http_code}' --max-time 8 https://example.com/")
        ok(f"blocked for TV (http={code})", code == "000")
        c.send(T["LIST_EDIT"], {"list": "block", "op": "remove", "items": ["full:example.com"]})
        t, m = c.until({"ACK", "ERROR"}); ok("unblock: " + m.get("msg", ""), t == "ACK")
        code = tv("curl -4 -s -o /dev/null -w '%{http_code}' --max-time 10 https://example.com/")
        ok(f"works again (http={code})", code == "200")
