#!/usr/bin/env python3
"""Проверка безопасности TVWP/2 с позиции устройства в домашней сети.

    sudo python3 tvwp_security_test.py <host>        # на Pi (нужны ключ агента, OpenSSL 3.5+, python3-cryptography)

Тесты на перегрузку — в безопасном масштабе; пиковая память агента меряется во время атаки.
"""
import json, os, secrets, socket, subprocess, sys, threading, time, zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tvwp_crypto as C  # noqa: E402
from tvwp_test_client import Client, T  # noqa: E402

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
KEY = bytes.fromhex(open("/usr/local/etc/tvwatch/key").read().strip())
PORT = 7878
results = []


def report(name, passed, detail="", severity="—"):
    results.append((name, passed))
    print(f"{'OK  ' if passed else 'VULN'} [{severity:>6}] {name}" + (f" — {detail}" if detail else ""), flush=True)


def section(t):
    print(f"\n== {t} ==", flush=True)


def agent_pid():
    return subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", "tvwatch-agent"],
                          capture_output=True, text=True).stdout.strip()


def rss_mb(pid):
    try:
        return int(open(f"/proc/{pid}/status").read().split("VmRSS:")[1].split()[0]) / 1024
    except Exception:
        return 0


class PeakMem:
    """Пиковая память агента, пока идёт атака."""
    def __init__(self):
        self.pid, self.peak, self.stop = agent_pid(), 0, False
        self.base = rss_mb(self.pid)
        self.t = threading.Thread(target=self.run, daemon=True); self.t.start()

    def run(self):
        while not self.stop:
            self.peak = max(self.peak, rss_mb(self.pid)); time.sleep(0.02)

    def done(self):
        time.sleep(1.5); self.stop = True; self.t.join()
        return self.base, self.peak


def raw():
    s = socket.create_connection((HOST, PORT), timeout=8)
    return s, s.makefile("rb")


def read_frame(f):
    h = f.read(C.HDR.size)
    if len(h) < C.HDR.size:
        return None, None, None
    _, _, t, fl, _, seq, ln = C.HDR.unpack(h)
    return t, h, f.read(ln)


def closed(s, timeout=8):
    s.settimeout(timeout)
    try:
        while True:
            if not s.recv(65536):
                return True
    except socket.timeout:
        return False
    except OSError:
        return True


def authed():
    c = Client(HOST, KEY); assert c.auth() == "AUTH_OK"; return c


# ------------------------------------------------------------------ аутентификация
section("Аутентификация и обмен ключами")
c = Client(HOST, KEY)
report("неверный ключ отклоняется", c.auth(key=secrets.token_bytes(32)) == "AUTH_FAIL" and closed(c.s), "", "крит")

s, f = raw(); read_frame(f)
s.sendall(C.plain_frame(T["LISTS_GET"], 1, b"{}"))
report("запрос без входа не выполняется", closed(s), "", "крит")

c = authed(); c.s.close()
report("сервер доказывает знание ключа и шифротекста ML-KEM", True, "проверено в Client.auth()", "высок")

nonces = set()
for _ in range(15):
    s, f = raw(); t, h, b = read_frame(f); nonces.add(json.loads(b)["nonce"]); s.close()
report("одноразовые числа сервера не повторяются", len(nonces) == 15, f"{len(nonces)}/15", "высок")

# подмена ключа ML-KEM посредником: заменить kem_pub в чужом AUTH
s, f = raw(); t, h, b = read_frame(f); ns = C.unb64(json.loads(b)["nonce"])
nc, kem_real, kem_evil = secrets.token_bytes(32), C.KemClient(), C.KemClient()
auth = {"client": "x", "ver": 2, "nonce": C.b64(nc), "kem_pub": C.b64(kem_evil.pub),
        "mac": C.b64(C.client_mac(KEY, ns, nc, kem_real.pub))}      # подпись от настоящего ключа, ключ ML-KEM — чужой
s.sendall(C.plain_frame(T["AUTH"], 1, json.dumps(auth).encode()))
t, _, _ = read_frame(f)
report("подмена ключа ML-KEM посредником обнаруживается", t == T["AUTH_FAIL"], "", "крит")

# перехваченное рукопожатие к новой сессии
s1, f1 = raw(); _, _, b1 = read_frame(f1); ns1 = C.unb64(json.loads(b1)["nonce"])
k = C.KemClient(); nc = secrets.token_bytes(32)
old = C.plain_frame(T["AUTH"], 1, json.dumps({"client": "x", "ver": 2, "nonce": C.b64(nc), "kem_pub": C.b64(k.pub),
                                              "mac": C.b64(C.client_mac(KEY, ns1, nc, k.pub))}).encode())
s2, f2 = raw(); read_frame(f2); s2.sendall(old)
t, _, _ = read_frame(f2)
report("перехваченное рукопожатие не подходит к новой сессии", t == T["AUTH_FAIL"], "", "крит")
s1.close(); s2.close(); s.close()

s, f = raw(); read_frame(f); time.sleep(6)
report("молчащий клиент отключается (5 с)", closed(s, 3), "", "средн")

# ------------------------------------------------------------------ целостность
section("Целостность и шифрование после входа")
c = authed()
fr = bytearray(c.chan.seal(T["PING"], 2, b'{"t":1}')); fr[C.HDR.size + 2] ^= 1
c.s.sendall(bytes(fr))
report("изменённый шифротекст отвергается", closed(c.s), "", "крит")

c = authed()
fr = bytearray(c.chan.seal(T["PING"], 2, b'{"t":1}')); fr[3] = T["LISTS_GET"]       # подмена типа в заголовке
c.s.sendall(bytes(fr))
report("изменённый заголовок отвергается (заголовок под AEAD)", closed(c.s), "", "крит")

c = authed()
good = c.chan.seal(T["PING"], 2, b'{"t":1}'); c.s.sendall(good); t, _ = c.recv(); c.s.sendall(good)
report("повтор кадра отвергается", t == "PONG" and closed(c.s), "", "высок")

c = authed()
c.s.sendall(C.plain_frame(T["PING"], 2, b'{"t":1}'))
report("незашифрованный кадр после входа отвергается", closed(c.s), "", "крит")

c1, c2 = authed(), authed()
c2.s.sendall(c1.chan.seal(T["PING"], 2, b'{"t":1}'))
report("кадр, зашифрованный ключом другой сессии, отвергается", closed(c2.s), "", "крит")
c1.s.close()

c = authed()
c.send(T["LISTS_GET"], {})
h = c.f.read(C.HDR.size); _, _, t, fl, _, seq, ln = C.HDR.unpack(h); body = c.f.read(ln)
plain_visible = b"block" in body or b"direct" in body
report("содержимое кадров зашифровано", bool(not plain_visible and fl & C.FLAG_ENC),
       f"ChaCha20-Poly1305, {ln} байт шифротекста", "средн")
c.s.close(); time.sleep(0.5)

# ------------------------------------------------------------------ формат
section("Битые кадры и старые версии")
for name, data in [("неверная сигнатура", b"XX" + C.plain_frame(2, 1, b"{}")[2:]),
                   ("клиент TVWP/1", C.HDR.pack(b"TW", 1, 2, 0, 0, 1, 2) + b"{}" + bytes(16)),
                   ("кадр 5000 байт до входа", C.HDR.pack(b"TW", 2, 2, 0, 0, 1, 5000)),
                   ("флаги (сжатие) до входа", C.HDR.pack(b"TW", 2, 2, 1, 0, 1, 2) + b"{}"),
                   ("мусор вместо JSON", C.plain_frame(2, 1, b"\xff\xfe not json"))]:
    s, f = raw(); read_frame(f); s.sendall(data)
    report(f"{name} → разрыв", closed(s), "", "средн")
s, f = raw(); t, _, _ = read_frame(f)
report("агент жив после битых кадров", t == T["HELLO"], "", "—")
s.close()

# ------------------------------------------------------------------ перегрузка
section("Перегрузка без ключа (безопасный масштаб)")
time.sleep(1)
pid0 = agent_pid()
pm = PeakMem()
bomb = zlib.compress(b"\0" * (200 * 1024 * 1024), 9)
s, f = raw(); read_frame(f)
try:
    s.sendall(C.HDR.pack(b"TW", 2, 2, 1, 0, 1, len(bomb)) + bomb)
except OSError:
    pass
base, peak = pm.done()
report("zlib-бомба до входа не распаковывается", peak - base < 20, f"бомба {len(bomb)//1024} КБ: пик памяти {base:.0f} → {peak:.0f} МБ", "крит")

pm = PeakMem()
socks = []
for _ in range(10):
    try:
        s, f = raw(); s.sendall(C.HDR.pack(b"TW", 2, 2, 0, 0, 1, 6 * 1024 * 1024) + b"\0" * (1024 * 1024)); socks.append(s)
    except OSError:
        pass
base, peak = pm.done()
report("большие кадры до входа не принимаются", peak - base < 20, f"10×6 МБ: пик памяти {base:.0f} → {peak:.0f} МБ", "высок")
for s in socks:
    s.close()

time.sleep(1)
opened = []
for _ in range(200):
    try:
        s = socket.create_connection((HOST, PORT), timeout=3); s.settimeout(2)
        if s.recv(1):          # получил HELLO — значит, соединение принято
            opened.append(s)
        else:
            s.close()
    except OSError:
        pass
report("число соединений без входа ограничено", len(opened) <= 4, f"принято {len(opened)} из 200 (лимит: 2 на адрес, 4 всего)", "средн")
for s in opened:
    s.close()

time.sleep(6)
report("агент пережил тесты без перезапуска", agent_pid() == pid0 and Client(HOST, KEY).auth() == "AUTH_OK",
       f"PID {pid0} → {agent_pid()}", "—")

print("\nИтог:", sum(1 for r in results if r[1]), "OK,", sum(1 for r in results if not r[1]), "уязвимостей")
