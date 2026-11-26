#!/usr/bin/env python3
import subprocess, sys
sys.path.insert(0, "/tmp/tvw")
from tvwp_test_client import Client, T
ok = lambda n, c: print(("PASS " if c else "FAIL ") + n)
K = "/usr/local/etc/tvwatch"
import json
_r = json.load(open(f"{K}/agent.json"))["relay"]
RELAY = f"{_r['user']}@{_r['host']}"
ssh = ["ssh", "-p", str(_r.get("port", 22)), "-i", f"{K}/relay_ed25519", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
       "-o", f"UserKnownHostsFile={K}/relay_known_hosts", "-o", "StrictHostKeyChecking=accept-new", RELAY]
r = subprocess.run(ssh + ["ping"], capture_output=True, text=True, timeout=30); ok(f"relay ping: {r.stdout.strip()}", '"ok": true' in r.stdout)
r = subprocess.run(ssh + ["cat /etc/passwd"], capture_output=True, text=True, timeout=30); ok(f"shell command refused: {r.stdout.strip()}", "запрещена" in r.stdout)
r = subprocess.run(ssh + ["set-hwid"], capture_output=True, text=True, timeout=30); ok("set-hwid via Pi key refused", "запрещена" in r.stdout)
import socket, time
fw = subprocess.Popen(ssh[:-1] + ["-N", "-L", "19999:127.0.0.1:22", ssh[-1]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(4)
banner = b""
try:
    s = socket.create_connection(("127.0.0.1", 19999), timeout=5); s.settimeout(5)
    banner = s.recv(64); s.close()
except OSError:
    pass
fw.terminate(); _, err = fw.communicate(timeout=10)
ok(f"port forwarding refused (got {banner[:20]!r}; ssh says: {err.strip().splitlines()[-1] if err.strip() else '-'})", not banner.startswith(b"SSH-"))
key = bytes.fromhex(open(f"{K}/key").read().strip())
c = Client("127.0.0.1", key); c.s.settimeout(None); assert c.auth() == "AUTH_OK"
c.send(T["SUB_GET"], {}); _, m = c.until({"SUB_PROFILES"}); ok(f"sub summary: relay={m['relay']} profiles={len(m['profiles'])}", m["relay"] == RELAY)
c.send(T["SUB_REFRESH"], {}); t, m = c.until({"ACK", "ERROR"}, 120)
ok(f"refresh without HWID -> {t}: {m.get('msg')}", t == "ERROR" and "HWID" in m.get("msg", ""))
