#!/usr/bin/env python3
"""Проверка SERVERS_GET / SERVER_TEST / SERVER_SELECT."""
import subprocess, sys, time
sys.path.insert(0, "/tmp/tvw")
from tvwp_test_client import Client, T
key = bytes.fromhex(open("/usr/local/etc/tvwatch/key").read().strip())
c = Client("127.0.0.1", key); c.s.settimeout(None); assert c.auth() == "AUTH_OK"
ok = lambda n, cond: print(("PASS " if cond else "FAIL ") + n)
c.send(T["SERVERS_GET"], {}); _, s = c.until({"SERVERS"})
srv = s["servers"]
ok(f"servers: {len(srv)}, auto={s['auto']}, selected={s['selected']!r}, e.g. {srv[0]['tag']} {srv[0]['protocol']} {srv[0]['address']}", len(srv) > 0)
tags = [x["tag"] for x in srv[:4]]
c.send(T["SERVER_TEST"], {"tags": tags}); _, a = c.until({"ACK", "ERROR"}); ok("test started", a.get("ok"))
res = {}
t0 = time.time()
while True:
    t, m = c.until({"SERVER_TEST_RESULT"}, 120)
    if m.get("done"): break
    res[m["tag"]] = m.get("ms") if m.get("ms") is not None else m.get("error")
ok(f"latency ({time.time()-t0:.0f}s): {res}", len(res) == len(tags))
rules = subprocess.run(["xray", "api", "lsrules", "-s", "127.0.0.1:10085"], capture_output=True, text=True).stdout
ok("test rule removed afterwards", "t-test" not in rules)
pick = next((t for t, v in res.items() if isinstance(v, int)), tags[0])
c.send(T["SERVER_SELECT"], {"tag": pick}); t, a = c.until({"ACK", "ERROR"}); ok(f"select {pick}: {a.get('msg')}", t == "ACK")
bi = subprocess.run(["xray", "api", "bi", "-s", "127.0.0.1:10085", "auto"], capture_output=True, text=True).stdout
ok("override active in xray", pick in bi.split("Selects")[0])
c.send(T["SERVER_SELECT"], {"tag": ""}); t, a = c.until({"ACK", "ERROR"}); ok(f"back to auto: {a.get('msg')}", t == "ACK")
bi = subprocess.run(["xray", "api", "bi", "-s", "127.0.0.1:10085", "auto"], capture_output=True, text=True).stdout
ok("override cleared", pick not in bi.split("Selects")[0])
c.send(T["SERVER_SELECT"], {"tag": "nope"}); t, a = c.until({"ACK", "ERROR"}); ok("unknown tag rejected", t == "ERROR")
