# TVWP/2 — TV Watch Protocol

Протокол между агентом на Raspberry Pi (`tvwatch-agent`) и приложением на Mac (`TVWatch.app`).
Транспорт: TCP, порт **7878** на Pi (со стороны телевизора закрыт фаерволом и самим агентом).

**Криптография (постквантовая):**

| Задача | Алгоритм | Стойкость |
|---|---|---|
| Обмен ключами | **ML-KEM-1024** (FIPS 203), одноразовая пара ключей на каждое соединение | NIST категория 5 (как AES-256), устойчив к квантовому компьютеру |
| Аутентификация | общий ключ 256 бит + HMAC-SHA256 | квантовый компьютер даёт лишь √ ускорение (Гровер) → ≥128 бит |
| Ключи сессии | HKDF-SHA256 из **общего ключа И секрета ML-KEM** (гибрид) | чтобы взломать, нужно сломать оба |
| Шифрование кадров | **ChaCha20-Poly1305**, 256-битный ключ на каждое направление | ≥128 бит даже против квантового компьютера |
| Прямая секретность | ключ ML-KEM одноразовый и удаляется после рукопожатия | утечка общего ключа не раскрывает записанные сеансы |

В протоколе нет RSA и эллиптических кривых — единственного, что ломает алгоритм Шора.

## Кадр

```
 0      2     3      4      5      6          10         14
 +------+-----+------+------+------+----------+----------+----------------------------------+
 | "TW" | ver | type | flag | rsv  | seq (BE) | len (BE) | body (len байт)                  |
 +------+-----+------+------+------+----------+----------+----------------------------------+
```

- `ver` = 2. Кадры другой версии — разрыв.
- `seq` строго растёт в каждом направлении (защита от повтора), с первого кадра.
- До входа: `flag` = 0, `body` — JSON, `len` ≤ **4096**. Сжатия в протоколе нет.
- После входа: `flag` = `0x02` (ENC), `body` = `ChaCha20-Poly1305(key_dir, nonce, json, aad=header)` = шифротекст ‖ тег 16 Б,
  `len` ≤ 8 MiB. `nonce` = `00 00 00 00 ‖ seq (8 Б, BE)`. Заголовок целиком под защитой AEAD.
  Незашифрованный кадр после входа — разрыв.

## Рукопожатие

Общий ключ `K` (32 байта): на Pi — `/usr/local/etc/tvwatch/key`, на Mac — в Связке ключей.

1. S → C `HELLO {server, ver: 2, kem: "ML-KEM-1024", nonce: b64(ns, 32 Б)}`
2. C создаёт одноразовую пару ML-KEM-1024 и отправляет
   `AUTH {client, ver: 2, nonce: b64(nc, 32 Б), kem_pub: b64(ek, 1568 Б),`
   `mac: b64(HMAC(K, "TVWP2-client" ‖ ns ‖ nc ‖ SHA256(ek)))}` — подпись привязывает ключ ML-KEM к общему ключу, подменить его посредник не может.
3. S проверяет `mac` (за постоянное время), инкапсулирует `ct, ss = ML-KEM.Encaps(ek)` и отвечает
   `AUTH_OK {ct: b64(ct, 1568 Б), proof: b64(HMAC(K, "TVWP2-server" ‖ nc ‖ ns ‖ SHA256(ek) ‖ SHA256(ct)))}`.
   Иначе `AUTH_FAIL` и разрыв.
4. C проверяет `proof` (за постоянное время), получает `ss = ML-KEM.Decaps(dk, ct)` и удаляет `dk`.
5. Обе стороны: `salt = SHA256(ns ‖ nc ‖ SHA256(ek) ‖ SHA256(ct))`, `ikm = K ‖ ss`,
   `key_c2s = HKDF-SHA256(ikm, salt, "TVWP2 c2s")`, `key_s2c = HKDF-SHA256(ikm, salt, "TVWP2 s2c")`.

## Защита от перегрузки (агент)

- рукопожатие должно уложиться в 5 с;
- до входа: кадр ≤ 4096 байт, флаги запрещены, не больше 2 незавершённых входов с одного адреса и 4 всего;
- не больше 8 соединений одновременно;
- подключения из сети телевизора (`10.42.0.0/24`) отклоняются, порт закрыт в nftables.

## Типы сообщений

| code | имя | направление | payload |
|---|---|---|---|
| 0x01 | HELLO | S→C | `{server, ver, kem, nonce}` |
| 0x02 | AUTH | C→S | `{client, ver, nonce, kem_pub, mac}` |
| 0x03 | AUTH_OK | S→C | `{ct, proof}` |
| 0x04 | AUTH_FAIL | S→C | `{reason}` |
| 0x05 | ACK | S→C | `{ref, ok, msg, ...}` (ref = seq запроса) |
| 0x06 | ERROR | S→C | `{ref, code, msg}` |
| 0x10 | SUBSCRIBE | C→S | `{backlog: N}` — прислать N последних событий и дальше в реальном времени |
| 0x11 | EVENT | S→C | одно событие (см. ниже) |
| 0x12 | EVENT_BATCH | S→C | `{events: [...]}` |
| 0x13 | UNSUBSCRIBE | C→S | `{}` |
| 0x20 | LISTS_GET | C→S | `{}` |
| 0x21 | LISTS | S→C | `{block: [...], direct: [...], vpn: [...]}` — рассылается всем при изменении |
| 0x22 | LIST_EDIT | C→S | `{list: "block"\|"direct"\|"vpn", op: "add"\|"remove", items: ["full:host", "domain:x.com"]}` |
| 0x30 | STATUS_GET | C→S | `{}` |
| 0x31 | STATUS | S→C | `{uptime, agent_uptime, xray, temp, to_tv, from_tv, profile, profile_updated, outbounds, balancer, lists, events}` |
| 0x40 | CONFIG_PUSH | C→S | `{remarks, config}` — применить готовый конфиг Xray (устаревшее; обычно подписку качает сам Pi через relay) |
| 0x50 | SERVERS_GET | C→S | `{}` |
| 0x51 | SERVERS | S→C | `{servers: [{tag, protocol, address, port, network, security, sni, latency}], selected, auto, profile, testing}` — рассылается всем при изменении |
| 0x52 | SERVER_SELECT | C→S | `{tag}` — закрепить сервер; `""` = автовыбор. Сохраняется и переживает перезапуск Xray |
| 0x53 | SERVER_TEST | C→S | `{tags: [...]}` — проверить задержку (пустой список = все) |
| 0x54 | SERVER_TEST_RESULT | S→C | `{tag, ms, error, done}` — по одному на сервер, в конце `done: true` |
| 0x60 | SUB_GET | C→S | `{}` |
| 0x61 | SUB_PROFILES | S→C | `{profiles: [{remarks, protocols, servers}], selected, fetched_at, userinfo, error, busy, relay}` — рассылается всем при изменении |
| 0x62 | SUB_REFRESH | C→S | `{}` — Pi скачивает подписку через свой сервер-ретранслятор и применяет выбранный профиль |
| 0x63 | SUB_SELECT | C→S | `{remarks}` — применить другой профиль из последней подписки |
| 0x7E | PING | любое | `{t}` |
| 0x7F | PONG | любое | `{t}` |

### Событие (EVENT)

```json
{"id": 3282881749, "ts": 1795700000123, "src": "10.42.0.201", "sport": 33012,
 "ip": "142.251.150.4", "port": 443, "net": "tcp",
 "host": "www.youtube.com", "out": "proxy-14", "kind": "vpn", "rule": "base-6"}
```

`kind`: `vpn` | `direct` | `block`. `rule` — тег сработавшего правила (`u-block`, `ads`, …).

## Подписка через свой сервер (relay)

```
TVWatch.app ──TVWP SUB_REFRESH──▶ Pi ──SSH (ключ с forced command)──▶ свой сервер ──HTTPS + X-HWID──▶ провайдер VPN
```

HWID и адрес подписки хранятся только на сервере (`/etc/tvwatch-relay/config.json`).
Ключ Pi на сервере ограничен в `authorized_keys`: `command="… tvwatch_relay.py --restricted",no-pty,no-port-forwarding,…` —
он умеет только `fetch` и `ping`.

## Правила на Pi

Пользовательские списки превращаются в правила Xray, которые стоят **раньше** всех остальных:

1. `u-block` → blackhole
2. `u-direct` → напрямую, без VPN
3. `u-vpn` → через автовыбор серверов (балансировщик `auto`)
4. дальше — базовые правила из подписки и блокировка рекламы (`ads`)

Изменения применяются на лету через API Xray (`RoutingService`), без перезапуска; если API недоступен — перезапуск Xray.
