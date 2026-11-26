# TVWP/1 — TV Watch Protocol

Протокол между агентом на Raspberry Pi (`tvwatch-agent`) и приложением на Mac (`TVWatch.app`).
Транспорт: TCP, порт **7878** на Pi.

## Кадр

```
 0      2     3      4      5      6          10         14            14+len       14+len+16
 +------+-----+------+------+------+----------+----------+-------------+------------+
 | "TW" | ver | type | flag | rsv  | seq (BE) | len (BE) | payload     | tag (16 B) |
 +------+-----+------+------+------+----------+----------+-------------+------------+
   2 B    1 B   1 B    1 B    1 B     4 B        4 B       len байт      HMAC
```

- `ver` = 1
- `seq` — номер кадра, строго растёт в каждом направлении (защита от повтора).
- `len` ≤ 8 MiB. `payload` — JSON в UTF-8.
- `flag` бит 0 = payload сжат zlib (используется для больших кадров: конфиг, история).
- `tag` — первые 16 байт `HMAC-SHA256(session_key, header ‖ payload)`.
  До завершения рукопожатия `tag` = 16 нулевых байт.

## Рукопожатие

Общий секрет `K` (32 байта) хранится на Pi в `/usr/local/etc/tvwatch/key` и в настройках приложения.

1. Сервер → `HELLO {server, ver, nonce: hex(16 B ns)}`
2. Клиент → `AUTH {client, ver, nonce: hex(16 B nc), mac: hex(HMAC(K, "TVWP1-client|" ‖ ns ‖ nc))}`
3. Сервер проверяет `mac` и отвечает
   `AUTH_OK {proof: hex(HMAC(K, "TVWP1-server|" ‖ nc ‖ ns))}` — клиент проверяет, что говорит с настоящим агентом.
   Иначе `AUTH_FAIL` и разрыв.
4. Обе стороны вычисляют `session_key = HMAC(K, "TVWP1-session|" ‖ ns ‖ nc)`; с этого момента все кадры подписаны.

Шифрования нет (только целостность и подлинность) — протокол рассчитан на домашнюю сеть.

## Типы сообщений

| code | имя | направление | payload |
|---|---|---|---|
| 0x01 | HELLO | S→C | `{server, ver, nonce}` |
| 0x02 | AUTH | C→S | `{client, ver, nonce, mac}` |
| 0x03 | AUTH_OK | S→C | `{proof}` |
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
