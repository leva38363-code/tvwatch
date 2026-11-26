# TV Watch

Raspberry Pi как «умный роутер» для телевизора: весь трафик ТВ идёт через VPN (Xray),
реклама и слежка Smart TV режутся, а приложение для macOS показывает **каждый запрос телевизора в реальном времени**
и позволяет **правой кнопкой мыши** блокировать домены, пускать их мимо VPN или наоборот только через VPN.

*Raspberry Pi as a transparent VPN gateway for a smart TV, with live request monitoring, per-domain rules
and ad/telemetry blocking, controlled from a native macOS app over a small post-quantum custom protocol (TVWP/2: ML-KEM-1024 + PSK, ChaCha20-Poly1305).*

```
                 Wi-Fi                     Ethernet
 интернет ◀──── Raspberry Pi ◀──────────── телевизор
                  │  Xray: VPN + блокировка рекламы + твои правила
                  │  tvwatch-agent  ◀── TVWP/2 (TCP 7878) ──  TV Watch.app (macOS)
                  └── SSH ──▶ твой сервер (relay) ──▶ провайдер VPN (подписка с HWID)
```

## Возможности

- **Прозрачный VPN для телевизора.** Телевизор подключается кабелем к Pi и ничего не настраивает. Внутри — Xray с TPROXY, маршрутизация из твоей подписки (российские сайты напрямую, остальное через VPN).
- **Поток запросов** в реальном времени: время, домен, IP, маршрут (VPN / напрямую / блок), сервер, сработавшее правило.
- **Правая кнопка мыши** по домену: заблокировать, всегда напрямую, всегда через VPN — один адрес или весь домен; скрыть из ленты; показать только его. Правила применяются **на лету**, без перезапуска VPN.
- **Блокировка рекламы и слежки**: база `category-ads-all` + реклама и ACR Samsung Smart TV (без поломки обновлений и аккаунта).
- **Выбор сервера** вручную или автовыбор, проверка задержки каждого сервера (не мешает телевизору).
- **Подписка через свой сервер**: Pi по SSH просит твой сервер скачать подписку с HWID. HWID и ссылка подписки живут только на сервере; ключ Pi там может выполнить ровно одну команду.
- **Полноэкранный режим**: панель трафика — сколько ТВ получил и отправил, график скорости, частые сайты, серверы.
- **Свой протокол TVWP/2, постквантовый**: обмен ключами ML-KEM-1024 + общий ключ (гибрид), шифрование ChaCha20-Poly1305, прямая секретность, защита от повтора и перегрузки. См. [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Что нужно

- Raspberry Pi 4/5 с Raspberry Pi OS (64-bit), подключённый к домашнему Wi-Fi, и кабель Ethernet до телевизора.
- Своя VPN-подписка в формате JSON-конфигов Xray (как у клиентов Happ / v2rayN).
- Свой сервер с SSH (любой VPS) — для ретранслятора подписки. Можно и без него: тогда подписку на Pi придётся класть вручную.
- Mac с macOS 26+ (нужен CryptoKit с ML-KEM) и Xcode Command Line Tools (Swift 6) — собрать приложение.

## Установка

### 1. Raspberry Pi

```bash
git clone https://github.com/<you>/tvwatch.git && cd tvwatch
sudo bash pi/setup_pi.sh --relay tvwatch-relay@your-server.example.com
```

Скрипт поставит Xray (с проверкой контрольной суммы), настроит раздачу интернета на `eth0`, перенаправление трафика ТВ в Xray,
агента `tvwatch-agent` и выведет **публичный ключ Pi** для сервера.

### 2. Сервер-ретранслятор подписки

```bash
scp relay/tvwatch_relay.py relay/install_relay.sh root@your-server:/tmp/
ssh root@your-server 'bash /tmp/install_relay.sh "ssh-ed25519 AAAA... tvwatch-pi"'
ssh -t root@your-server 'sudo -u tvwatch-relay python3 /opt/tvwatch-relay/tvwatch_relay.py set-url'
ssh -t root@your-server 'sudo -u tvwatch-relay python3 /opt/tvwatch-relay/tvwatch_relay.py set-hwid'
```

Создаётся отдельный пользователь `tvwatch-relay`; ключ Pi в его `authorized_keys` ограничен
`command=…--restricted,no-pty,no-port-forwarding` — только `fetch` и `ping`.

### 3. Приложение на Mac

```bash
bash build_app.sh          # соберёт TVWatch.app
open TVWatch.app
```

В «Подписка и серверы» укажи адрес Pi и ключ (`sudo cat /usr/local/etc/tvwatch/key` на Pi), нажми «Обновить сейчас».

### 4. Телевизор

Соедини ТВ и Pi кабелем, в настройках сети ТВ выбери «Кабель», всё автоматически.


## Свой VPN-сервер (`vpn-server/`)

Xray на своём VPS за пределами РФ, несколько протоколов, у каждого человека свой ключ:

| Порт | Протокол |
|---|---|
| 443/tcp | VLESS + Vision + REALITY (маскировка под www.samsung.com) |
| 443/udp | Hysteria 2 |
| 2053 | VLESS + XHTTP + REALITY + **ML-KEM-768** (постквантовое шифрование VLESS) |
| 2083 | Trojan + REALITY |
| 2087 | VLESS + Vision + REALITY (маскировка под max.ru) |
| 2096 | VLESS + XHTTP + REALITY + ML-KEM-768 (маскировка под ozon.ru) |

REALITY с подписью **ML-DSA-65** и обменом ключами X25519MLKEM768 (отпечаток chrome); через VPN закрыт доступ
к внутренним службам сервера, торренты и почтовые порты; журнал посещений не ведётся.

```bash
scp vpn-server/* root@server:/tmp/vpn/ && ssh root@server 'bash /tmp/vpn/install.sh <публичный-IP> me'
ssh root@server 'vpnctl add friend'     # новый человек → ссылки
ssh root@server 'vpnctl links friend'   # ссылки для Happ / v2RayTun / Hiddify
ssh root@server 'vpnctl off friend'     # отключить
```

Порт 443 обычно занят веб-сервером — либо выдели VPN отдельный IP и перенаправь его 443 на внутренние порты
(`2443/tcp`, `8443/udp`), либо поменяй `PUBLIC` в `vpnctl.py`. Не забудь открыть порты в фаерволе.

## Важно

- **Используй только свою подписку** и в рамках правил своего VPN-провайдера. Проект не раздаёт VPN другим людям.
- Протокол TVWP/2 шифрует трафик, но рассчитан на домашнюю сеть: не открывай порт 7878 в интернет.
- Проверка безопасности протокола: `sudo python3 agent/tvwp_security_test.py <ip-pi>` (на Pi).
- HTTPS телевизора не расшифровывается: видны только домены (SNI), IP и объём трафика.

## Структура

| Папка | Что внутри |
|---|---|
| `agent/` | `tvwatch_agent.py` — агент на Pi (Python 3.11+, `python3-cryptography`, OpenSSL 3.5+), `tvwp_crypto.py`, установщик, функциональные тесты и тест безопасности |
| `pi/` | systemd-службы, правила nftables (TPROXY), базовый конфиг Xray, `setup_pi.sh` |
| `relay/` | ретранслятор подписки для своего сервера |
| `vpn-server/` | свой VPN-сервер: установщик и `vpnctl` (пользователи, ссылки) |
| `app/` | приложение для macOS на SwiftUI (Swift Package) |
| `docs/PROTOCOL.md` | описание протокола TVWP/2 |

## Лицензия

MIT
