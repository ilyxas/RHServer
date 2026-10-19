# 002. Tailscale LocalAPI whois: путь, формат, права

- Пункт SPEC: §3.3 (сверка отправителя), PLAN этап 1 [проверить]
- Дата: 2026-10-19
- Источник: исходники Tailscale v1.104.1 (`ipn/localapi/localapi.go`, `client/tailscale/apitype/apitype.go`, `tailcfg/tailcfg.go`, `paths/paths.go`, `safesocket/safesocket_darwin.go`, `safesocket/unixsocket.go`, `ipn/ipnserver/server.go`, `cmd/tailscale/cli/whois.go`), https://tailscale.com/kb/1080/cli, https://tailscale.com/kb/1065/macos-variants

## Вывод

- Запрос: `GET /localapi/v0/whois?addr=IP[:port]`, заголовок `Host: local-tailscaled.sock`, без `Referer`/`Origin`. 404 — адрес не из tailnet, 403 — нет прав на чтение.
- Ответ: `{Node, UserProfile, CapMap}`; `Node.StableID` — стабильный id узла, `Node.Name` — FQDN с точкой в конце.
- Как достучаться, по вариантам:
  - `tailscaled`: Unix-сокет `/var/run/tailscaled.socket` (0666), whois доступен любому локальному пользователю, включая будущего `_rhcore`.
  - Standalone: TCP 127.0.0.1, порт — цель симлинка `/Library/Tailscale/ipnport`, токен в `/Library/Tailscale/sameuserproof-<port>` (root:admin, 0640), Basic-Auth с пустым логином. Читают root и группа admin.
  - App Store: порт и токен находятся через `lsof` процесса `IPNExtension` вошедшего пользователя; другим пользователям недоступно.
- CLI `tailscale whois --json <ip>` сам выбирает нужный способ для любого варианта.

## На Mac Ильи (2026-10-19)

`defaults read /Applications/Tailscale.app/Contents/Info.plist CFBundleIdentifier` → `io.tailscale.ipn.macsys` (Standalone), `which tailscale` → `/usr/local/bin/tailscale`. Ядро находит CLI через PATH без ключа `tailscale` в конфиге.

## Следствие для кода

- `rh_core.peers.TailscaleWhois` вызывает `tailscale whois --json <ip>` (путь — ключ конфига `tailscale`, иначе `tailscale` из PATH, иначе `/Applications/Tailscale.app/Contents/MacOS/Tailscale`) и берёт `Node.StableID`; ответ кэшируется на 60 секунд по IP. Своя реализация трёх способов доступа к LocalAPI не нужна: CLI — официальный клиент того же LocalAPI.
- При pairing ядро запоминает узел; каждый подписанный запрос с другого узла или с неизвестного (whois не ответил) — отказ `peer_mismatch` и запись в журнал. Pairing без определённого узла тоже отклоняется.
- Этапы 1–6 ядро работает под пользователем Ильи — whois работает при любом варианте.
- **Вопрос к этапу 7 (не к этапу 1):** под `_rhcore` whois доступен только с open-source `tailscaled`. У Ильи Standalone: токен LocalAPI читают только root и группа admin, так что `_rhcore` сверять отправителя не сможет. Варианты (перейти на `tailscaled`, отдельный помощник с правами чтения токена и т. п.) решу с Ильёй перед этапом 7.
