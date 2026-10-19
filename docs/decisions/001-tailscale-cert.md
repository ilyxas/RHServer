# 001. `tailscale cert`: выдача, продление, файлы, sudo, ATS

- Пункт SPEC: §3.3 (HTTPS на MagicDNS-имени), PLAN этап 1 [проверить]
- Дата: 2026-10-19
- Источник: https://tailscale.com/kb/1153/enabling-https, https://tailscale.com/kb/1080/cli, https://tailscale.com/kb/1065/macos-variants, исходники Tailscale v1.104.1 (`cmd/tailscale/cli/cert.go`, `ipn/localapi/cert.go`, `ipn/ipnserver/server.go`, `feature/acme/cert.go`, `feature/acme/refresh.go`), https://letsencrypt.org/docs/certificate-compatibility/

## Вывод

- Нужно: MagicDNS и «HTTPS Certificates» на странице DNS админки Tailscale. Имя машины попадает в публичные логи Certificate Transparency. Проверка — DNS-01 на `*.ts.net`, ключ не покидает Mac.
- Команда: `tailscale cert --cert-file <путь>.crt --key-file <путь>.key <имя>.<tailnet>.ts.net`. Без флагов пишет `ИМЯ.crt` / `ИМЯ.key` в текущий каталог; сертификат 0644, ключ 0600.
- Варианты Tailscale на macOS отличаются:
  - App Store (`io.tailscale.ipn.macos`): CLI в песочнице, файлы оказываются в `~/Library/Containers/io.tailscale.ipn.macos/Data/…` (CLI предупреждает об этом). Работает только под вошедшим пользователем.
  - Standalone (`io.tailscale.ipn.macsys`): доступ через токен LocalAPI `/Library/Tailscale/sameuserproof-*` (root:admin, 0640) — у пользователя-администратора есть.
  - open-source `tailscaled`: выдаёт сертификат root, оператору или UID из `TS_PERMIT_CERT_UID`; остальным 403.
  - Нужен ли sudo на App Store / Standalone под пользователем Ильи — по коду не подтверждено; проверяется первым выпуском сертификата на Mac.
- На Mac Ильи (2026-10-19): Standalone (`io.tailscale.ipn.macsys`), CLI `/usr/local/bin/tailscale`, не в песочнице — файлы пишутся по путям из `--cert-file`/`--key-file`.
- Срок — 90 дней. Файлы на диске продлевает только повторный `tailscale cert` (он перезаписывает их лишь при изменении); частые запросы упираются в лимиты Let's Encrypt. Фоновое обновление в демоне работает только при `tailscale serve` с HTTPS.
- iOS доверяет ISRG Root X1 с iOS 10, исключение ATS не нужно. Что `*.ts.net`-сертификат проходит все правила ATS — вывод, проверим первым настоящим запросом с iPhone.

## Следствие для кода

- `rh-core` не вызывает `tailscale cert` сам: пути к файлам — в конфиге (`tls_cert`, `tls_key`), рабочий режим без них не стартует. Uvicorn читает сертификат при старте, значит после продления ядро перезапускается.
- Этап 1: Илья выпускает сертификат вручную по инструкции из PR. Этап 7: launchd-задача раз в сутки `tailscale cert` + перезапуск ядра при изменении файла; способ доступа `_rhcore` к сертификату зависит от варианта Tailscale (см. 002).
