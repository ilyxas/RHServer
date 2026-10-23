# 004. PreToolUse hook as a gate: timeout, failure, `onFailure: "block"`

- Пункт SPEC: §5.3 («Таймаута нет. Вызов ждёт столько, сколько нужно»), задание friend slice 2 (гейт PreToolUse для сессии Friend)
- Дата: 2026-10-23
- Источник: https://code.claude.com/docs/en/hooks, разделы «Block the action when a hook fails», «Timeouts», «Common fields» (прочитано 2026-10-23)

## Вопрос

Может ли хук PreToolUse быть гейтом: действие не выполняется, пока хук не разрешил? Что происходит при таймауте, падении или отсутствии скрипта хука?

## Вывод (цитаты из документации)

- Таймаут: поле `timeout`, секунды; для command-хуков по умолчанию **600 с** (на `UserPromptSubmit` — 30 с). На `async: true` таймаут не действует.
- «On `PreToolUse`, a timed-out `command`, `http`, or `mcp_tool` hook doesn't block the tool call, except for hooks whose failure blocks the action. The call continues through the normal permission flow, so don't count on a stalled hook to act as a gate.»
- «On most events, when a hook fails or times out, Claude Code still carries out the action. A policy hook with a wrong path or a crashing script then lets everything through. To block the action instead, set `"onFailure": "block"` on a `command` or `http` hook. Requires Claude Code v2.1.295 or later.»
- Что считается отказом при `onFailure`: хук не запустился (нет скрипта или интерпретатора); код выхода **кроме 0 и 2** (даже если напечатан JSON с `permissionDecision: "allow"`); таймаут; нечитаемый или не прошедший схему JSON. «With "block" set, a failure does what exit code 2 does on that event … a `PreToolUse` failure blocks the tool call».
- Код выхода 2 блокирует вызов всегда, stderr — причина для модели. JSON `permissionDecision: deny` с кодом 0 — тоже блок.
- Не действует на `Stop`, `SubagentStop`, `TaskCompleted`, `TeammateIdle` и на фоновые хуки (`async`).

## Следствие для кода

1. Гейт `rh-friend-gate` **не ждёт решения владельца**. Он только ищет уже существующее действительное `allow` для точного вызова и тратит его через admin-сокет ядра. Ожидание «без таймаута» из SPEC §5.3 хуком не реализуется: по истечении `timeout` вызов пошёл бы дальше, а задание требует fail closed. Вопрос владельцу задаёт отдельная команда `rh-friend-ask`; действие Friend запускает после ответа.
2. Запись хука обязана содержать `"onFailure": "block"` и явный `timeout` (30 с достаточно: гейт читает файлы и один раз ходит в сокет). Без `onFailure` падение, отсутствие venv или таймаут пропускают вызов.
3. Блок — `exit 2` с причиной на stderr (сильнее JSON: действует даже при повреждённом выводе). Разрешение — `exit 0` и JSON с `additionalContext` (метка решения для модели); `permissionDecision: allow` гейт не выдаёт: он нижняя граница, не замена разрешений Claude Code.
4. Любая ошибка внутри гейта (конфиг, падение, ядро не отвечает) — `exit 2`. Непрошедший тест этого пути — `test_hook_process_end_to_end`, `test_gate_crash_blocks`, `core-unreachable` в векторах.
5. Требуемая версия Claude Code: ≥ 2.1.295 (на Mac владельца 23.10 — 2.1.295 у Claude.app; версию CLI в tmux Friend проверить при установке: `claude --version`).

## Что не проверено

- Поведение `onFailure` на самой машине владельца проверяется приёмкой (шаг «гейт без решения → блок» с намеренно сломанным путём к venv). Документация не говорит, применяются ли правки hooks в настройках к уже идущей сессии; на приёмке сессия Friend перезапускается после установки хука.
