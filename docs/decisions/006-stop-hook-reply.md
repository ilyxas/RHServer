# 006. Stop hook as the agent's reply to the phone

- Пункт SPEC: §4.4 (сервер шлёт ответ агента), §6.2 (каждый ответ агента записан), задание friend slice 3 («агент отвечает в Клиент»)
- Дата: 2026-10-24
- Источник: https://code.claude.com/docs/en/hooks, разделы «Stop», «Common fields», «UserPromptSubmit» (прочитано 2026-10-24)

## Вопрос

Как хук узнаёт финальный ответ агента, чтобы отправить его на телефон, и когда он срабатывает?

## Вывод (цитаты из документации)

- «In addition to the common input fields, Stop hooks receive `stop_hook_active`, `last_assistant_message`, `background_tasks`, and `session_crons`.»
- «The `last_assistant_message` field contains the text content of Claude's final response, so hooks can access it without parsing the transcript file. … the transcript file isn't guaranteed to include the final message at Stop time on all versions.»
- Stop «runs when the main Claude Code agent has finished responding. Does not run if the stoppage occurred due to a user interrupt.»
- Общие поля: `session_id`, `prompt_id` («UUID for the prompt being processed»), `transcript_path`, `cwd`, `hook_event_name`.
- `UserPromptSubmit` `additionalContext`: «Claude Code wraps the string in a system reminder and inserts it into the conversation at the point where the hook fired.»

## Следствие для кода

1. `rh-friend-reply` — Stop-хук: берёт `last_assistant_message` как есть (до 8000 символов контракта), транскрипт не читает.
2. Кому отвечать, хук узнаёт из заметки верификатора `state/rh_current.json` (id, kind, prompt_id); ход, который владелец не вызывал (заметки нет), ответа не шлёт.
3. Прерванный ход Stop не даёт, поэтому ядро само закрывает предыдущее сообщение как `superseded`, когда приходит новое.
4. Хук никогда не блокирует и ничего не печатает в stdout; без `onFailure`, `timeout` 10 с. Недоступное ядро — ответ откладывается в `state/rh_pending.jsonl`.
5. Не проверено по документации, проверяется живьём: совпадает ли `prompt_id` в Stop и в UserPromptSubmit одного хода (до проверки `[channel] match_prompt_id = false`); порядок Stop(ход N) / UserPromptSubmit(ход N+1); что Stop срабатывает после хода, закончившегося `rh-friend-ask`.
