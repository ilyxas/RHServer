# 007. The owner's message interrupts: one Escape before the pointer

- Пункт SPEC: §6.2 («новое сообщение прерывает ход агента»; «агент ждёт approval → новое сообщение снимает ожидание»), задание friend slice 3
- Дата: 2026-10-24
- Источник: https://code.claude.com/docs/en/interactive-mode, разделы «Queue messages», «Esc» (прочитано 2026-10-24); подтверждения из отчётов пользователей (issue 36326, 69124 в репозитории claude-code)

## Вопрос

Прерывает ли текст, напечатанный в tmux во время хода, работу агента (аксиома владельца), или ставится в очередь? Как прервать, не потеряв сделанное?

## Вывод (цитаты из документации)

- «Type a message and press `Enter` while Claude is working. Claude Code queues the message instead of interrupting the turn.» Очередь отдаётся модели после текущих tool calls в том же ходе или по окончании хода.
- `Esc`: «Interrupt Claude, or close a dialog | Stop the current response or tool call mid-turn so you can redirect. Claude keeps the work done so far. If you have messages queued, Claude Code sends them next. … On a permission prompt, `Esc` declines the action».
- `Esc`+`Esc` на пустой строке «opens the rewind menu».

## Следствие для кода

1. Мост до slice 3 не прерывал: `send-keys -l` + `Enter` ставили сообщение в очередь, и Stop того хода ответил бы на два сообщения сразу.
2. Мост шлёт ровно один `Escape`, пауза 0.3 с, затем указатель и `Enter` (`[bridge] interrupt = true`, по умолчанию). Два Escape недопустимы (меню rewind).
3. Побочный эффект по SPEC §6.2: ожидание разрешения в собственном диалоге Claude Code отклоняется.
4. Проверить живьём: паузы хватает на любой машине владельца; Escape на idle-сессии ничего не ломает (очищает черновик строки, что только помогает указателю прийти отдельной строкой).
