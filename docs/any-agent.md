# Any agent on the Friend mechanism: what is bound to the name "Friend" and what changes

Статус: **описание для утверждения владельцем, без кода.** После утверждения — разработка
отдельными PR (контракт → ядро → хуки/мост → iOS), каждый со своими тестами.

Задание владельца (23.10.2026, iPhone ✔ 17:37): механизм «подписанное сообщение с телефона →
сессия агента» и «вопрос агента → подписанное решение → гейт» (slice 1 и 2, PR #14/#15,
RHClient #10/#12) сегодня работает только для одной сессии с именем Friend. Нужно, чтобы на него
можно было посадить любого агента — и не одного, а нескольких одновременно, каждый со своим
именем, каталогом, tmux-сессией, входящими и журналами.

Что НЕ меняется: подпись на iPhone (Secure Enclave, Face ID для allow), уровни ключей
(deny = normal, allow = critical), окно решения 120 с, одноразовое списание решения ядром,
точное совпадение канонического текста действия, список устройств, формат указателя
`⟦rh:<id>⟧`, «ремень, не песочница» (docs/friend-gate.md).

Инвентарь ниже собран по `grep -rni friend` в RHServer и RHClient (23.10, main c72e7ff /
c89f925). Пометки: **[P]** видно в протоколе (контракт, подписанное тело, op в подписи, путь);
**[I]** внутреннее имя; **[S]** предполагает ровно одного получателя.

## 1. Главное решение: агент = идентификатор, а не имя файла

Вводится понятие **agent id** — строка из раздела «Команда» (тот же id, что в `agents.status`:
`Friend`, `RemoteHands`, `Claude-Render`, …). Всё, что сейчас значит «Friend», становится
«агент с id X». `Friend` остаётся первым агентом и значением по умолчанию, так что текущая
установка продолжает работать без правок конфигурации.

Правила для id: `[A-Za-z0-9_-]{1,32}`, уникален в команде, регистр важен; используется как
ключ в таблицах, как сегмент пути в файловой системе и в URL, поэтому без пробелов и Unicode.
Отображаемое имя (title) берётся из раздела «Команда», id — не для показа.

## 2. Контракт (`contracts/`, зеркало в RHClient) — [P]

Сейчас: `openapi.yaml` 0.4.0, пути `/v1/friend`, `/v1/friend/questions`, `/v1/friend/decide`,
op `friend.send` / `friend.questions` / `friend.decide` (op входит в подписанный материал),
тело send и decide: `to: const "Friend"` [P][S]; схемы `FriendQuestion`, `FriendDecision`;
`agents.status` описан как чтение `~/Friend/CLAUDE.md`.

Меняется (bump **0.4.0 → 0.5.0**, запись в CHANGELOG, обновление MANIFEST):

| Было | Станет | Замечание |
|---|---|---|
| `to: const "Friend"` | `to: string` = agent id (pattern выше) | единственное обязательное изменение подписанного тела; подпись уже покрывает `to`, значит подмена адресата невозможна без ключа телефона |
| `/v1/friend` (`friend.send`) | `/v1/agents/{id}/messages` (op `agent.send`) | op остаётся константой, адресат — в `to`; `{id}` в пути обязан совпадать с `to`, иначе `bad_request` |
| `/v1/friend/questions` (`friend.questions`) | `/v1/agents/questions` (op `agent.questions`), ответ с полем `agent` в каждом вопросе; фильтр `?agent=` необязателен | телефон хочет один список по всем агентам |
| `/v1/friend/decide` (`friend.decide`) | `/v1/agents/decide` (op `agent.decide`); тело `{to, id, question_sha256, action, decision}` — `to` = agent id вопроса | `question_sha256` считается по тому же JCS-объекту, в который добавляется поле `agent` |
| `FriendQuestion`, `FriendDecision` | `AgentQuestion` (+ `agent`, + `title` для показа), `AgentDecision` | |
| vectors `friend.json`, `friend_decide.json` | `agent_send.json`, `agent_decide.json`: те же кейсы + кейсы «`to` ≠ `{id}` пути», «`to` неизвестен ядру» (`unknown_agent`), «два агента, вопросы с одинаковым action» | генераторы `scripts/vectors_*.py` переименовать |
| описание `agents.status` «из ~/Friend/CLAUDE.md» | «из team_file конфига ядра» | текст, не схема |

Альтернатива (не рекомендую, но дешевле): оставить пути `/v1/friend*` и op `friend.*`, менять
только `to`. Минус: имя `friend` навсегда в протоколе и в подписях; при добавлении второго
агента всё равно нужен bump. Решение владельца — п. 9.1.

Совместимость: ядро 0.5.0 принимает только `0.5.0`; старое приложение получит `bad_request`
на `to` — приложение синкает контракты на SHA мержа, как делалось для #11.

## 3. Ядро (`src/rh_core`, `src/rh_common`)

Сейчас: `rh_common/friend.py` — `RECIPIENT = "Friend"` [P][S], `OP_*`, типы `FriendMessage`,
`FriendDecision`, `Question`; `app.py` — три маршрута, один spool-inbox [S], один экспорт
подписанного списка устройств «для verifier Friend» [S], права 644 «для пользователя сессии
Friend»; `admin.py` — `friend.ask`, `friend.questions`, `friend.question.withdraw`,
`friend.decision.use`, один admin-сокет, в командах нет агента [S]; `store.py` — таблицы
`friend_questions`, `friend_decisions` без колонки агента [S]; `config.py` — секция `[friend]`
(`inbox_dir`, `devices_file`, `decide_window_s`), `TEAM_FILE = ~/Friend/CLAUDE.md` [S];
`data.py` — строка Home `rh.questions` с подзаголовком «Friend asks · <tool>»; `logfeed.py` —
заголовки Log с литералом Friend; `agents.py` — команда из `~/Friend/CLAUDE.md`.

Меняется:

- `rh_common/friend.py` → `rh_common/agent_channel.py`: `RECIPIENT` убирается, `parse_body`
  проверяет `to` по pattern и по **реестру агентов ядра** (ниже); типы
  `AgentMessage`, `AgentDecision`, `Question(agent=…)`.
- **Реестр агентов** в конфиге ядра — новая секция вместо `[friend]`:

  ```toml
  [agents]
  team_file = "~/Friend/CLAUDE.md"      # уже есть (agents.status)
  devices_file = ".../devices.json"     # общий для всех агентов, один список устройств
  decide_window_s = 120                 # общий по умолчанию

  [[agents.channel]]                    # один блок = один агент, посаженный на механизм
  id = "Friend"
  inbox_dir = ".../inbox/Friend"        # по умолчанию data_dir/inbox/<id>
  project_dir = "~/Friend"              # cwd сессии; нужен хукам и agents.status
  ```

  Только агенты с `[[agents.channel]]` принимают сообщения и задают вопросы; остальные
  члены команды видны в `agents.status`, но `to` на них → `unknown_agent`. Это и есть
  ответ на «как посадить любого агента»: добавить блок и сгенерировать его конфиг (п. 4).
- Spool: `inbox/<id>/` на агента; экспорт списка устройств — один файл, читаемый всеми.
- `store.py`: колонка `agent TEXT NOT NULL` в обеих таблицах (переименовать в
  `agent_questions`, `agent_decisions`); индекс `(agent, action_sha256, ts)`; правило
  «новейшее решение по действию» и аннулирование (`voided`) считаются **внутри одного
  агента**: allow для Friend не действует на тот же action у другого агента.
- `admin.py`: у всех команд обязательное поле `agent`; переименование `friend.ask` →
  `agent.ask`, `friend.questions` → `agent.questions` (без `agent` — все), `agent.question.withdraw`,
  `agent.decision.use`. Admin-сокет один; **ядро проверяет, что `agent` в команде совпадает с
  тем, от чьего имени она пришла** — пока под одним пользователем это самоотчёт (ремень), с
  этапа 7 — по UID/peer credentials сокета (см. п. 8).
- Журнал: имена событий `agent.message`, `agent.question`, `agent.question.withdrawn`,
  `agent.decision`, `agent.decision.{used,refused,voided}`, `agent.question.refused`; в каждом
  событии поле `agent`. `logfeed.py`: заголовки по шаблону с title агента — «Message to
  {title} from …», «{title} asks for a decision», «Allowed {title}'s action (iPhone)», «{title}
  used a decision», и т.д.; фильтр Approvals — по префиксам `agent.question*`/`agent.decision*`.
- `data.py`: `rh.questions` — строки по всем агентам, подзаголовок «{title} asks · <tool>».
- `agents.py`/`agent_rules.py`: `project_dir` из `[[agents.channel]]` используется как `cwd`
  правила по умолчанию (сейчас cwd задаётся отдельно в `[[agents.rule]]`; дублирование убрать).

## 4. Сторона агента: конфиг, хуки, мост, ask (`src/rh_friend`, `src/rh_cli`)

Сейчас: пакет `rh_friend`, entry points `rh-friend-verify`, `rh-friend-bridge`,
`rh-friend-gate`, `rh-friend-ask`; `FriendConfig` с `DEFAULT_PATH …/friend.toml` [S],
`project_dir=~/Friend` [S], `seen_file`, `rejected_log`, `[bridge] target="friend"` [S],
`[gate] log`, `ask`; `rhcore friend-config` печатает friend.toml с pinned ключом ядра;
`bridge.py` опрашивает один inbox и печатает `⟦rh:<id>⟧` в один tmux-target [S];
`verify.py` и `gate.py` работают только при `CLAUDE_PROJECT_DIR == project_dir` [S].

Меняется:

- Пакет `rh_agent_side` (или оставить `rh_friend` как имя пакета — п. 9.2), entry points
  `rh-agent-verify`, `rh-agent-gate`, `rh-agent-ask`, `rh-agent-bridge`.
- **Один конфиг на агента**: `…/RemoteHands/agents/<id>.toml` (managed:
  `/usr/local/etc/remotehands/agents/<id>.toml`), секции как сейчас плюс `id`:

  ```toml
  id = "Friend"
  project_dir = "~/Friend"
  inbox_dir = ".../inbox/Friend"
  devices_file = ".../devices.json"
  seen_file = "~/Friend/state/rh_seen.jsonl"
  rejected_log = "~/Friend/log/rh_rejected.jsonl"
  [bridge]  tmux = "...", target = "friend", state_file = "~/Friend/state/rh_bridge.json"
  [gate]    admin_socket = "...", decide_window_s = 120, log = "~/Friend/log/rh_gate.jsonl", ask = "..."
  [[gate.protected]] …
  ```

  Генерация: `rhcore agent-config --id X --project ~/X --target x --owner-names '…'`
  (бывший `friend-config`); все пути по умолчанию выводятся из `--project`.
- Хуки в settings.json проекта агента получают `--agent X --config …/agents/X.toml`;
  проверка `CLAUDE_PROJECT_DIR == project_dir` остаётся (это и есть привязка хука к агенту).
  Хук, поставленный в проект другого агента с чужим конфигом, завершается сразу (как сейчас
  для других проектов).
- `verify`: метка `[RH ✔ owner · iPhone · HH:MM:SS · → X]`; конверт с `to ≠ id` конфига —
  отказ `wrong_recipient` в rejected log (сейчас такого случая нет, т.к. `to` константа).
- `gate`: `agent.decision.use` с полем `agent = id`; всё остальное без изменений.
- `ask`: `--agent` берётся из конфига; вопрос уходит с `agent = id`.
- **Мост**: один процесс `rh-agent-bridge --config-dir …/agents/` обслуживает все конфиги
  (inbox → tmux target каждого); один LaunchAgent `com.ilya.rh.bridge` вместо N. Состояние —
  по агенту (`state_file` из его конфига). Альтернатива — мост на агента (п. 9.3).
- Защищённые правила: набор по умолчанию общий (`default_protected(owner_names)`), у каждого
  агента свой файл, поэтому можно сужать/расширять по агенту. Правило о записи в CGC
  (что хозяин что-то разрешил) сегодня подставляет только `{owner}`; в шаблон добавить `{agent}`.
- Автозапуск сессии (`bin/friend_autostart.sh`, tmux-сессия `friend`) — вне репо, у владельца;
  в docs описать требование: tmux-сессия с именем = `target` конфига.

## 5. Приложение (RHClient)

Сейчас: RHKit `Operations.swift` — `friendSend`/`friendQuestions`/`friendDecide` [P];
`Models.swift` — `FriendSendRequest.to = "Friend"` [P][S], `FriendQuestion`, `FriendDecision`;
`CoreClient` — `sendToFriend`, `friendQuestions`, `decide`; `AppModel` — один список
`questions` [S]; `RootTabView` — вкладка Chat = `FriendView`; `FriendView` — заголовок
«Friend», «Friend asks», «Message to Friend», подсказки, accessibility id `friend.*`;
тесты RHKit `FriendTests`, `FriendDecideTests`, `FakeCore`; UI `FriendSendTests`,
`FriendDecideTests` (через admin-сокет dev-ядра).

Меняется:

- Операции `agentSend(to:)`, `agentQuestions()`, `agentDecide(_:)`; модели `AgentSendRequest(to:)`,
  `AgentQuestion` (+ `agent`, `title`), `AgentDecision`; `CoreClient.send(to:text:)`,
  `questions()`, `decide(_:)`.
- Chat: **выбор адресата** — список агентов из `agents.status`, у которых есть канал (ядро
  отдаёт признак `channel: true` в строке агента; добавить в контракт `agents.status`).
  Заголовок = title агента; при одном агенте с каналом выбор не показывать (текущий вид).
  Вкладка остаётся одна.
- Вопросы: один список по всем агентам (как `agent.questions`), в карточке — title агента
  («{title} asks»), id вопроса и срок; Allow/Deny без изменений. Сейчас карточка не показывает
  id и время — при двух агентах с одинаковым action это нужно (наблюдение из live-теста).
- Строки: «Allow needs Face ID and lets {title} run exactly this call once…», «Signed on this
  iPhone. {title} checks the signature before reading.»
- Accessibility id: `agent.*` (`agent.list`, `agent.picker`, `agent.question.text`,
  `agent.question.agent`, `agent.allow`, `agent.deny`, `agent.decided`, `agent.message`).
- Log/Home: заголовки приходят с сервера — изменений в приложении нет, кроме фикстур тестов.
- Тесты: RHKit — векторы 0.5.0, `FakeCore` с двумя агентами; UI — `AgentSendTests`
  (выбор адресата), `AgentDecideTests` (вопросы двух агентов с одинаковым action: решение
  уходит правильному); `scripts/test.sh` — dev-ядро с фикстурой двух каналов.
  Попутно (из прогона 23.10): список вопросов обновлять не только на appear/pull —
  опрос или событие, иначе второй вопрос не виден; `HomeLogTests` не должен полагаться на то,
  что пара осталась в 5 строках Last Activity.

## 6. Документация и тесты ядра

- `docs/friend-gate.md` → `docs/agent-gate.md` (все пути с `~/Friend` → `<project_dir>`,
  `--target friend` → `--target <session>`); `docs/agents-status.md` — `[[agents.channel]]`;
  `docs/decisions/005-agent-id.md` — это решение после утверждения; PLAN.md — ссылка.
- `tests/test_friend*.py` → `test_agent_channel.py`, `test_agent_decide.py`; обязательные
  новые кейсы: два агента, одинаковый action, allow одного не открывает другого; `to`
  неизвестен; `to ≠ {id}` пути; решение для вопроса другого агента → `bad_request`;
  withdraw чужого вопроса → отказ; `agent.questions` без фильтра отдаёт оба.
- `tests/fixtures/stage2/team.md` — уже содержит несколько агентов; добавить фикстуру
  конфига с двумя каналами для `rhcore dev up`.

## 7. Миграция текущей установки

1. Ядро: при старте, если в конфиге есть старая секция `[friend]` и нет `[[agents.channel]]`,
   ядро считает её каналом `id = "Friend"` и пишет предупреждение (одна версия переходного
   периода); БД — миграция схемы 3 → 4: добавить колонку `agent` со значением `Friend`,
   переименовать таблицы.
2. Файлы: `friend.toml` → `agents/Friend.toml` (команда `rhcore agent-config --from-friend-toml`
   или руками по docs); inbox `friend-inbox/` → `inbox/Friend/`.
3. Хуки в `~/Friend/.claude/settings.json`: новые имена программ и `--agent Friend`
   (правка settings — действие под гейтом; делает владелец или до включения гейта).
4. LaunchAgents: `com.ilya.rh.bridge` на новый entry point и `--config-dir`.
5. Приложение: sync contracts @<SHA мержа>, новая сборка на телефон.
6. Второй агент: блок `[[agents.channel]]`, `rhcore agent-config --id …`, хуки в его
   settings.json, tmux-сессия с именем = target. Для агента не на Claude Code (без хуков)
   доступна только доставка сообщений в tmux; вопросы/гейт — нет (честно записать в docs).

## 8. Что это не решает (чтобы не обещать лишнего)

- Под одним пользователем macOS агент A может прочитать inbox и конфиг агента B и назвать
  себя B в admin-сокете. Изоляция между агентами появляется вместе с изоляцией от владельца —
  этап 7 (отдельные пользователи, admin-сокет проверяет peer UID, inbox с правами 700).
  Описание выше кладёт поле `agent` всюду, чтобы на этапе 7 его оставалось только проверять.
- Гейт работает только там, где есть PreToolUse-хук (Claude Code). Для других агентов это
  канал сообщений, не гейт.
- Один телефон, один владелец — без изменений.

## 9. Решения владельца (нужны до разработки)

1. **Пути/op в контракте:** `/v1/agents/*` и `agent.*` (рекомендую) или оставить `friend.*`,
   меняя только `to`.
2. **Имена:** пакет `rh_friend` → `rh_agent_side` и entry points `rh-agent-*` (рекомендую,
   иначе «friend» остаётся в каждой установке), или оставить имена программ.
3. **Мост:** один процесс на все конфиги (рекомендую) или LaunchAgent на агента.
4. **Выбор адресата в Chat:** picker в одной вкладке (рекомендую) или вкладка на агента.
5. **Порядок PR:** (a) контракт 0.5.0 + векторы (ревью iOS), (b) ядро + миграция,
   (c) сторона агента + docs, (d) iOS. Live-тест повторить по docs/agent-gate.md с двумя
   агентами (Friend + тестовая сессия) до переустановки.
6. **Переходный период:** принимать ли старую секцию `[friend]` одну версию (рекомендую) или
   требовать правку конфига сразу.
