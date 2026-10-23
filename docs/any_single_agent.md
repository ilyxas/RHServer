# Any single agent on the channel: replace the hard-coded "Friend" with one configured name

Статус: **утверждено владельцем** (ревью PR #17, 2026-10-23 19:41Z) с добавками —
docs/decisions/005-channel-agent.md. Серверная часть (a, b, c) реализована; где реализация
отличается от описания ниже, верна запись 005 (team file не роняет ядро; target хранится
явно; `channel set` сам перезапускает ядро и проверяет результат).

Задание владельца (PR #16, 23.10.2026): на канале сидит **один** агент, но **любой**: владелец
хочет менять его и ставить кого нужно в любой момент. Сейчас имя «Friend» зашито в контракт,
ядро, хуки, конфиг, приложение и документацию. Несколько агентов одновременно — **не в объёме**
(документ PR #16 и замечания к нему оставлены на будущее).

## 1. Принцип

Имя агента канала задаётся **в одном месте** — в конфиге ядра — и всё остальное его читает:

```toml
# ~/Library/Application Support/RemoteHands/core.toml
[channel]
agent = "Friend"            # id из раздела «Команда» team_file; единственное место, где имя задано
project_dir = "~/Friend"    # каталог сессии агента: cwd для хуков и правила agents.status
inbox_dir = "…"             # по умолчанию data_dir/inbox (было friend-inbox)
devices_file = "…"          # без изменений
decide_window_s = 120       # без изменений
```

- Секция `[friend]` переименовывается в `[channel]`, ключ `agent` обязателен (ядро без него не
  стартует — явная ошибка лучше, чем тихий «Friend»).
- `title` для показа берётся из team file по id (`- **Friend** — observer` → «Friend»); если id
  нет в team file — ошибка конфига при старте.
- Правила id: `[A-Za-z0-9_-]{1,32}`; сравнение с team file — точное; имя участвует в путях
  (`inbox_dir`, конфиг агента), поэтому ядро проверяет, что реальные пути не совпадают с
  путями другого имени в другом регистре (файловая система Mac регистронезависима).
- Сторона агента (хуки, ask, мост) получает то же имя из своего конфига, который генерирует
  `rhcore friend-config` из конфига ядра, и **проверяет совпадение** с `to` в конвертах.
- Литерала `"Friend"` не остаётся ни в коде, ни в контракте, ни в векторах, ни в приложении.
  Слово `friend` остаётся **именем механизма** (пути `/v1/friend*`, op `friend.*`, программы
  `rh-friend-*`, пакет `rh_friend`, таблицы, события журнала) — это не имя агента, и его
  переименование в объём не входит (п. 6).

## 2. Контракт (`contracts/`, зеркало в RHClient) — bump 0.4.0 → 0.5.0

| Где | Было | Станет |
|---|---|---|
| `openapi.yaml`: тело `friend.send`, тело `friend.decide`, схема `FriendDecision` | `to: {type: string, const: Friend}` | `to: {type: string, pattern: "^[A-Za-z0-9_-]{1,32}$"}`, описание: «id агента канала, как отдаёт `status.channel.agent`; другое значение → `bad_request`» |
| `openapi.yaml`: ответ `status` | `mac_name, core_version, agent_version, mode, server_time` | + `channel: {agent: string, title: string}` (обязательное) — откуда приложение узнаёт, кому писать и как его называть |
| `openapi.yaml`: описания | «Friend inbox / session / verifier / gate», «team from ~/Friend/CLAUDE.md» | «the channel agent's …», «team from the core's team_file» |
| `vectors/friend.json`, `vectors/friend_decide.json` | все тела с `"to":"Friend"` | тела с **не-Friend** id (например `"Agent-Alpha"`), чтобы тесты ловили любой оставшийся литерал; + кейсы: `to` ≠ настроенный агент → `bad_request`; `status.channel` в векторе статуса |
| `CHANGELOG.md`, `MANIFEST.sha256`, генераторы `scripts/vectors_friend*.py` | — | запись 0.5.0; генераторы принимают id параметром |

Подписанный материал меняется только в значении поля `to`; формат подписи, op, ключи — без
изменений. Схемы `FriendQuestion`/`FriendDecision` не переименовываются (имя механизма).

## 3. Ядро (`src/rh_core`, `src/rh_common`)

| Файл | Сейчас | Станет |
|---|---|---|
| `rh_common/friend.py` | `RECIPIENT = "Friend"`; `parse_body`/`parse_decide_body` сравнивают с константой; `FriendDecision(to=RECIPIENT, …)` | константа убирается; функции получают `agent: str` параметром (ядро — из `[channel]`, verifier — из своего конфига) |
| `rh_core/config.py` | `[friend]` → `friend_inbox` (default `friend-inbox`), `devices_file`, `decide_window_s`; `TEAM_FILE = ~/Friend/CLAUDE.md` как default `[agents].team_file` | `[channel]` с `agent` (обязательно), `project_dir`, `inbox_dir` (default `inbox`), остальное без изменений; default `team_file` убрать — путь только из конфига (сейчас он указывает в каталог одного конкретного агента) |
| `rh_core/app.py` | docstrings «Friend verifier / Friend gate / Friend session's user»; маршруты и обработчики | текст → «channel agent»; обработчики передают `core.config.channel.agent` в parse_*; `status` отдаёт `channel` |
| `rh_core/admin.py` | команды `friend.*` без имени агента | без изменений в именах; в ответ `friend.questions` и в событие `friend.question` добавляется поле `agent` (для журнала и будущего) |
| `rh_core/store.py` | `friend_questions`, `friend_decisions` без агента | колонка `agent TEXT NOT NULL` в обеих (schema 3 → 4, заполнение текущим именем); нужна для п. 5 (смена агента аннулирует старое) |
| `rh_core/logfeed.py` | заголовки с литералом: «Message to Friend from …», «Friend asks for a decision», «Allowed Friend's action», «Friend's allow superseded», «Friend used a decision» | те же заголовки с `title` агента из конфига/team file |
| `rh_core/data.py` | `rh.questions`: subtitle «Friend asks · <tool>» | «{title} asks · <tool>» |
| `rh_core/agents.py` / `agent_rules.py` | cwd агента канала задаётся отдельным `[[agents.rule]]` | правило для `channel.agent` по умолчанию строится из `channel.project_dir` (явный `[[agents.rule]]` с тем же id имеет приоритет) |
| журнал | события `friend.*` без имени | поле `agent` в каждом событии канала; новое событие `friend.channel.changed {from, to}` при смене имени (п. 5) |

## 4. Сторона агента (`src/rh_friend`, `src/rh_cli`)

| Файл | Сейчас | Станет |
|---|---|---|
| `rh_friend/config.py` (`FriendConfig`) | `project_dir` default `~/Friend`, `seen_file`/`rejected_log`/`[bridge].state_file`/`[gate].log` с defaults под `~/Friend/…`, `[bridge].target = "friend"` | ключ **`agent`** (обязателен, из `rhcore friend-config`); `project_dir` обязателен, без default; все пути по умолчанию выводятся из `project_dir` (`<project_dir>/state/…`, `<project_dir>/log/…`); `target` — без default, задаётся генератором |
| `rh_cli/rhcore.py` `friend-config` | `--project` (required), `--tmux`, `--target` (default `friend`), `--decide-window`, `--owner-names` | берёт `agent` и `project_dir` из `[channel]` ядра (флаги `--project`/`--target` остаются как переопределение; `--target` default = id агента в нижнем регистре); пишет `agent = "<id>"` в конфиг |
| `rh_friend/verify.py` | проверяет `to` через `rh_common` (константа) | `to == cfg.agent`, иначе отказ `wrong_recipient` в rejected log; метка `[RH ✔ owner · iPhone · time]` без изменений (имя агента в метке не нужно — сессия одна) |
| `rh_friend/gate.py` | `friend.decision.use` | без изменений; в лог гейта добавляется `agent` |
| `rh_friend/ask.py` | `friend.ask` | без изменений; ядро само проставляет `agent` |
| `rh_friend/bridge.py` | один inbox → один `target` | без изменений |
| `default_protected(owner_names)` | правило о записи в CGC подставляет только `{owner}` | без изменений (имя агента в правилах не используется) |
| `pyproject.toml` | `rh-friend-*` | без изменений (имя механизма) |

Хуки в `settings.json` проекта агента: командная строка не меняется (`--config … --project …`);
`--project` обязан совпадать с `channel.project_dir` — иначе `rhcore friend-config` печатает
ошибку, а не конфиг.

## 5. Смена агента «в любой момент» — процедура владельца

Одна команда ядра делает переключение явным и журналируемым:

```
rhcore channel set --agent Codex-Arch --project ~/CodexArch [--target codex]
```

Что она делает (всё — в ядре, по порядку):
1. Проверяет id по правилам п. 1 и наличие в team file.
2. Пишет `[channel]` в core.toml (бэкап `core.toml.bak-<ts>`).
3. В БД: открытые вопросы прежнего агента → `withdrawn` (reason `channel_changed`), неиспользованные
   allow → `voided` (reason `channel_changed`); событие журнала `friend.channel.changed`.
4. Печатает конфиг стороны агента (как `friend-config`) в `…/RemoteHands/friend.toml`
   (бэкап старого) и список ручных шагов:
   - добавить хуки `rh-friend-verify` / `rh-friend-gate` в `<project_dir>/.claude/settings.json`
     нового агента (правка settings — действие под гейтом у Friend; у нового агента гейта ещё
     нет, у старого — удалить хуки руками владельца);
   - tmux-сессия нового агента с именем = `target`;
   - `launchctl kickstart -k` ядра и моста;
   - в приложении ничего: следующий `status` принесёт новое `channel.agent/title`, Chat
     переименуется сам.
5. Старые inbox-конверты прежнего агента остаются в `inbox/` (мост их уже доставил); seen/
   rejected/gate логи — в каталоге прежнего проекта, не переносятся.

Без `channel set` то же можно сделать руками по docs (п. 6), команда — чтобы не забыть шаг 3.

## 6. Приложение (RHClient)

| Файл | Сейчас | Станет |
|---|---|---|
| `RHKit …/Models.swift` | `FriendSendRequest.to = "Friend"` (стр. 158), `FriendDecideRequest.to = "Friend"` (246); `StatusResponse` без канала | `to` — параметр (`init(to:…)`); `StatusResponse.channel: {agent, title}` |
| `RHKit …/CoreClient.swift`, `Operations.swift` | `sendToFriend(text)`, `decide(…)` | `send(to:text:)`, `decide(to:…)`; имена операций `friendSend`/`friendDecide` — без изменений |
| `AppModel.swift` | `sendToFriend`, `decide`, `questions` | хранит `channel` из `status` (обновляется при каждом `status`); `send`/`decide` берут `to` из него; до первого `status` поле отправки неактивно |
| `FriendView.swift` | `navigationTitle("Friend")`, «Friend asks», «Message to Friend», «…lets Friend run exactly this call once…», «Friend checks the signature…», «Friend sees it as a verified message…» | все строки через `channel.title`; accessibility id `friend.*` — без изменений (имя механизма, тесты) |
| `FakeCore.swift`, RHKit-тесты, UI-тесты | `"Friend"` в ответах и ассертах | fake отдаёт `channel` с не-Friend именем (`Agent-Alpha`), ассерты по нему; `scripts/test.sh` поднимает dev-ядро с `[channel] agent = "Agent-Alpha"` из фикстуры stage2 (там этот id уже есть) |
| `contracts/` | @900b828 | sync @<SHA мержа контракта 0.5.0> |

## 7. Документация и тесты ядра

- `docs/friend-gate.md`: «Friend session» → «the channel agent's session» там, где речь об агенте; пути `~/Friend/…` → `<project_dir>/…`; установка — через `[channel]` и `rhcore friend-config`; новый раздел «Switching the agent» (п. 5). Название файла и слово «Friend gate» как имя механизма — оставить.
- `docs/agents-status.md`: пример `team_file` без привязки к `~/Friend`; `[channel].project_dir` как источник cwd правила.
- `docs/decisions/005-channel-agent.md`: это решение после утверждения.
- `tests/test_friend.py`, `test_friend_decide.py`, `test_home_log.py`, `test_agent_rules.py`, `test_contracts.py`, `test_dev_up.py`: конфиг с не-Friend именем во всех фикстурах; кейсы: `to` ≠ агент → `bad_request`; старт без `[channel].agent` → ошибка; id не в team file → ошибка; `channel set` → withdrawn/voided + событие; `status.channel`; verifier с `wrong_recipient`.
- Ревизия «нет литерала»: тест, который грепает `src/`, `contracts/` и фикстуры на `"Friend"` вне docs и падает, если нашёл (дешёвая защита от возврата хардкода).

## 8. Что остаётся как есть (и почему)

- Пути `/v1/friend*`, op `friend.*`, схемы `Friend*`, программы `rh-friend-*`, пакет `rh_friend`,
  таблицы `friend_*`, события `friend.*`, accessibility id `friend.*`, файл `friend.toml`:
  **имя механизма**, не имя агента. Переименование — отдельное решение, трогает подписи
  (op), launchd, settings.json и все тесты; для задачи «поставить кого нужно» не требуется.
- Один агент, один inbox, один admin-сокет, одна tmux-сессия, один конфиг — без изменений.
- Замечания Астры к PR #16 (идентичность через сокет, cwd в подписанном действии, общий мост)
  относятся к нескольким агентам или к этапу 7; здесь учтено только правило id против
  коллизий регистра в путях.

## 9. Решения владельца

1. `status.channel` как источник имени для приложения (рекомендую) или отдельный запрос.
2. Команда `rhcore channel set` с аннулированием открытых вопросов/решений прежнего агента
   (рекомендую) или только ручная процедура по docs.
3. Обязательный `[channel].agent` без default (рекомендую) или default `Friend` для
   совместимости (тогда текущая установка стартует без правки конфига).
4. Порядок PR: (a) контракт 0.5.0 + векторы (ревью iOS); (b) ядро + schema 4 + `channel set`;
   (c) сторона агента + docs; (d) iOS sync + строки + тесты. После (c) — live-тест по
   docs/friend-gate.md с именем, отличным от Friend, на тестовой tmux-сессии.
