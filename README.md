# keyhunter-rs

Автономный endpoint-first сканер утечек API-ключей: GitHub, Gitee, GitLab, Gitea, Codeberg, Hugging Face, GitHub Gists, V2EX, NodeLoc, NodeSeek, Pastebin + Telegram-бот с админ-панелью.

Логика: находит в коде endpoint → спускается в историю коммитов → достаёт ключ → проверяет `GET /models` → отправляет challenge-слово в модели → присылает карточку в чат.

После загрузки PAT сканер работает сам: **30 000+ встроенных запросов**, ротация, repo discovery, автоматическое углубление в найденные репозитории и самообучение на новых endpoint-хостах. Параллельно внешний цикл обходит Gitee, GitLab, Gitea, Codeberg, Hugging Face, GitHub Gists, V2EX, NodeLoc, NodeSeek и Pastebin — без PAT и без ручных команд.

## Сборка

```bash
source $HOME/.cargo/env
cargo build --release
```

Бинарник: `target/release/keyhunter-rs`.

## Настройка

```bash
cp .env.example .env
```

```ini
TG_TOKEN=123456:AA...
ADMIN_ID=8228560276
DB_PATH=data/scanner.db
PROXY=
TG_PROXY=
NOTIFY_START=1
RUST_LOG=info
```

`PROXY` — http/https/socks5 для GitHub и проб. `TG_PROXY` — отдельно для Telegram.

## Запуск

```bash
./target/release/keyhunter-rs            # бот + сканер
./target/release/keyhunter-rs --check https://api.host/v1 sk-...   # точечная проба
./target/release/keyhunter-rs --demo     # пример карточки
./target/release/keyhunter-rs --getme    # проверка токена бота
./target/release/keyhunter-rs --recheck  # перепробить всё не-VALID из базы
./target/release/keyhunter-rs --recheck valid  # перепроверить все VALID новым challenge
./target/release/keyhunter-rs --recheck fake  # перепроверить FAKE и вернуть ложные срабатывания
./target/release/keyhunter-rs --recheck all  # перепроверить всю базу
./target/release/keyhunter-rs --recheck api.x.ai  # только хосты, содержащие строку
./target/release/keyhunter-rs --sources gitee openai 300   # проверить внешний источник, до 300 документов
./target/release/keyhunter-rs --export exports/valid.txt  # VALID-ключи в txt
./target/release/keyhunter-rs --export-send             # записать и отправить файл админу
```

## Бот

Первый запуск: `/start` → панель. Доступ только у `ADMIN_ID`.

### Команды

- `/panel` — админ-панель
- `/addpat` — залить пачку PAT (по одному в строке, до 200 за раз, или файлом `.txt`/`.csv`)
- `/pats` — пул, квоты, scope
- `/delpat ID` — удалить токен
- `/scan owner/repo` — просканировать репозиторий целиком
- `/scan repo:owner/repo` — то же явно
- `/scan "sk-" in:file` — GitHub code search запрос
- `/check https://api.host/v1 sk-...` — точечная проверка
- `/repo owner/repo` — короткая форма
- `/queries` · `/addq <query>` · `/toggleq ID` · `/delq ID` — пул поисковых запросов
- `/auto on|off` — автономный режим
- `/auto now` — внеочередной импульс
- `/auto` — статус: интервал, очередь, запросы, хосты
- `/sources` — внешние источники
- `/sources on|off` — включить/выключить обход
- `/sources now` — внеочередной источник
- `/proxies` — публичный прокси-пул
- `/proxies on|off` · `/proxies now` · `/proxies scope`
- `/export` — выгрузить все VALID-ключи в `.txt` (ключ, base url; старые → новые)
- `/stats` — статистика
- `/set probe_limit 26` — настройка
- `/cancel` — сбросить ввод

### Автономный режим

Включён по умолчанию. После `/addpat` ничего писать не нужно:

- каждые 30 секунд запускается пачка code search запросов (минимум 20 секунд);
- каждые 10 минут — repo discovery по свежим AI/LLM-репозиториям;
- найденные репозитории автоматически уходят в глубокий скан: дерево, 600 файлов, 50 коммитов;
- новые endpoint-хосты становятся новыми запросами;
- уже просканированные файлы кэшируются на 3 дня;
- 24 воркера обрабатывают задачи параллельно.

Управление: кнопка «📡 Авто» в панели или `/auto on|off`.

### Внешние источники

Отдельный цикл, не требующий PAT. Каждые **15 секунд** (минимум 10) запускает пачку из **16 источников**; у каждого — до **600 документов**. Внутри адаптеров raw-файлы и темы тянутся параллельно (до 24 запросов на адаптер), без искусственных пауз; общий дедлайн одного источника — **45 секунд**.

**Source parser v2**: URL канонизируются (фрагменты, креды, utm/fbclid/gclid), документы дедуплицируются по URL и хэшу текста, challenge-страницы отбрасываются, страницы поисковой выдачи используются только для discovery ссылок (не для извлечения ключей), прокси «липнут» к хосту, падения адаптеров получают cooldown, а crawl-frontier имеет лимит на один хост и приоритет по сигналу документа.

- 🇨🇳 **Gitee** — поиск репозиториев через `so.gitee.com`, дерево и raw-файлы через API v5;
- 🇨🇳 **V2EX** — свежие темы + ответы (`reply_content`);
- 🇨🇳 **NodeLoc** — поиск Discourse `/search.json` + полные темы с ответами;
- 🇨🇳 **NodeSeek** — свежие посты и ответы;
- 🇺🇸 **Hacker News** — комментарии через Algolia API (`hn.algolia.com`);
- 🌍 **Stack Overflow / Stack Exchange** — вопросы с телами через API;
- 🇺🇸/🇮🇳 **Dev.to** — статьи по тегам, полный `body_markdown`;
- 🇺🇸/🇮🇳 **Medium** — RSS тегов, полный текст;
- 🇸🇬 **Tech in Asia** — поиск по сингапурским технологическим новостям;
- 🇮🇳 **GeeksforGeeks** — поиск по статьям;
- 🇯🇵 **Qiita**, **Zenn**, **Note**, **Hatena** — статьи и поиск;
- 🇰🇷 **Velog** — GraphQL `searchPosts` с полным телом;
- 🇻🇳 **Viblo**, **Tinhte** — API постов и поиск;
- 🇷🇺 **Habr**, **Tproger** — поиск и полные статьи;
- 🇺🇦 **DOU** — поиск по украинскому dev-сообществу;
- 🇧🇾 **dev.by** — поиск по белорусскому IT;
- 🌍 **GitLab**, **Gitea.com**, **Codeberg** — публичные репозитории, дерево и raw;
- 🌍 **Hugging Face** — Spaces, модели и датасеты: `app.py`, `.env`, конфиги;
- 🌍 **GitHub Gists** — публичные гисты;
- 🌍 **Pastebin** — свежий архив и raw-пасты;
- 🦆 **DuckDuckGo** — HTML-выдача + выкачка найденных страниц, включая paste/gh/rentry/telegra.ph;
- 🧑‍💻 **Debian Code Search** — код пакетов Debian;
- 🗄 **Internet Archive** — metadata/full-text поиск;
- 🐳 **Docker Hub** — описания публичных образов и env-примеры;
- 🐘 **Mastodon** — публичные статусы через v2 search;
- 🦫 **Lemmy** — публичные посты и комментарии через v3 search;
- 🦊 **GitLab Snippets** — публичные сниппеты GitLab (rate-limit — fail-fast);
- 🔭 **Marginalia** — независимый поисковый индекс + выкачка найденных страниц;
- 🌍 **Telegram** — публичные каналы `t.me/s/...` (RU/UA/BY/global);
- 🔎 **Bing** (и ручной Brave) — поиск по всему открытому вебу, включая `pastebin.com`, `gist.github.com`, `rentry.co`, `justpaste.it`, `telegra.ph`, затем выкачивание найденных страниц;
- 🧅 **Torch** — поиск по Tor hidden services через локальный SOCKS5 (`TOR_PROXY`), включая onion-страницы с утечками/paste-сервисами. Tor-демон `tor-keyhunter.service` поднимает SOCKS5 на `127.0.0.1:9051`;

**Новый пак v3 (85 адаптеров):**
- 🇨🇳 **Juejin, CSDN, SegmentFault, CNBlogs, OSChina, 51CTO, Tencent Cloud, Aliyun, Jianshu, Weibo, Bilibili** — китайские статьи, форумы и поиск по сниппетам;
- 🇨🇳/🇷🇺 **WeChat через Sogou** — поиск публичных статей WeChat;
- 🌍 **npm registry** — метаданные пакетов (`description`, `keywords`);
- 🌍 **Bluesky** — публичный searchPosts API;
- 🌍 **Discourse-форумы OpenAI, Hugging Face, Cursor, Vercel, Roblox DevForum** — `/search.json` с блёрбами тем;
- 🌍 **paste.gg** — свежие пасты и содержимое файлов;
- 🌍 **urlscan.io** — поиск страниц по баннерам и URL;
- 🌍 **Mojeek, Yandex, Baidu, Sogou, Naver, Startpage, SearX, old.reddit, Lobsters** — дополнительные поисковые индексы;
- 🌍 **security/news** — The Hacker News, BleepingComputer, SecurityWeek, InfoQ, HackRead, CyberNews, The Register, Packet Storm;
- 🌍 **Stack Exchange family** — Security, ServerFault, SuperUser, AskUbuntu (HTML fallback);
- 🌍 **hashnode, justpaste, rentry** — блоги и пасты.

**Shodan:** адаптер поддерживает `SHODAN_API_KEY` и `shodan/host/search`, но активные задачи не ставятся, если у ключа нет query-кредитов: текущий ключ отдаёт `api-info` 200, а key-specific запросы — `401 Insufficient query credits`. Ключ не выводится в логи/карточки.

Для китайских релеев добавлен разбор «голых» 32/40/64-hex токенов: если такой токен стоит рядом с endpoint, он проверяется как ключ, даже без префикса `sk-`.

Все находки идут в тот же конвейер `/models` → challenge → карточка. Управление: `🌐 Источники` в панели, `/sources on|off`, `/sources now`. По умолчанию: **15 секунд** между пачками (минимум 10), **16 источников параллельно**, **600 документов** с каждого, дедлайн **45 с**; `source_interval`, `source_docs`, `source_batch`, `source_timeout`. Пул — **274 статических задач / 85 источников** плюс динамические задачи Source Atlas. 403/429 больше не ретраятся впустую: источник падает быстро, воркер не висит.

**Source Atlas (новое):**

- `source_tasks` — durable-очередь задач с `priority/runs/hits/last_run`: источник, который даёт пары, поднимается, пустой — опускается;
- `source_frontier` — очередь реальных страниц, найденных внутри результатов; каждый crawl-джоб забирает страницу из frontier, а не только поисковую выдачу;
- `scan::run_source` извлекает `href/src` из страницы и ставит до **120** ссылок в frontier на следующий hop; same-host ссылки углубляют сайт, внешние — только известные code/paste-хабы;
- `source_crawl_depth=2` (настраивается 0–4), `source_frontier_every=4` — каждый 4-й слот пачки идёт в crawl;
- `source_atlas::synthesize` раз в 90 секунд добавляет endpoint-driven задачи `"host" "api key"`, `"host" "sk-"`, `"host" site:pastebin.com` и Torch-пивот для хостов с находками;
- frontier и source_tasks переживают рестарт; при старте незавершённые `running`-страницы возвращаются в `queued`, битые search-redirect URL вычищаются.

Настройки: `/set source_crawl_depth 3`, `/set source_frontier_every 3`, `/set source_atlas_interval 60`.

Приоритет **Alibaba Cloud DashScope / 百炼, качественные classic-ключи**: в пуле **600+ DashScope/Qwen-запросов** — оба хоста (`dashscope.aliyuncs.com`, `dashscope-intl.aliyuncs.com`), native `/api/v1`, `/compatible-mode/v1`, `DASHSCOPE_API_KEY`, `ALIBABA_CLOUD_API_KEY`, `BAILIAN_API_KEY`, `QWEN_API_KEY`, SDK-вызовы (`import dashscope`, `dashscope.Generation.call`) и модели `qwen3-max`, `qwen-max`, `qwen-plus`, `qwen-coder`, `qwen-vl-max`. **Жёсткий quality-парсер принимает только classic `sk-` + 32 hex и только в DashScope-контексте** (endpoint, `DASHSCOPE_*`/`BAILIAN_*`/`QWEN_*`, `.env`/config). **`sk-ws-…` workspace-ключи исключены**: они получают отдельный kind `dashscope_ws` и не сканируются новыми quality-задачами. **Native endpoint автоматически переводится на `/compatible-mode/v1`**, а workspace bare-host получает `/compatible-mode/v1` первым кандидатом.

**Официальные ключи**: сканирование сфокусировано на **OpenAI, DeepSeek, OpenRouter, Moonshot, Anthropic, xAI и Alibaba DashScope / 百炼**. Для GitHub-поиска официальный lane принимает только пары с первым party-хостом; DashScope classic `sk-` проходит quality-фильтр, `sk-ws-…` в новые quality-задачи не попадает. Лейн отсекает тесты, примеры, README и `.env.example`, ограничивает **400 файлов** и **16 файлов на репозиторий**. Источники с официальным запросом проходят тот же фильтр после извлечения. Мусорные search/captcha-категории и их чекеры удалены из кода.

**Batch-поиск GitHub:** планировщик запускает до **10 независимых поисковых задач за тик** (интервал 20 с), PAT burst — до **6** дорков; одновременно работают до **48** воркеров. Результаты поиска обрабатываются **сниппетами**: `text_matches` из GitHub code search сразу дают endpoint+key кандидатов без скачивания каждого файла; полный raw-файл остаётся fallback. За один цикл deep repo hunt ставит до **20** репозиториев, файловый бюджет — **1 800**, проб — **1 500**. Запросы разбиты на точные пакеты: официальные ENV/endpoint/prefix, `.env`, docker-compose, workflows и PAT-дорки. Все настройки — `auto_batch`, `auto_interval`, `pat_burst`, `discover_repos`, `max_files`, `max_probes`.

**PAT-пул (несколько провайдеров):** `/addpat` принимает GitHub (`ghp_…`, `github_pat_…`), GitLab (`glpat-…` или `gitlab:…`), Gitee (`gitee:…`), Gitea (`gitea:…`) и Codeberg (`codeberg:…`). GitHub-токены идут в code-search pool; Gitee/GitLab/Gitea/Codeberg валидируются через API провайдера и автоматически подставляются в соответствующие source-адаптеры. **GitHub PAT-ключи:** найденные `ghp_…`, `github_pat_…`, `gho_/ghu_/ghs_/ghr_` — отдельная категория `github_pat`, **не AI и не search**. Проверка: `/user` + один code-search запрос; валидный ключ должен уметь `search/code`. Такие находки получают отдельный счётчик **🔑 PAT VALID** и отдельную карточку, но обычный probe-ранг. Для их поиска выделен отдельный lane **`pat`** на **2 PAT** и PAT burst: **6 поисковых задач за тик**, до **2 страниц** и **2 000 файлов** на задачу, отдельный фильтр путей (`.env`, workflow, config, scripts; без test/docs/example) и **PAT history**: до **3 файлов** на задачу и **25 коммитов** на файл, чтобы достать токен, удалённый из текущей ветки. GitHub code search идёт с `sort=indexed` и **без** `pushed:` — этот qualifier в code search схлопывает выдачу почти в ноль; `search_fresh_days` применяется к repository discovery (0 = окно 120 дней).

### Прокси-пул

Каждые **5 минут** скачивает 18 публичных списков HTTP/SOCKS5, проверяет до 1000 кандидатов через `https://api.ipify.org` с таймаутом 6 секунд и оставляет только рабочие. Панель: **🌐 Прокси**, команды `/proxies`, `/proxies on|off`, `/proxies now`, `/proxies scope`.

Режимы:
- **sources** — прокси только для внешних источников (по умолчанию);
- **probe** — только для проверки ключей;
- **all** — для GitHub, источников и проб.

Ручной `proxy` в настройках имеет приоритет и применяется ко всем клиентам. Авто-пул после рестарта подхватывает только валидированные адреса.

### Админ-панель

- 🗂 **PAT-пул** — загрузка, проверка, удаление мёртвых, остатки квот
- 🎯 **Запросы** — code search запросы и авто-пул
- ⚙️ **Настройки** — модели, потоки, глубина коммитов, файлы, страницы, пробы, авто-интервал, батч, deep repos, кэш, звёзды, форки, recheck, чат отчётов, прокси
- 📊 **Статистика**
- 🗃 **База** — последние найденные ключи
- 🗺 **Атлас** — найденные endpoint-хосты и их valid-счётчики
- 🌐 **Источники** — Gitee, GitLab, Gitea, Codeberg, HF, Gists, V2EX, NodeLoc, NodeSeek, Pastebin; вкл/выкл и запуск
- 🌐 **Прокси** — публичный пул, проверка, область применения
- 📡 **Авто** — вкл/выкл, интервал, очередь

Настройки применяются на лету, прокси пересоздаёт HTTP-клиенты.

### Ручной скан и источники

`/scan` запускает **широкий набор дork-запросов** (по умолчанию 20, до 40) и веер источников:

- базовый запрос, точные `.env`/config-файлы, Dockerfile, compose, workflows, terraform, JSON/YAML/TOML/properties;
- официальные провайдеры (OpenRouter, OpenAI, DeepSeek, DashScope, Anthropic, Moonshot, xAI), literal-префиксы ключей и PAT;
- свежие репозитории `pushed:>{90 дней}` и контекстные запросы `api_key`, `base_url`, `中转`, `百炼`.

Набор dorks ротируется между запусками (`manual_dork_cursor`), поэтому повторный `/scan` по той же цели не читает те же первые страницы. Веер источников получает 8 разных plain-запросов с ротацией (`manual_source_cursor`), а не один и тот же текст.

Повторки отсекаются: известные пары `endpoint+key` пропускаются на 24 часа (`manual_skip_hours`), неизменённые файлы берутся из `scanned`-кэша (`manual_force_rescan=0`), недавно пройденные deep-репозитории — 6 часов (`manual_deep_hours`). Количество источников: `/set manual_sources_limit 100` (0 отключает, максимум 120); `manual_dorks` — до 40. Если PAT-пул пуст, GitHub-часть пропускается, но источники всё равно запускаются.

## PAT

Нужен classic token со scope `public_repo` либо fine-grained с public read.
Code search без авторизации не работает. Лимиты GitHub:

- поиск: ~10 запросов/мин на токен
- core: 5000/час на токен

Пул ротирует токены по остатку квоты. Поиск разделён на три лейна: **3 official PAT** (официальные API), **pair PAT** (кастомные/неофициальные) и **2 pat PAT** (только GitHub PAT-креды). 401 помечает токен мёртвым. PAT burst использует `pat` и `pair` лейны, не забирая official-резерв; настройки: `pat_burst=6`, `pat_scan_pages=2`, `pat_max_files=2000`, `pat_max_probes=3000`, `pat_files_per_repo=64`, `pat_history=1`, `pat_history_files=3`, `pat_history_depth=25`.

Ручное управление лейнами: `/lane` — список id и текущих лейнов; `/lane 12 official` — перевести PAT #12 в official; `/lane 12 pair` — вернуть в pair; `/lane auto` — снова авто-раскладка 3/остальные. После первой ручной команды авто-перебалансировка отключается и больше не затирает выбор при reload/рестарте.

## Точность official-поиска

Официальные ключи теперь ищутся отдельным точным слоем, а не просто «запросами с openai в тексте»:

- `src/official.rs` — профили провайдеров: `api.openai.com`, `api.deepseek.com`, `openrouter.ai`, `api.moonshot.cn/.ai`, `api.anthropic.com`, `api.x.ai`, DashScope;
- классификатор учитывает **host + env + уникальный префикс ключа**: `sk-proj-`, `sk-ant-`, `sk-or-v1-`, `xai-`, `sk-ws-`; голый `sk-` в official-лейн не попадает;
- в таблицу `queries` добавлена колонка `official`; `next_official_query` и `next_pair_query` больше не используют длинный LIKE-предикат, а читают точный флаг;
- добавлены seed-дорки вида `"api.openai.com" "sk-proj-" path:.env`, `"OPENAI_API_KEY" "api.openai.com" in:file`, `"api.anthropic.com" "sk-ant-" in:file`;
- официальные задачи **Source Atlas** (`"api.openai.com" "sk-proj-"`, `site:pastebin.com` и т.п.) получают priority **330** и идут раньше обычных хостовых пивотов;
- пары с префиксом official-провайдера поднимаются в начало `probe_pairs` даже если endpoint оказался релеем.
- official-очередь использует **1 страницу** (`official_scan_pages=1`) вместо 6: первые 100 результатов обычно содержат лучшие совпадения, а сэкономленная квота уходит на большее число разных official-дорков;
- редкие admin-префиксы (`sk-admin-`, `sk-svcacct-`) имеют меньший приоритет, чем массовые `sk-proj-`, `sk-or-v1-`, `sk-ant-`, `sk-ws-`; очередь не тратит первые слоты на редкие формы.

Проверка: `/atlas` показывает счётчики query-графа, `/pats` — сколько PAT в official/pair. Ручное перераспределение: `/lane <id> official|pair`, `/lane auto`.

## Что сканируется

- поиск по коду (несколько страниц, дедуп repo+path)
- дерево репозитория (до `max_files`)
- коммиты по конкретному файлу, где найден endpoint, но нет ключа
- коммиты всего репозитория, если endpoint найден
- ключи без endpoint проверяются по дефолтному эндпоинту провайдера (OpenAI, Anthropic, OpenRouter, xAI, HF)
- внешние источники: 85 адаптеров — Gitee, GitLab, Hugging Face, V2EX, NodeLoc, Pastebin, DuckDuckGo, Debian Code Search, Internet Archive, Docker Hub, Mastodon, GitLab Snippets, Marginalia, Juejin, CSDN, SegmentFault, CNBlogs, OSChina, 51CTO, Tencent Cloud, Aliyun, WeChat/Sogou, Jianshu, Weibo, Bilibili, npm, Bluesky, Discourse-форумы, paste.gg, urlscan, Mojeek, Yandex, Baidu, Naver, Startpage, SearX, security/news-поиск

Фильтры: форки, архивы, минимальные звёзды, размер файла, мусорные пути (`node_modules`, `dist`, lock-файлы), плейсхолдеры (`YOUR_KEY`, `xxxx`, `changeme`).

## Производительность

- SQLite работает в WAL с `cache_size=64 MiB`, `mmap_size=256 MiB`, `temp_store=MEMORY` и `busy_timeout=15s`; индекс `findings(last_checked)` и `jobs(state, created_at)` ускоряют recheck и отчёты.
- Перед пробой проверка «этот endpoint+key уже проверяли» идёт одним batch-запросом на 250 пар вместо SELECT на каждую пару.
- Сообщение прогресса ручной пробы обновляется не на каждый ключ, а раз в 10 ключей или раз в 2 секунды.
- Горячие SQL-запросы (`was_scanned`, `recent_finding`, `needs_deep`) используют prepared-statement cache.
- Модели внутри одной пробы идут параллельно; баланс запрашивается одновременно с моделями.

## Турбо-режим

Профиль рассчитан на скорость, а не на экономию PAT-квоты:

- **24 воркера**, до **6 поисковых задач** за тик; число official-слотов равно числу живых official-PAT, остаток — pair; авто каждые **25 с**;
- **6 страниц** поиска, до **1800 файлов** на скан, **4 страницы** параллельно, **96 файлов** в полёте;
- **12 моделей** на ключ, **40** тестов на ключ, до **500** пар на скан, **64** ключа параллельно, общий probe-gate **96**;
- до **10 deep-репозиториев** за цикл, **100** коммитов, **80** файлов для commit mining, **до 2 не-дефолтных веток** (`branch_depth`);
- источники: **16 задач** за тик (до 16, две трети воркеров), каждые **15 с**, до **600 документов**, внутренний параллелизм **24**, дедлайн **45 с**; discovery каждые **5 минут**, до **8 репозиториев**;
- при исчерпании search-квоты задача падает сразу, а не держит воркер в многосекундном сне; scheduler сам попробует следующий тик.

**PAT-лейны:** на свежей базе три PAT с наименьшими id автоматически получают `official`; остальные — `pair`. После `/lane` раскладка ручная и сохраняется при reload/рестарте. В авто-батче official-слотов ровно столько, сколько живых official-PAT; остаток — pair. В `/pats` видны оба счётчика, ручное переключение — `/lane <id> official|pair`, сброс — `/lane auto`. **Приоритет official-провайдеров** выше DashScope: в пробах они идут **рангом 0**, DashScope — **рангом 1**; deep-scan даёт им **+8** против **+6**. Источники с official env/хостами и Source Atlas official-задачи идут первыми. Mistral, Gemini, Cohere, Perplexity, Together, Fireworks, Cerebras, SambaNova, NVIDIA, Hugging Face, Replicate и Cloudflare сканируются, но **без повышенного приоритета**.

## Seedance / Volcengine Ark

Поддержаны ключи Seedance/Ark (`https://ark.cn-beijing.volces.com/api/v3`).
Для ручной/API-проверки создаётся **минимальное видео** по каждой модели: 480p, 5 секунд,
без звука. После завершения (успех, ошибка или таймаут) задача удаляется через
`DELETE /contents/generations/tasks/{id}`; без удаления ключ получает `PARTIAL`, а не `VALID`.
Автоскан не создаёт видео: ему доступна только дешёвая проверка авторизации/каталога.
В карточке используется метка `SEEDANCE`, модели хранятся как `video/seedance/<id>`.
Ручные дорки для `seedance` используют `SEEDANCE_API_KEY`/`ARK_API_KEY`, без чужих провайдеров.

## TTS-провайдеры

Fish Audio и ElevenLabs проверяются отдельным TTS-путём, а не чат-моделями:

- Fish Audio — `POST https://api.fish.audio/v1/tts`, модель `s2.1-pro-free`, плюс проверка баланса через `/wallet/self/api-credit`;
- ElevenLabs — список голосов `/v1/voices` и `POST /v1/text-to-speech/{voice_id}`, модель `eleven_flash_v2_5`.

Успешный `200` с `audio/mpeg` переводит ключ в `VALID` и показывает в карточке строку `✅ TTS`. `401/403` — `INVALID`, `402/429` — `LIMIT`. TTS-ключи не отправляются в AI-ранг.

## Проба

1. `GET {base}/models` (Bearer; для Anthropic — `x-api-key`)
2. выбирает до `probe_limit` моделей с приоритетом топовых
3. отправляет сообщение: «ответь ровно этим токеном и больше ничем: `<base>-<6 hex>`», `max_tokens: 64`
4. точное совпадение принимается с обёртками: кавычки, точки, markdown, код-блок, пробелы — нормализуются; регистр не важен
5. если токен есть внутри короткого ответа («Sure, token: …»), отправляется **второй challenge с новым токеном**; оба ответа должны содержать свой токен
6. ASCII-арт, эхо промпта и не-JSON → `FAKE`; ответ без токена, отказ модели и пустой ответ → `PARTIAL`, а не `FAKE`
7. статусы: `VALID` (хотя бы одна модель прошла challenge), `FAKE` (повторные protocol-нарушения или все HTTP-200 пустые/фейковые), `LIMIT` (только 429), `INVALID` (401), `PARTIAL`, `UNREACHABLE`
8. если `/models` ответил 200, пробует узнать баланс ключа; результат кладётся в карточку
9. карточка уходит в отчётный чат; повторы в пределах `recheck_hours` не пробиваются

Challenge-база задаётся кнопкой **🎯 Challenge** или `/set probe_challenge <слово>`. По умолчанию **🎲 Random** включён: к базе добавляется случайный 6-символьный hex-нонс на каждую пробу, поэтому статичный ответ `alibaba` от фейк-API не проходит. Отключить: кнопка **🎲 Random** или `/set probe_random 0`.

## Баланс

Проверка запускается только когда ключ принят (`/models` → 200). Поддерживаются:

- **DeepSeek** — `/user/balance`, отдаёт `total_balance` + валюту
- **OpenRouter** — `/api/v1/credits`, считает `total_credits - total_usage`
- **SiliconFlow** — `/v1/user/info`, поле `totalBalance`
- **Moonshot** — `/v1/users/me/balance`
- **New API / One API / Sub2API** — `/dashboard/billing/subscription` + `/dashboard/billing/usage`; это **лимит** расходов, поэтому в карточке пишется `лимит $…`, а не выдуманный «баланс»
- общие варианты `/api/user/self`, `/api/user/balance`, `/v1/user/info`, `/v1/users/me/balance`

Если ни один эндпоинт не дал баланс — в карточке будет ровно:

```
💰 Баланс: ?
```

Заведомо огромные placeholder-лимиты (`hard_limit_usd ≥ 100000`) считаются непроверяемыми и тоже дают `?`. Отрицательный баланс показывается как есть: `$-0.21` — это реальное превышение кредита.

**Защита от мусорных чисел:** значения больше `1e9` не считаются деньгами. Если релей вернул timestamp/id в поле `balance` (например `2026102622361475021131657248768.00`), это больше не попадёт в карточку: парсер пропустит поле и попробует `remaining`/`available_balance`/`quota`; если валидного числа нет — будет `?`. То же ограничение применяется к ошибкам pre-deduct и к готовой карточке.

## Карточка

```
🔑 CHAT API
✅ VALID · api.host

sk-...

🌐 Эндпоинт
https://api.host/v1

💰 Баланс · $12.34
⚡ RPM · 500/мин
🧠 Каталог · 430 моделей
🎯 Проверено · 26 · chat OK
📅 Проверка · 27.10 07:15 MSK

✅ Работают · 5
• gpt-4o-mini · 1.1с
• claude-haiku-5.5 · 1.4с

🔬 Пробы
✅ gpt-4o-mini · 200 · 1.1с
⏱️ aion-2.0 · 429
...

📦 Каталог моделей
gpt-4o-mini, claude-haiku-5.5, ... +416

🏷 CHAT API · PAIR · 26 проб
✅ ключ принят
```

**AI-ранг:** после успешной пробы `VALID`/`LIMIT` ключ уходит в OpenAI-compatible ranker (`RANK_BASE_URL`, `RANK_MODEL`, `RANK_API_KEY`). Он получает отпечаток ключа и результаты проб (без самого секрета) и возвращает `S/A/B/C/D/E/F` + score; в карточке строка `🏆 Ранг` стоит сразу после баланса. Кэш — `rank_recheck_hours` (24 ч). CLI: `--rank <endpoint> <key>`.

Карточка отправляется **один раз** на уникальную пару `endpoint + key`: флаг `card_sent` сохраняется при upsert, а `claim_card` атомарно захватывает отправку, поэтому параллельные воркеры и повторный recheck не дублируют сообщение. Если Telegram не принял сообщение, claim снимается и карточка уйдёт в следующем цикле.

## Стресс-тест API

Кнопка **⚡ Стресс-тест** в панели или команда `/stress`. Пришли ключ и строкой ниже base url (или `.txt` с парой). Движок находит до **5 рабочих моделей**, затем гоняет нагрузку до цели **5 500 000 токенов** (настройка `stress_target_tokens`). Считает RPM (наблюдаемый и лимит из заголовков), TPS, контекст модели, латентность p50/p95, успешность, ошибки и расход input/output токенов. В конце отдаёт **`exports/stress_*.txt`** с разбивкой по моделям.

Лимит — 5 моделей; цель можно поднять/опустить через `/set stress_target_tokens 5500000`. Тест реально расходует токены ключа.

## Чекер API

Загрузка файла: кнопка **🧪 Чекер API**, команда `/apicheck` или просто пришли `.txt` — формат распознаётся сам.

Вход — пары `ключ` + `base url`, между парами пустая строка:

```
sk-...
https://api.host/v1

sk-...
https://api.host/v2
```

Чекер:

1. разбирает пары, дубликаты убирает;
2. делает `GET /models`;
3. прогоняет модели через challenge (до `checker_models`, по умолчанию **0 = все**; `checker_threads`, по умолчанию 32 пары в полёте; `checker_probe_concurrency`, по умолчанию **4** модели на ключ; `checker_timeout`, по умолчанию **12 секунд**). Проверка идёт напрямую, без source-прокси; если прямой запрос не удался — повтор через прокси. `/models` 200 считается подтверждением авторизации, поэтому 429/таймаут чата не превращает рабочий ключ в `INVALID`;
4. берёт баланс (см. раздел «Баланс»);
5. в результат попадают **только ключи со статусом VALID**; `/models` ищется параллельно по кандидатам `base`, поэтому мёртвый endpoint не тратит три последовательных таймаута;
6. присылает `.txt` с заголовком, нумерацией и подписями:

```
════════════════════════════════════════════════
            ✅ API ЧЕКЕР · ВАЛИДНЫЕ КЛЮЧИ
════════════════════════════════════════════════
Валидных ключей: 1 из 2
Дата проверки: 25.10.2026 16:00 МСК

────────────────────────────────────────────────
1. 🔑 КЛЮЧ
sk-...

🌐 BASE URL
https://api.host/v1

💰 БАЛАНС
$12.34

⚡ RPM
500/мин

🤖 РАБОТАЮЩИЕ МОДЕЛИ (2)
• gpt-4o-mini
• claude-haiku-5.5

────────────────────────────────────────────────
```

Если баланс неизвестен — ровно `?`. **RPM** читается из `x-ratelimit-limit-requests` / `x-ratelimit-limit` (а также `ratelimit-limit`, `x-rate-limit-limit`) на `/models` и chat-ответах; если провайдер не отдаёт лимит — `?`. Выходной файл сохраняется в `exports/api_check_*.txt` с правами `600`.

Для локальной проверки без Telegram: `./target/release/keyhunter-rs --checkfile pairs.txt out.txt`.

## Выгрузка VALID

Кнопка **📤 VALID .txt** или `/export` открывает меню:

• **Все AI-ключи**
• **DashScope**
• **Moonshot (офиц.)**
• **OpenAI (офиц.)**
• **Модель / endpoint** — вводишь `claude-opus-5`, `api.openai.com`, `dashscope`; для модели по каждому VALID-ключу отправляется запрос **hi**, и в файл попадают только ключи, где модель реально ответила. Для endpoint достаточно совпадения строки.

Команды: `/export all`, `/export dashscope`, `/export moonshot`, `/export openai`, `/export <модель или endpoint>`. CLI: `--export`.

Формат файла — только ключ и endpoint, пары через пустую строку:

```
sk-...
https://api.host/v1

sk-...
https://api.host/v1
```

Попадают только записи со статусом `VALID`, старые → новые. Файл приходит документом в отчётный чат.

## GitHub search v2

- Поисковые запросы получают tier-priority: `.env`/env-переменные и точные provider-дорки идут раньше длинных language-хвостов; `"sk-" in:file` остаётся в ротации, но не забирает первые слоты.
- Результаты страницы ранжируются по пути **до** обрезки `max_files`: `.env`, `secrets`, `credentials`, `config.*` выше README и тестов; на один репозиторий — не больше `max_files_per_repo` файлов (40).
- `pushed:>` **не добавляется** к code search: GitHub принимает qualifier синтаксически, но выдаёт 0–1 результат вместо миллионов. Свежесть применяется в repository discovery и `sort=indexed`.
- PAT-квота резервируется атомарно при `pick`, поэтому параллельные страницы не превышают 10 search-запросов/минуту на токен.
- Atlas генерирует только `host`, `host + sk-`, `host + api_key`, `host + path:.env` и repo/owner-пиворы; cap — **400 запросов**, синтез — не более 40–50 новых за проход.
- Обновлённые настройки: `auto_interval=25`, `official_scan_pages=1`, `page_concurrency=6`, `file_concurrency=96`, `cache_days=7`, `search_fresh_days=0`.

## Atlas: многоуровневый скан GitHub

Вместо плоской очереди из 8 000 запросов теперь работает **Atlas**:

- **L0 seed** — компактный пул: официальные ENV/endpoint-пары и PAT-дорки;
- **L1 code dorks** — поиск по коду с пагинацией и дедупом repo+path;
- **L2 repo/owner pivot** — из репозиториев с находками генерируются `repo:` и `user:` запросы;
- **L3 endpoint pivot** — каждый новый endpoint-хост автоматически становится набором запросов `in:file`, `"sk-"`, `path:.env`, `filename:.env`;
- **L4 deep branches** — для deep-репозиториев читаются до `branch_depth` не-дефолтных веток, а затем история коммитов.

Планировщик учитывает не только `last_run`, но и **priority**, **runs** и **yield** `(hits+1)/(runs+2)`: новые и результативные запросы получают ход раньше, пустые — уходят вниз. Официальные API-хосты получают повышенный приоритет. Новые Atlas-запросы видны в `/atlas`; синтез идёт не чаще раза в `atlas_interval` (45 с), чтобы не забивать БД.

## Баланс

Проверка баланса теперь делает **широкий sweep**: DeepSeek, OpenRouter, SiliconFlow, Moonshot, New API/One API (`/api/user/self`, `/api/user/quota`, `/dashboard/billing/*`, `/v1/dashboard/billing/*`), credit grants и generic-поля. Парсер понимает вложенные `data`, `result`, `account`, `user`, квоты `quota`/`quota_per_unit`, кредиты и `hard_limit_usd`.

Ошибки вида `Need to pre-deduct $1000, balance $5.839 is insufficient`, `insufficient_quota`, `余额不足` разбираются в баланс — как из billing-ответов, так и из ответов `/models` и chat-проб. `?` остаётся только если провайдер действительно не отдал ни одного числового баланса.

Есть **cost-probe** (`balance_cost_probe=1`): один заведомо сверхбюджетный запрос, чтобы провайдер вернул pre-deduct-ошибку с балансом. В коде по умолчанию выключен, но на этой инсталляции включён; отключается через `/set balance_cost_probe 0`.

## Прокси

- **36 списков** публичных прокси (HTTP/SOCKS5), параллельная загрузка;
- до **4000 кандидатов**, проверка с конкурентностью **384** и таймаутом **3 с**;
- рабочая выборка сортируется по latency и кэшируется в `data/proxies.json` (600);
- источник получает **12 лучших exit-IP** с round-robin на каждый запрос;
- refresh по умолчанию 300 с, `proxy_scope=sources` — GitHub и проверки ключей идут напрямую, источники через пул.

## Структура

- `src/github.rs` — PAT-пул, code/repo search, дерево, коммиты, raw/blob
- `src/extract.rs` — regex endpoint'ов и ключей, пары, провайдер-фильтры, плейсхолдеры
- `src/probe.rs` — `/models`, challenge-слово по моделям, статусы, FAKE-фильтр
- `src/scan.rs` — пул воркеров, commit mining, кэш, deep-скан, отправка карточек
- `src/checker.rs` — файловый чекер: пары ключ/base, `/models`, модели, баланс, красивый txt
- `src/auto.rs` — авто-планировщик, Atlas-синтез, repo discovery, очередь источников
- `src/atlas.rs` — многоуровневый граф запросов, pivot-хосты/репозитории/владельцы, yield-приоритет
- `src/source_atlas.rs` — Source Atlas: динамические задачи по endpoint-хостам и crawl-frontier
- `src/sources.rs` — 85 источников, compact source pack, parallel fetch, link extraction для crawl
- `src/proxy.rs` — 36 списков, параллельная валидация, кэш и ротация прокси
- `src/sources.rs` — Gitee, GitLab, Hugging Face, V2EX, NodeLoc, Pastebin
- `src/bot.rs` — Telegram, панель, команды, авто, атлас
- `src/store.rs` — SQLite: PAT, находки, запросы, хосты, кэш, джобы, настройки
- `src/format.rs` — карточка
- `src/tg.rs` — тонкий клиент Bot API

## systemd

```bash
mkdir -p ~/.config/systemd/user
cp deploy/keyhunter.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now keyhunter
journalctl --user -u keyhunter -f
```
