# Состояние 14.22 — что закрыто, и есть ли kernel R/W на 14.1x–14.2x

Статус: в работе (живой документ, дописывается по ходу разведки).
Агент: recon-1422-status (task-3). Машина: Linux, без root, сеть через `socks5h://127.0.0.1:10810` (часть запросов — напрямую, см. §6).
Write-scope: только `ps5jb/recon/`. Дата сбора: 2026-11-11.

## 0. Легенда достоверности

| Метка | Значение |
|---|---|
| `ПОДТВЕРЖДЕНО` | есть первичный источник, который я открыл в этой сессии, и он прямо говорит это |
| `ЗАЯВЛЕНО АВТОРОМ` | так написано в репозитории автора; независимой проверки нет |
| `СООБЩЕСТВО ПОВТОРЯЕТ` | утверждение кочует между вторичными источниками без первоисточника |
| `НЕ ПРОВЕРЕНО` | источник не найден / проверить не удалось |
| `ОПРОВЕРГНУТО` | найдено прямое противоречие в первичном источнике |

Три вещи, которые я различаю и не смешиваю:
1. **автор проверил** — есть коммит/дизасм/тест/лог в репозитории;
2. **сообщество повторяет** — утверждение есть в разных местах, но все ссылаются друг на друга;
3. **домысел** — правдоподобная экстраполяция без источника.

---

## 1. TL;DR (для лида)

1. **Sony НЕ раскрыла, что закрыла в 14.22.** Официальные примечания к прошивке — одна строка: «We've made some security fixes to the system software». Это подтверждено и вторичными изданиями, и цитатой самих патчнотов. Любое утверждение «14.22 закрыла X» — **не от Sony**.
2. **14.22 = 26.07-14.22.00, вышла 2 ноября 2026.** Размер ~1.267 ГБ. Предыдущее обновление — меньше чем за две недели до этого.
3. **Kernel R/W на 14.1x–14.2x НЕ продемонстрирован никем.** Самый крупный публичный репозиторий (ZigZagBoi1, 484★) прямо пишет: «Kernel read/write on 14.10 is **not demonstrated**», в его шкале «Demonstrated 14.10 kernel read/write — 0/15». Второй по значимости (pastawithpesto) — «Kernel: **BLOCKED** — needs browser code execution first».
4. **Есть ровно два источника, которые вообще называют конкретику по 14.22**, и оба — заявления авторов без аппаратных доказательств:
   - `kevinisgoated24-spec/PS5-14.20-Jailbreak-Research`: «Sony's patch in 14.22 adds a context-change guard that invalidates re-entrant `getContext()` calls» — **0 звёзд, аккаунт создан 2026-08-28, весь репозиторий — 38 минут коммитов 2026-11-10**, приборных артефактов нет;
   - `logicalpeyote777/ps5-14.00-jailbreak-research` (PAPER.md): «14.22 shipped on 2 November with additional security fixes. No kernel jailbreak exists on 14.20 or 14.22 either» — вторая часть совпадает со всеми остальными источниками, первая — пересказ официальной формулировки.
5. **Патч AIO/Prolapse-цепочки** (kuzibelit, `aio_lapse_exploit.c`): автор утверждает, что дыра закрыта в **14.20** строгой проверкой generation-id, и что kernel R/W там — только план (stages 4–5), не результат.
6. **Практический вывод:** обновляться до 14.22 нечем — ни одного публично подтверждённого kernel R/W на 14.10+ не существует, а 14.22 сужает окно. Держать ≤14.10 (или ≤14.20 по версии kevinisgoated, но эта версия не подтверждена).

---

## 2. Источники

Скачано в этой сессии в `recon/_src/t3-*` (сырьё сохранено, чтобы утверждения можно было перепроверить).

| # | Источник | Тип | Что содержит |
|---|---|---|---|
| S1 | `ZigZagBoi1/PS5-14.10-Research` (484★, master, push 2026-11-10) | репозиторий первичных экспериментов | 3301 probe-скрипт, 3468 захватов, 264 документа, гейты цепочки |
| S2 | `pastawithpesto/PS5-14.10-Jailbreak-Research` (19★, master, push 2026-11-05) | репозиторий первичных экспериментов | CVE-2026-43720 Canvas UAF, подтверждённые примитивы на железе |
| S3 | `logicalpeyote777/ps5-14.00-jailbreak-research` (1★, main, push 2026-11-09) | аналитическая работа (PAPER.md 180 КБ) | sysctl kind swap на 14.00, разбор сообщений о 14.20/14.22, цитаты первоисточников |
| S4 | `kuzibelit/PS5-14.00-14.10-Jailbreak-PoC` (50★, main, push 2026-10-27) | PoC-репозиторий | `aio_lapse_exploit.c` (26 КБ) — AIO double-free, статический анализ IDA |
| S5 | `kevinisgoated24-spec/PS5-14.20-Jailbreak-Research` (0★, main, push 2026-11-10) | репозиторий-заявление | порт Canvas UAF на 14.20; утверждение о патче в 14.22 |
| S6 | `rohbatista18-sys/ps5-jb-tracker` (4★, main, push 2026-11-06) | агрегатор (Next.js) | список 4 отслеживаемых проектов 14.10 |
| S7 | `manos555555/PS5-Suite` (111★, main) | инструмент (клиент) | работает поверх etaHEN/kstuff; kernel-оффсеты FW 14.00/14.10 |
| S8 | `knutwurst/ps5-ultrapack` (72★, main) | инструмент (fpkg-пакер) | к 14.22 отношения не имеет, kernel R/W не заявляет |
| S9 | GBAtemp 2026-11-03 | пресса | полный текст патчноутов 14.22 («security fixes»), цитата Sony |
| S10 | IGN 2026-11-02 | пресса | «26.07-14.22.00, weighs in at 1.267 GB, released today, November 2» |
| S11 | NVD (services.nvd.nist.gov) | первоисточник CVE | CVE-2026-43720 и CVE-2026-43715 реально существуют |
| S12 | `oniz93/ps5-14.10-research` (3★) | status-страница | фазовый статус, ничего не публикует («Public artefact: none») |

Отдельно: `ZigZagBoi1` и `pastawithpesto` — **единственные два репозитория с признаками реальной работы на железе** (захваты, probe-номера, коммиты на протяжении недель). Остальные — производные.

---

## 3. Что именно закрыла Sony в 14.22

### 3.1 Официальная позиция Sony: ничего конкретного

Прошивка `26.07-14.22.00`, 2 ноября 2026. Полный текст официальных примечаний (цитата по GBAtemp, S9; IGN, S10, вторит тому же):

> We've made some security fixes to the system software.

Это всё. Ни списка CVE, ни подсистем, ни описания. **Sony не назвала ни одной исправленной уязвимости.**

Прямая цитата GBAtemp: «Sony does not say what was fixed explicitly, so it is not clear which if any exploits this one patches.»

### 3.2 Что издания ДОБАВИЛИ от себя (и это уже не Sony)

| Издание | Формулировка | Чем является |
|---|---|---|
| geeky-gadgets (2026-11-03) | «addresses jailbreak exploits… as Sony appears to secure the console ahead of GTA 6» | домысел: «appears» |
| nextgenupdate (2026-11-02) | «sole listed change is "some security fixes"» + «community advises against updating» | корректный пересказ + совет сообщества |
| games.gg (2026-11-02) | «adding security fixes as jailbreak efforts continue ahead of GTA 6» | контекст-домысел |
| onejailbreak (2026-11-02) | «It does not mean a jailbreak for 14.20 is coming soon» | интерпретация |

Ни один вторичный источник не имеет доступа к диффу прошивки. **Никто публично не сравнул 14.20 и 14.22 бинарно.**

### 3.3 Что сообщество домысливает как «закрытое»

| Утверждение | Кто | Чем подтверждено | Статус |
|---|---|---|---|
| «14.22 патчит Canvas `getContext()` UAF цепочку; 14.20 остаётся непропатченной» | S5, README:23 и README:124 | **ничем**: заявление в README, нет дизасма, нет теста на 14.22 | `ЗАЯВЛЕНО АВТОРОМ` |
| «Патч добавляет context-change guard, инвалидирующий re-entrant `getContext()`» | S5, README:124 | ничем; конкретика механизма не подкреплена ни строкой дизасма | `ЗАЯВЛЕНО АВТОРОМ` (и подозрительно: 0★, аккаунт новый, 38 минут коммитов) |
| «AIO/Prolapse-вектор закрыт в 14.20 проверкой `*state != saved_generation_id`» | S4, `aio_lapse_exploit.c` шапка | статический анализ IDA по `kernel_1410.elf`; на железе **не проверялось**, автор сам пишет «requires physical console testing» | `ЗАЯВЛЕНО АВТОРОМ` (статика) |
| «14.22 вышла с дополнительными security fixes; kernel jailbreak’а нет ни на 14.20, ни на 14.22» | S3, PAPER.md:2694-2695 | первая часть — официальная формулировка, вторая — совпадает с S1/S2 (отсутствие работающего эксплойта) | `ПОДТВЕРЖДЕНО` для «нет jailbreak’а»; `СООБЩЕСТВО ПОВТОРЯЕТ` для описания патча |

### 3.4 Контекст: что Sony официально заявляла о предыдущих прошивках

Это важно, потому что «14.22 патчит X» проверяется сравнением с тем, что Sony писала раньше — и насколько её формулировки вообще коррелировали с реальными патчами.

| Прошивка | Дата | Официальные примечания Sony | Что реально закрыто (по сообществу/исследователям) |
|---|---|---|---|
| 14.00 | 16–17 сентября 2026 | — | Relapse kernel bug: `aio_multi_wait` UAF + `get_aio_debug_request_info` info leak (S1 status report; диапазон Relapse кончается на 13.60) |
| 14.10 | 1 октября 2026 | — | Hypervisor bug (S3-resume `startup_mp`), подтверждено Sonic_Iso ~3–4 окт.; изначально Jordy утверждал обратное, потом опровергнут (S1 status report) |
| 14.20 | 21 октября 2026 | «We've improved the messages and usability on some screens» — **про безопасность ни слова** | Спорно: onejailbreak озаглавил «14.20 Patches Recent Jailbreak and FPKG Bugs», но это вывод из тайминга, не из патчноутов |
| 14.22 | 2 ноября 2026 | «We've made some security fixes to the system software» | **неизвестно никому публично** |

Ключевой факт: **14.20 официально не заявляла security-фиксов вообще** (только «messages and usability»). Поэтому утверждение S5 «14.20 остаётся непропатченной, а 14.22 патчит canvas» противоречит не только отсутствию доказательств, но и тому, что Sony как раз в 14.20 ничего про безопасность не писала, а в 14.22 — написала. Логика S5 перевёрнута относительно официальных заявлений.

Источники таблицы: S1 `PS5-FW-14.10-Jailbreak-Status-Report.md` §3 (14.00, 14.10); [IGN 2026-10-21](https://www.ign.com/articles/sony-issues-new-ps5-firmware-update-as-jailbreak-race-heats-up-ahead-of-gta-6-release) и [TechSpot](https://www.techspot.com/drivers/driver/file/information/18026/) (14.20 — «improved the messages and usability»); S9 GBAtemp (14.22).

### 3.5 Вердикт по главному вопросу: подтверждено ли, что 14.22 патчит Canvas `getContext()` UAF

**НЕТ. Не подтверждено ничем, кроме README-заявления репозитория с 0 звёзд.**

Разбор по пунктам, чем именно это могло бы подтверждаться и чего нет:

| Требуемое доказательство | Есть ли | Комментарий |
|---|---|---|
| Официальный текст Sony с упоминанием WebKit/canvas | **нет** | Sony написала только «some security fixes» |
| Бинарный дифф 14.20 → 14.22 по WebKit-модулю | **нет** | Никто публично не выкладывал; у S5 нет ни байта дизасма |
| Дизасм конкретной функции (`getContext()`/`checkSetSize`/context-change guard) | **нет** | S5 описывает механизм словами, но не приводит ни адреса, ни строки ассемблера |
| Тест на живой 14.22: UAF-триггер не срабатывает | **нет** | У S5 нет ни лога, ни захвата; `karter-captain/ps5-14.22-browser-probes` (единственный, кто делал пробы на 14.22) прямо пишет «No public exploit chain for 14.22 exists» и результатов не публикует |
| Хотя бы одна независимая группа, повторившая вывод | **нет** | Единственный, кто повторяет — сам S5 в двух строках одного README |

**Что известно достоверно:**
- CVE-2026-43720 реальна (NVD, CWE-416, WebKit UAF, фикс в Safari 26.5.2) — но привязка «CVE-2026-43720 = именно Canvas `getContext()` reentrant UAF» сделана **pastawithpesto**, в NVD такого описания нет.
- Canvas UAF **подтверждён на 14.10** аппаратно (S2, V573/V630 с захватами).
- Перенос на 14.20 заявлен S5 (`V573 ✅ → V630 ✅`), но без единого артефакта.
- 14.22 вышла 2 ноября с «some security fixes».

**Наиболее вероятная реконструкция (помечаю как ОЦЕНКА, не факт):** Sony в 14.22 закрыла что-то из свежевсплывших баг-векторов; учитывая, что 14.22 — второе обновление за две недели и что публичная активность шла по Canvas UAF на 14.10, canvas-вектор — правдоподобный кандидат. Но это **правдоподобная догадка, а не установленный факт**, и проверить её можно только диффом прошивки (что и есть задача соседних task'ов по PUP/дизасму).

### 3.6 Важная находка: `devravik/PS5-14.20-Jailbreak-Research` (9★) — перелицованный клон, а не исследование 14.20

Найдено через GitHub search по «ps5 14.20 jailbreak». Проверил побайтово:

- **один коммит** `Initial commit`, 2026-10-24, автор `devravik` (аккаунт с 2018, 69 репозиториев, 0 подписчиков);
- файловый состав **идентичен** `pastawithpesto/PS5-14.10-Jailbreak-Research` (те же `archive/v569.html`…`v674`, те же размеры);
- `diff` README даёт **ровно 4 смысловых отличия**: «14.10»→«14.20» (2 раза), и **подмену донат-адресов** PayPal/BTC/SOL на свои;
- `CHANGELOG.md` отличается одной строкой: «All Relapse CVEs confirmed patched on 14.10» → «…on 14.20»;
- `VERSION` = `0.1.1`, как у оригинала.

То есть весь «14.20 research» — это 14.10-данные с другим номером прошивки и другими кошельками. **Как источник по 14.20 он недействителен, и его 9 звёзд — не признак достоверности.** Отдельно рекомендую лиду не ссылаться на него в отчёте.

**Вывод по §3:** вопрос «что именно закрыла Sony» публично **не имеет ответа на уровне диффа**. Единственное, что можно утверждать: официально заявлены «some security fixes»; никакого публичного бинарного сравнения 14.20/14.22 не существует. Все «X закрыт» — авторские гипотезы, а самый заметный «доказательный» репозиторий про 14.20 оказался клоном.

---

## 4. Kernel read/write на 14.1x–14.2x — есть ли сообщения

### 4.1 Прямые отрицания в первичных источниках

| Источник | Дословно | Дата |
|---|---|---|
| S1 ZigZagBoi1, README:5 | «Kernel read/write on 14.10 is **not demonstrated**.» | push 2026-11-10 |
| S1, README:84-96 | «Demonstrated 14.10 kernel read/write — **0/15**»; «Repeatable complete kernel exploit — **0/15**» | — |
| S1, `JAILBREAK_CHAIN_14_10.md` | Гейт 4 «Kernel read/write» = **Open**; гейт 5, гейт 6 = **Open** | 2026-10-22 |
| S1, описание репозитория на GitHub | «Kernel read/write and a complete exploit are **not demonstrated**.» | — |
| S2 pastawithpesto, README | Стадия «Kernel» = **BLOCKED** — «Needs browser code execution first» | — |
| S3 logicalpeyote, PAPER.md:2695 | «**No kernel jailbreak exists on 14.20 or 14.22 either.**» | 2026-11-09 |
| S3, PAPER.md (о 13.60) | «homebrew experimentation is limited to July software 13.60… **No kernel jailbreak exists above it**» | — |
| S4 kuzibelit, README | «does **not** demonstrate a working jailbreak for firmware 14.00 or 14.10, nor a reliable end-to-end privilege-escalation chain» | 2026-10-27 |
| S4, README «Source Code Status» | «pointer to arbitrary-free primitive, kernel read/write capability, ASLR bypass, credential modification… **do not establish**» | — |
| S4, README «Known Limitations» | `reclaim_and_confirm()` и `detect_double_free()` **определены, но не вызываются из `main()`** | — |

### 4.2 Что реально достигнуто на 14.10 (единственный уровень, где есть аппаратные доказательства)

По S2 (pastawithpesto, подтверждено на розничном железе через встроенный браузер):

- UAF-триггер `HTMLCanvasElement::getContext()` — **CONFIRMED** (CVE-2026-43720)
- Same-type reclaim 500× Canvas2D spray — **CONFIRMED** (V573)
- Alias R/W через все 12 API Canvas2D — **CONFIRMED** (V630)
- Crash oracle (forged `m_stateStack`) — **CONFIRMED** (V650–V655)
- ASLR defeat, APNG overread → 1651 heap pointer — **CONFIRMED** (V674)
- Arbitrary R/W (forge lineDash Vector) — **DESIGNED**, не подтверждён
- Code exec (vtable hijack + ROP) — **NEXT**
- **Kernel — BLOCKED**

То есть **userland R/W в рамках WebContent-процесса есть, kernel R/W — нет.** Это и есть ключевое различение, которое теряется в пересказах.

### 4.3 Ложный след: «14.10 уже сломана» (Gezine)

S3 (PAPER.md) разбирает это отдельно: Gezine дошёл до **debug menu на 14.10**, но «A debug menu reached on 14.10 is userland and configuration access; the kernel read/write that would follow it is neither present nor public». Заголовки «14.10 already jailbroken» описывают меню, не ядро.

### 4.4 Противоречие внутри S1 (важно для оценки)

`TWITTER_POST.md` в том же репозитории S1 кричит: «AIO DOUBLE-FREE RACE CONFIRMED — 57% hit rate», «The jailbreak for PS5 14.10 is REAL and it's COMING». При этом `JAILBREAK_CHAIN_14_10.md` (обновлён позже, 2026-10-22) квалифицирует то же самое как «socket-lifetime behavior, **not memory corruption**», а README прямо ретрактит часть прошлых заявлений: «Probe 45c **retracts** earlier `fn_addr`/ROP execution and W^X-bypass claims… historical diagrams and older findings are not current proof».

**Правило вывода: у S1 верить README/CHAIN/CHANGELOG, а не твит-тексту.** Твит — маркетинг для донатов, документы — доказательства.

### 4.5 Единственные заявления о kernel-прогрессе выше 14.10

| Утверждение | Источник | Чем подтверждено |
|---|---|---|
| «Подтвердили, что ядро-ядро UAF FontFace пойман на 14.20, но JS-wrapper становится no-op» | S5 README (Phase 1) | ничем; и это же утверждение противоречит S2, где CSSFontFace UAF — **DoS-only** |
| «V573 ✅ → V630 ✅ на 14.20, V674 🔄 в процессе» | S5 README (таблица стадий) | ничем: нет ни одного захвата/лога; только HTML/JS-файлы |
| «AIO `aio_multi_delete` double-free → arbitrary free → kernel R/W» | S4, шапка `aio_lapse_exploit.c` | только статический анализ IDA; stages 4–5 не реализованы на железе |

Ни одно из трёх не является сообщением о **полученном** kernel R/W. Все три — про планы/частичные шаги.

### 4.6 Отдельно: ЛЮБЫЕ сообщения о kernel R/W на 14.1x–14.2x — методика поиска и результат

Чтобы ответить не «я не нашёл», а «я искал вот так и вот где», фиксирую исчерпывающий проход:

**Что именно искал:** любые утверждения о полученном kernel read/write (или kernel read, или kernel write, или произвольном доступе к памяти ядра) на прошивках 14.00–14.22, от кого угодно — автора, исследователя, издания, форума.

**Метод 1 — грепом по всему скачанному корпусу.** Скачаны и прогрепаны целиком: README/CHANGELOG/PAPER/notes/status/JAILBREAK_CHAIN/TWITTER_POST/TODO/AI_HANDOFF всех репозиториев S1–S8, S12 (≈700 КБ текста). Шаблоны: `kernel (read|write|r/w)|kernel exploit|not demonstrated|privesc|credential`.

**Метод 2 — GitHub search API.** Запросы: `ps5+14.22`, `ps5+jailbreak+14.2`, `ps5+firmware+14.2+research`. Найдено 7 репозиториев, все разобраны:

| Репозиторий | ★ | Вердикт |
|---|---|---|
| `devravik/PS5-14.20-Jailbreak-Research` | 9 | **клон** pastawithpesto 14.10 с подменой номера прошивки и донат-адресов (§3.6) |
| `kevinisgoated24-spec/PS5-14.20-Jailbreak-Research` | 0 | заявление о 14.20 + домысел о 14.22 (§3.3) |
| `karter-captain/ps5-14.22-browser-probes` | 1 | **пробы на 14.22, без эксплойта**: «No public exploit chain for 14.22 exists», «diagnostic only» |
| `larpingvibecoder/rockstar` | 0 | **пустой репозиторий** (0 байт), описание «rockstar ps5 jailbreak 14.22» |
| `qraillife/PS5-14.22-Jailbreak` | 0 | **пустой репозиторий**, создан 2026-11-11 (сегодня) |
| `qraillife/PS5-14.22-JB` | 0 | **пустой репозиторий**, создан 2026-11-11 |
| `oniz93/ps5-14.10-research` | 3 | status-страница: «Public artefact: none», содержимого нет |

**Метод 3 — пресса.** Прочёсаны материалы про 14.20 и 14.22 (IGN ×2, GBAtemp, Push Square, Polygon, MP1st, notebookcheck, TechSpot, nextgenupdate, games.gg, onejailbreak). Ни один не сообщает о kernel R/W на 14.1x–14.2x.

**РЕЗУЛЬТАТ: ноль сообщений о полученном kernel R/W на 14.1x–14.2x.** Ни одного — ни подтверждённого, ни заявленного, ни даже кликбейтного, кроме упомянутого в §4.5 частичного прогресса S5/S4. Разрозненные «14.22 jailbreak» репозитории пустые физически (0 байт).

Единственные сообщения, которые существуют и которые надо отличать от kernel R/W:
- **userland** alias R/W + heap leak на **14.10** (S2, аппаратно) — это не ядро;
- **debug menu** на 14.10 (Gezine) — это не ядро (§4.3);
- **userland entry** (browser) на 14.20 — заявлен S5, без артефактов;
- **kernel R/W** — только как **план** (S4 stages 4–5 «[TUNE]», S5 «V701+», S1 «Open»).

Отрицательный результат подкреплён тремя независимыми авторами, каждый из которых писал бы о прогрессе с радостью: S1 («not demonstrated», 0/15), S2 («BLOCKED»), S3 («No kernel jailbreak exists on 14.20 or 14.22 either»).

---

## 5. Итоговая таблица

| Утверждение | Источник | Статус |
|---|---|---|
| 14.22 = `26.07-14.22.00`, релиз 2 ноября 2026 | S10 IGN, S9 GBAtemp, S3 | `ПОДТВЕРЖДЕНО` |
| Размер обновления 14.22 ≈ 1.267 ГБ | S10 IGN | `ПОДТВЕРЖДЕНО` (одно издание) |
| Официальные примечания Sony = «We've made some security fixes to the system software» | S9 GBAtemp (цитата), S10, nextgenupdate | `ПОДТВЕРЖДЕНО` |
| Sony назвала конкретные исправленные уязвимости в 14.22 | — | `ОПРОВЕРГНУТО` (не назвала) |
| Публичное бинарное сравнение 14.20 vs 14.22 существует | — | `НЕ ПРОВЕРЕНО` → склоняюсь к «не существует», но это отсутствие доказательства |
| 14.22 — второе обновление менее чем за две недели | S9 GBAtemp | `ПОДТВЕРЖДЕНО` |
| 14.22 патчит Canvas `getContext()` UAF; 14.20 — нет | S5 README:23,124 | `ЗАЯВЛЕНО АВТОРОМ` (0★, нет артефактов) |
| Патч в 14.22 = context-change guard для re-entrant getContext | S5 README:124 | `ЗАЯВЛЕНО АВТОРОМ`, механизм не доказан |
| AIO/Prolapse закрыт в 14.20 проверкой generation-id | S4 `aio_lapse_exploit.c` | `ЗАЯВЛЕНО АВТОРОМ` (только IDA-статика) |
| Kernel R/W на 14.10 **не** продемонстрирован | S1 README:5, S2 README, S4 README | `ПОДТВЕРЖДЕНО` (три независимых автора) |
| Kernel R/W на 14.1x–14.2x не продемонстрирован | S1, S2, S3, S4 | `ПОДТВЕРЖДЕНО` (отсутствие заявлений + прямые отрицания авторов) |
| Kernel jailbreak не существует выше 13.60 | S3 PAPER | `ПОДТВЕРЖДЕНО` (по S3; согласуется с S1/S2) |
| 13.60 — единственная jailbroken прошивка | S3 PAPER | `ПОДТВЕРЖДЕНО` (по S3) |
| На 14.10 достигнут userland alias R/W (Canvas2D) | S2 README (CONFIRMED V630) | `ПОДТВЕРЖДЕНО` автором на железе |
| На 14.10 достигнут ASLR defeat (APNG overread) | S2 README (CONFIRMED V674) | `ПОДТВЕРЖДЕНО` автором на железе |
| На 14.10 достигнут arbitrary R/W в userland | S2 README (DESIGNED) | `ОПРОВЕРГНУТО` как «достигнут» — это статус DESIGNED |
| «14.10 уже jailbroken» (Gezine) | вторичные заголовки | `ОПРОВЕРГНУТО` — это debug menu, userland |
| CVE-2026-43720 существует и является WebKit UAF | S11 NVD | `ПОДТВЕРЖДЕНО` |
| CVE-2026-43720 = именно Canvas `getContext()` reentrant UAF | S2 (авторская привязка) | `ЗАЯВЛЕНО АВТОРОМ` — в NVD описание общее (CWE-416, Safari) |
| CVE-2026-43715 существует | S11 NVD | `ПОДТВЕРЖДЕНО` |
| CSSFontFace UAF (CVE-2026-43715) на 14.10 — только DoS | S2 CHANGELOG (2026-10-18/19) | `ПОДТВЕРЖДЕНО` автором на железе |
| «FontFace UAF пойман на 14.20, wrapper становится no-op» | S5 README Phase 1 | `ЗАЯВЛЕНО АВТОРОМ`; противоречит S2 (DoS-only на 14.10) |
| «AIO DOUBLE-FREE RACE CONFIRMED, 57% hit rate» | S1 `TWITTER_POST.md` | `ОПРОВЕРГНУТО` собственными документами S1: `JAILBREAK_CHAIN_14_10.md` называет то же «socket-lifetime behavior, not memory corruption» |
| 14.20 = `26.07-14.20.00`, релиз 21 октября 2026 | IGN 2026-10-21, MP1st, onejailbreak | `ПОДТВЕРЖДЕНО` |
| Официальные примечания 14.20 = «improved the messages and usability on some screens», security НЕ упомянута | TechSpot (цитата), IGN | `ПОДТВЕРЖДЕНО` |
| «14.20 патчит недавние jailbreak/FPKG-баги» | onejailbreak (заголовок) | `СООБЩЕСТВО ПОВТОРЯЕТ` — вывод из тайминга, не из патчноутов |
| 14.00 закрыла Relapse kernel bug (`aio_multi_wait` UAF + info leak) | S1 status report §3, диапазон Relapse | `ПОДТВЕРЖДЕНО` (по S1, со ссылками на первоисточники) |
| 14.10 закрыла hypervisor bug (S3-resume) | S1 status report §3 (Sonic_Iso) | `ПОДТВЕРЖДЕНО` (по S1) |
| `devravik/PS5-14.20-Jailbreak-Research` (9★) — исследование 14.20 | — | `ОПРОВЕРГНУТО`: клон pastawithpesto 14.10, 1 коммит, подменены номер FW и донат-адреса |
| `karter-captain/ps5-14.22-browser-probes` содержит эксплойт/цепочку для 14.22 | — | `ОПРОВЕРГНУТО` автором: «No public exploit chain for 14.22 exists», «diagnostic only» |
| Репозитории `qraillife/PS5-14.22-Jailbreak`, `qraillife/PS5-14.22-JB`, `larpingvibecoder/rockstar` содержат что-либо | — | `ОПРОВЕРГНУТО`: пустые (0 байт); два созданы 2026-11-11 |
| Репозиторий S5 создан 2026-11-10, все коммиты — 38 минут | GitHub API | `ПОДТВЕРЖДЕНО` |
| Аккаунт kevinisgoated24-spec создан 2026-08-28, 0 подписчиков | GitHub API | `ПОДТВЕРЖДЕНО` |

---

## 6. Проверка живости ссылок

Все ссылки проверены `curl -L -o /dev/null -w '%{http_code}'` 2026-11-11, сначала напрямую, при неудаче — через `socks5h://127.0.0.1:10810`.

### 6.1 Репозитории (первоисточники)

| URL | HTTP | Примечание |
|---|---|---|
| https://github.com/ZigZagBoi1/PS5-14.10-Research | **200** | 484★, первичный |
| https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research | **200** | 19★, первичный |
| https://github.com/logicalpeyote777/ps5-14.00-jailbreak-research | **200** | 1★, PAPER.md |
| https://github.com/kuzibelit/PS5-14.00-14.10-Jailbreak-PoC | **200** | 50★, AIO PoC |
| https://github.com/kevinisgoated24-spec/PS5-14.20-Jailbreak-Research | **200** | 0★, заявление о 14.22 |
| https://github.com/rohbatista18-sys/ps5-jb-tracker | **200** | 4★, агрегатор |
| https://github.com/manos555555/PS5-Suite | **200** | 111★, инструмент |
| https://github.com/knutwurst/ps5-ultrapack | **200** | 72★, инструмент |
| https://github.com/devravik/PS5-14.20-Jailbreak-Research | **200** | 9★, **клон** (§3.6) |
| https://github.com/karter-captain/ps5-14.22-browser-probes | **200** | 1★, пробы 14.22 |
| https://github.com/oniz93/ps5-14.10-research | **200** | 3★, пустая status-страница |

### 6.2 Сырые файлы, на которые опираются утверждения

| URL | HTTP |
|---|---|
| https://raw.githubusercontent.com/ZigZagBoi1/PS5-14.10-Research/master/README.md | **200** |
| https://raw.githubusercontent.com/ZigZagBoi1/PS5-14.10-Research/master/JAILBREAK_CHAIN_14_10.md | **200** |
| https://raw.githubusercontent.com/pastawithpesto/PS5-14.10-Jailbreak-Research/master/README.md | **200** |
| https://raw.githubusercontent.com/pastawithpesto/PS5-14.10-Jailbreak-Research/master/CHANGELOG.md | **200** |
| https://raw.githubusercontent.com/logicalpeyote777/ps5-14.00-jailbreak-research/main/PAPER.md | **200** |
| https://raw.githubusercontent.com/kuzibelit/PS5-14.00-14.10-Jailbreak-PoC/main/aio_lapse_exploit.c | **200** |
| https://raw.githubusercontent.com/kevinisgoated24-spec/PS5-14.20-Jailbreak-Research/main/README.md | **200** |
| https://raw.githubusercontent.com/rohbatista18-sys/ps5-jb-tracker/main/src/lib/repos.ts | **200** |
| https://raw.githubusercontent.com/devravik/PS5-14.20-Jailbreak-Research/main/README.md | **200** |
| https://raw.githubusercontent.com/karter-captain/ps5-14.22-browser-probes/main/README.md | **200** |
| https://raw.githubusercontent.com/oniz93/ps5-14.10-research/master/STATUS.md | **200** |

### 6.3 Пресса, официальные и справочные

| URL | HTTP | Примечание |
|---|---|---|
| https://gbatemp.net/news/ps5-firmware-14-22-00-arrives-with-security-fixes.686166/ | **200** | цитата патчноутов 14.22 |
| https://www.ign.com/articles/sony-issues-yet-another-ps5-firmware-update-as-jailbreak-whac-a-mole-continues-ahead-of-gta-6-release | **200** | 14.22: дата, 1.267 ГБ |
| https://www.ign.com/articles/sony-issues-new-ps5-firmware-update-as-jailbreak-race-heats-up-ahead-of-gta-6-release | **200** | 14.20: 21 октября |
| https://mp1st.com/news/ps5-update-26-07-14-20-00minor-system-patch-released-security-and-gta-6 | **200** | 14.20: дата |
| https://www.techspot.com/drivers/driver/file/information/18026/ | **200** | 14.20: «improved the messages and usability» |
| https://www.notebookcheck.net/Firmware-14-20-may-stop-PS5-console-jailbreak-but-an-exploit-has-already-surfaced.1430271.0.html | **200** | 14.20: контекст |
| https://www.playstation.com/en-us/support/hardware/ps5/system-software/ | **200** | страница Sony жива, но **SPA**: текста патчноутов в HTML нет (grep «14.22» = 0), поэтому цитата взята из GBAtemp |
| https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-43720 | **200** | JSON NVD, CWE-416 |
| https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-43715 | **200** | JSON NVD, CWE-416 |
| https://www.pushsquare.com/news/2026/11/new-ps5-firmware-update-available-now-as-sony-cracks-down-on-jailbreaks | **403** | Cloudflare-bot-block, не «мертва»: URL процитирован GBAtemp как source, страница существует |
| https://www.playstation.com/en-us/support/system-updates/ps5/ | **404** | такого URL у Sony нет — первая попытка взять патчноуты была неудачной |
| https://www.psdevwiki.com/ps5/System_Software | **403** | Cloudflare («Just a moment…»), не удалось прочитать |

**Итог по живости:** все содержательные ссылки отдают 200. Единственные не-200: две Cloudflare-заглушки (403) и один несуществующий URL Sony (404), вынесенный в таблицу как зафиксированная неудача, а не как источник.

## 7. Журнал разведки

- 2026-11-11 13:48 — взят task-3 с доски, начат сбор источников, создан этот файл.
- 13:50 — метаданные 7 репозиториев через `gh api`; выяснено, кто из них первичный.
- 13:52 — скачаны README/CHANGELOG/PAPER/notes основных репозиториев; грепом найдены **все** упоминания «14.22» в корпусе (2 файла).
- 13:55 — вывод: официальный текст патчноутов + дата/размер через GBAtemp/IGN; найдены kuzibelit (S4) и oniz93 (S12) через трекер S6.
- 14:00 — NVD: проверены CVE-2026-43720 и CVE-2026-43715 — оба реальны.
- 14:10 — GitHub search: найдены devravik (клон, §3.6), karter-captain (пробы 14.22), два пустых репозитория qraillife; подтверждено отсутствие иных заявлений о kernel R/W.
- 14:12 — установлена дата 14.20 (21 октября) и её официальные примечания — только «messages and usability», без security; найдена хронология 14.00→14.10→14.20→14.22.
- 14:20 — проверены HTTP-коды всех ссылок (§6), дописаны §3.4–3.6, §4.6.

### 7.1 Что я НЕ смог проверить (честные пробелы)

1. **Текст патчноутов 14.22 напрямую с сайта Sony** — официальная страница отдаётся как SPA, текста в HTML нет; цитата взята из GBAtemp, который цитирует Sony дословно. Второй независимый путь (PlayStation.Blog) не проверялся.
2. **Бинарный дифф 14.20 vs 14.22** — не делался (это задача соседних task'ов по PUP/дизасму); именно поэтому вопрос «что закрыто» остаётся открытым по существу.
3. **Реальный статус canvas UAF на 14.20/14.22** — требует консоли на соответствующей прошивке; ни у одного публичного автора таких захватов нет.
4. **Заявления в закрытых каналах** (Discord/X) — не проверял, доступа нет. Возможно, там известно больше, но публично-проверяемого следа нет.