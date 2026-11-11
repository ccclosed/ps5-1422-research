# YARPE и LUA — userland-входы на 14.XX: что это, работают ли на 14.2x, что готовим

Статус: разведка завершена, бандл подготовлен. Машина: Linux, без root; `api.github.com`
напрямую → **403**, через `socks5h://127.0.0.1:10810` → **200**. Write-scope: `ps5jb/recon`,
`ps5jb/tools/lua-lab/bundle-1422`.

## 0. Вводная и что с ней удалось сделать

Лид передал цитату из GBAtemp «PS5 Exploit Guide» (правка 2 ноя 2026): «14.XX = No public KEX,
HV/A53 patched in 14.20, **UL ONLY (LUA/YARPE)**», WebKit в списке рабочих входов отсутствует.

`ЗАЯВЛЕНО` — саму страницу GBAtemp получить не удалось: DuckDuckGo (`html.duckduckgo.com`) отдаёт
**HTTP 202** (анти-бот), Bing по `site:gbatemp.net` — **HTTP 200**, но результаты выдачи
санитизированы (только `playstation.com`/`amazon.com`), `gh api search/code?q="No public KEX"` —
**total_count 0**. Поэтому цитата остаётся вторичным источником, а все выводы ниже опираются на
репозитории и код, которые я проверил напрямую.

Зато **суть цитаты подтверждается независимо** (§6): публичных kernel-эксплойтов выше 13.60 нет,
а оба «UL»-входа (LUA и YARPE) — это игровые save-эксплойты, не зависящие от прошивки.

## 1. Легенда

| Метка | Значение |
|---|---|
| `ПОДТВЕРЖДЕНО` | первичный источник/код прочитан в этой сессии (+ HTTP-код) |
| `ЗАЯВЛЕНО` | так написано в источнике, независимой проверки нет |
| `НЕ НАЙДЕНО` | поиск не дал результата |
| `ОПРОВЕРГНУТО` | найдено противоречие |

## 2. TL;DR

1. **YARPE = «Yet another Ren'Py PlayStation exploit»** (`Helloyunho/yarpe`, 116★, Apache-2.0,
   **archived**). Это **userland-эксплойт через сохранение игры на движке Ren'Py**: файл сейва —
   pickle, который вызывает `renpy.python.py_exec(SCRIPT)`, а скрипт делает `execfile("/saves/yarpe/main.py")`.
   `ПОДТВЕРЖДЕНО` (pickletools по файлу из релиза v3.3.0: `\x80\x02c renpy.python py_exec`).
2. **Что даёт:** код на Python **внутри процесса игры**: `sc.mem` (fake-bytearray = произвольное
   чтение/запись памяти процесса), `sc.functions.*` (вызов функций до 6 аргументов через ROP),
   `sc.syscalls.*` (syscall через ROP), файловый I/O, TCP-сервер **на 9025**. Это **не** ядро и
   **не** root: `sc.is_jailbroken` = `getuid()==0 && is_in_sandbox()==0`.
3. **FW:** смещения в YARPE не ключуются прошивкой (ключ = игра + издание PS4/PS5), т.е. дизайн
   FW-независимый; встроенный kernel-payload `lapse.py` покрывает **4.03–12.02**; форки/автолоадеры
   заявляют **«up to 13.60»**. Для 14.2x заявлений нет.
4. **Наш LUA-вектор (Hamidashi Creative Demo CUSA27390 → inject.iet → /savedata0/main.lua → TCP 9026)**
   — того же класса: загрузчик официально **«not firmware dependant, tested on PS5 Pro 10.40»**,
   и на 14.10 он **доказанно работает** (гейт 0 в исследовании ZigZagBoi). Ограничение «до 13.60»
   относится к автолоадерам (они тащат Relapse/Lapse), а не к загрузчику.
5. **Вывод:** на 14.22 оба пути — реальные кандидаты на userland-вход, и это **единственные**
   публично известные входы такого класса. Kernel R/W они не дают.
6. На ПК мы можем подготовить атаку: бандл `tools/lua-lab/bundle-1422/` (Lua-проба + отправщик +
   YARPE-скрипт + README) — проверен на компиляцию Lua 5.1 и на протокол 9026 через mock-загрузчик.

## 3. YARPE: проект, автор, что даёт

### 3.1 Идентификация

| Параметр | Значение | Источник |
|---|---|---|
| Репозиторий | `Helloyunho/yarpe` — «Yet another Ren'Py PlayStation exploit» | `gh api repos/Helloyunho/yarpe` → **200** |
| Метрики | 116★, 11 форков, язык Python, создан 2025-11-05, pushed 2026-06-26 | там же |
| Лицензия | **Apache-2.0**; репозиторий **archived** | там же |
| README | 21 900 байт, полный гайд + Python API | raw README → **200** |
| Релиз | **v3.3.0** (2026-03-19), ассеты `save.zip` (695 529 Б) и `1-1-LT1.save` (1 025 612 Б) | `gh api …/releases` → **200**; скачивание save.zip → **200**, 695 529 Б |
| Дисклеймер | «This exploit is userland exploit. Don't expect homebrew enabler(HEN) level of access» | README |

### 3.2 Как работает

`ПОДТВЕРЖДЕНО` (локальный анализ `save.zip` v3.3.0):
`save.zip` содержит `1-1-LT1.save`, `-saveindex`, набор модулей `_yarpe_*.py`, `_yarpe_elfldr-ps5.elf`
(364 424 Б), шрифт отладки и пример автолоада. Внутри `.save` — zip со `log`, `json`,
`screenshot.png`, `renpy_version` = **Ren'Py 7.4.0.0**. Файл `log` начинается с pickle-кода
`\x80\x02c renpy.python py_exec q…`, т.е. загрузка сейва выполняет `renpy.python.py_exec` с скриптом
вида `execfile("/saves/yarpe/main.py")`.

Дальше `src/main.py` (`ПОДТВЕРЖДЕНО`, локальный репозиторий):
1. поднимает `SploitCore` (`src/sc.py`): получает memory-объект, лeak'ает `FunctionType.tp_repr`
   → база исполняемого файла; `strcmp` GOT → база libc; `gettimeofday` → libkernel;
2. строит примитивы: `sc.functions.*` (вызов функции с rdi/rsi/rdx/rcx/r8/r9 через ROP-цепочку),
   `sc.syscalls.*` (номер syscall через ROP);
3. слушает **TCP 9025**, принимает **сырой Python-скрипт** (без заголовка длины), выполняет и
   возвращает лог клиенту; после JB-стадии отправляет ELF на `127.0.0.1:9021` (elfldr).

### 3.3 Что именно даёт (Python API)

| Возможность | API | Комментарий |
|---|---|---|
| Произвольное R/W **памяти процесса игры** | `sc.mem` (fake-bytearray), `utils.unsafe.readbuf/writebuf/readuint/writeuint` | `getmem()` собирает поддельный bytearray через `fakeobj`/`addrof` — классическая py2-техника |
| Вызов функций игры/libc/libkernel | `sc.functions.<name>(rdi, rsi, rdx, rcx, r8, r9)` | ROP-цепочка, до 6 аргументов |
| Syscall по имени | `sc.syscalls.<name>(...)` | тоже ROP; набор номеров в `SYSCALL` |
| Адреса | `sc.exec_addr`, `sc.libc_addr`, `sc.libkernel_addr` | выводятся из userland-leak'ов |
| Контекст | `sc.platform` (ps4/ps5), `sc.version` (FW), `sc.is_jailbroken` | `is_jailbroken = getuid()==0 && is_in_sandbox()==0` |
| Файлы, сеть | `utils.fs.*`, `utils.tcp.*` | TCP-сервер 9025, клиент 9021 |
| Форж объектов | `utils.unsafe.fakeobj(addr)` | подделка Python-объектов |

**Привилегированный контекст:** обычный процесс игры; при отсутствии JB — пользователь
`uid != 0` внутри песочницы. То есть по возможностям это ровно тот же класс, что наш Lua-загрузчик.

### 3.4 Игры

`ПОДТВЕРЖДЕНО` (README + game table автолоадера `itsPLK/ps5-yarpe-autoloader`, raw → **200**):

| Игра | ID | Издание |
|---|---|---|
| A YEAR OF SPRINGS | CUSA30428, CUSA30429, CUSA30430, CUSA30431 | PS4 |
| Arcade Spirits: The New Challengers | CUSA32096, CUSA32097 | PS4 |
| Arcade Spirits: The New Challengers | PPSA06409, PPSA06410 | **PS5** |

Смещения YARPE заданы как `GADGET_OFFSETS[game][PS4|PS5][gadget]` — **ключа прошивки нет**,
поэтому дизайн FW-независимый; но и набор игр жёстко ограничен двумя тайтлами.

### 3.5 Ограничения YARPE

1. **Только две игры** (три издания) — если их нет в PSN/на диске, вектор мёртв.
2. **Проект archived** с июня 2026, новых игр/прошивок не будет.
3. **PS5-издание сейва заменить на не-JB консоли нельзя**: README прямо пишет, что путь
   «PSN(or fake)-Activated» работает **только с PS4-играми**; для PS5-изданий нужна JB-консоль
   (garlic-savemgr). На non-JB 14.22 остаются PS4-издания через обратную совместимость.
4. **Нужен донор**: сборка сейва требует JB-PS4 (Apollo) либо Save Wizard/Discord-бот для
   расшифровки/перешифровки PS4-сейва; PSN-активация обязательна.
5. **Python 2.7** (Ren'Py 7.4): payload'ы пишутся под py2, часть API (`execfile`) py2-only.
6. **ROP-цепочки** → хрупкость, падение игры при неверных смещениях; kernel-эксплойт внутри
   (`lapse.py`) покрывает только **4.03–12.02** (проверено по ключам в файле).

### 3.6 Прошивки: что заявлено

| Источник | Заявление | Метка |
|---|---|---|
| `Helloyunho/yarpe` README | ограничений по FW не заявлено; «userland exploit» | `ЗАЯВЛЕНО` |
| `yarpe/payloads/lapse.py` | FW-ключи 4.03 … 12.02 (kernel-стадия) | `ПОДТВЕРЖДЕНО` (grep) |
| `itsPLK/ps5-yarpe-autoloader` | «Supports PS5 firmwares **up to 13.60**», требует уже взломанную PS5 | `ЗАЯВЛЕНО`, raw **200** |
| `chw602608/ps5-yarpe-autoloader` (форк, 2026-10-29) | то же: «up to 13.60» | `ЗАЯВЛЕНО`, raw **200** |
| `matem6/YarP2JB` | KEX-порт (p2jb, `cr_ref` overflow через `kqueueex`) на YARPE: **9.00–12.70**, проверено на 11.60 и 10.40 | `ЗАЯВЛЕНО`, raw **200** |
| issues `yarpe` + «14.20» | **0** результатов | `НЕ НАЙДЕНО` |
| issues `yarpe` + «14.22» | **0** результатов | `НЕ НАЙДЕНО` |

## 4. Наш LUA-вектор и его FW-границы

Напоминание (детали — `recon/lua-vector.md`): Hamidashi Creative **Demo** (CUSA27390) → `inject.iet` →
`/savedata0/main.lua` → `n0llptr/remote_lua_loader` → TCP **9026** → Lua 5.1-пробы; примитивы:
`memory.*` R/W, `make_syscall`, ROP, `thr_create(430)`, GPU mmap, дамп `mcontext` при крахе.

`ПОДТВЕРЖДЕНО`:
- upstream README: **«This loader is not firmware dependant, and has been successfully tested on
  PS5 Pro 10.40»** (raw → **200**);
- на 14.10 userland доказан: гейт 0 «Proven: Lua loader on TCP 9026, when its worker answers»
  (`JAILBREAK_CHAIN_14_10.md`, raw → **200**); ядро при этом «Open»;
- автолоадер `itsPLK/ps5-lua-autoloader` (форк загрузчика) заявляет «up to 13.60» — но это про
  **пакет** автолоада, который тянет Relapse (7.00–13.60) / Lapse (≤10.01); сам загрузчик FW-независим;
- список игр автолоадера: 18 тайтлов, включая **Hamidashi Creative Demo (CUSA27390)** и полную
  **CUSA27389**; приписка: «Demos require latest firmware to download from PSN» (raw → **200**).

Смежный LUA-путь (для полноты): **Luac0re** (`Gezine/Luac0re`, raw → **200**) — PS2-игра
*Star Wars Racer Revenge* (CUSA03474/CUSA03492), побег из ps2emu + JIT-эксплойт Lua 5.3;
README заявляет «arbitrary native userland code execution on the **latest** PS4/PS5 firmwares
without requiring a kernel exploit» (`ЗАЯВЛЕНО`, релиз 2026 года — «latest» на тот момент, не 14.22).
Там же: «Poopsploit payload requires 12.00 or lower firmware PS5».

## 5. Сопоставление

| Вектор | Что даёт | Контекст | FW (заявлено) | Доказательства | Чем проверять |
|---|---|---|---|---|---|
| **LUA (remote_lua_loader)** | Lua 5.1 в процессе игры: `memory.*` R/W, syscall по номеру, ROP, потоки, GPU mmap, дамп регистров при крахе | userland игры (Hamidashi Demo, Artemis) | «not firmware dependant», тест на 10.40; на 14.10 UL доказан | README + 14.10-исследование (гейт 0) + наш `recon/lua-vector.md` | `tools/lua-lab/` (mock 9026, lupa-гейт) + `bundle-1422/` |
| **YARPE** | Python 2.7 в процессе игры: `sc.mem` R/W, `sc.functions`, `sc.syscalls`, файлы, TCP 9025 | userland игры (Ren'Py: A YEAR OF SPRINGS, Arcade Spirits TNC) | FW-независим по дизайну; автолоадеры «up to 13.60»; KEX-часть ≤12.02/12.70 | pickle `renpy.python.py_exec` + API в `sc.py`; релиз v3.3.0 | `bundle-1422/yarpe_hello_9025.py` (py2-совместимый) |
| **Luac0re** | Lua 5.3 JIT в PS2-эмуляции, затем нативный userland | userland PS2-игры | «latest firmwares» на момент релиза; Poopsploit ≤12.00 | README + релизы | отдельный бандл (не готовили) |
| **Y2JB (YouTube)** | userland через приложение YouTube | приложение PPSA01650 | ≥4.03; версия приложения зависит от FW (01.000.003 для 4.03–12.40, 01.000.030 для 12.60+) | `Gezine/Y2JB` README, raw **200** | требует пакет YouTube нужной версии |
| **WebKit (canvas)** | heap R/W в WebProcess (по нашим данным — дважды подтверждённый bidirectional R/W на 14.10) | браузер | 14.10 — подтверждено в исследовании; на 14.22 публичной цепочки нет | `recon/webkit-vector.md`, форк TFujiwara (данные лида) | `tools/jsc-lab/`, entry-1422 (вне моего scope) |

## 6. Заявлял ли кто-то LUA/YARPE именно на 14.20/14.22

`НЕ НАЙДЕНО` — ни одного прямого заявления:
- `gh api search/issues?q=14.22+yarpe` → **total_count 0** (HTTP 200);
- `gh api search/issues?q=yarpe+"14.20"` → **0**;
- в репозиториях `Helloyunho/yarpe`, `itsPLK/ps5-yarpe-autoloader`, `itsPLK/ps5-lua-autoloader`
  упоминаний 14.x нет; все автолоадеры честно ограничивают себя 13.60;
- свежие репозитории про 14.22 — не про UL-входы: `qraillife/PS5-14.22-JB` (raw **200**:
  «This package provides a website launcher, not a jailbreak… manifest is deliberately empty»),
  `karter-captain/ps5-14.22-browser-probes` (raw **200**: «No public exploit chain for 14.22 exists»).

**Косвенное подтверждение канона** (почему «UL ONLY»): последний публичный kernel-эксплойт —
Relapse **7.00–13.60**; выше 13.60 публичного KEX нет; исследование 14.10 прямо фиксирует
«Kernel read/write on 14.10 is **not demonstrated**». Значит на 14.2x остаются только userland-входы,
и LUA/YARPE — единственные публичные инструменты такого класса с готовым кодом.

**Противоречие, которое надо держать в голове:** канон утверждает, что WebKit в списке нет, но
данные лида по форку `TFujiwara/PS5-14.10-Research` (beacon-логи 14.22, p553 «FULL BIDIRECTIONAL
R/W») говорят, что UL через браузер на 14.22 **есть**. Я это не проверял (`НЕ ПРОВЕРЕНО`), но это
означает, что «UL ONLY (LUA/YARPE)» — неполный список, а не доказательство отсутствия WebKit.

## 7. Что готовим на ПК: бандл `tools/lua-lab/bundle-1422/`

| Файл | Назначение |
|---|---|
| `probe_14xx_entry.lua` | самодостаточная Lua 5.1-проба: баннер, версия Lua, глобалы загрузчика, self-test R/W памяти, syscall getpid/getuid, маркеры `STAGE n: OK/FAIL`, финальный `=== PROBE 14XX COMPLETE ===` |
| `send_lua.py` | отправщик кадра `<u64 LE size><Lua source>` на 9026, печатает ответ, статусы транспорта |
| `yarpe_hello_9025.py` | py2-совместимый YARPE-payload для порта **9025**: баннер, `sc.version`/`sc.platform`/`sc.is_jailbroken`, self-test R/W через `utils.unsafe`, маркеры STAGE |
| `manifest.json` | метаданные бандла + sha256 файлов |
| `README.md` | порядок запуска на 14.22, что должно появиться в логе, что это доказывает и чего не доказывает |

Бандл уже собран: `ps5jb/tools/lua-lab/bundle-1422/` (`probe_14xx_entry.lua`, `send_lua.py`,
`yarpe_hello_9025.py`, `selftest.py`, `manifest.json` с sha256, `README.md`).

Проверено на ПК (`ПОДТВЕРЖДЕНО`, реальные прогоны):
- `python3 selftest.py` — проба **компилируется настоящим Lua 5.1** (lupa 2.6) и исполняется со
  стаб-загрузчиком: `STAGE 1..5: OK`, `=== PROBE 14XX COMPLETE ===`, `RESULT: PASS`;
- `python3 send_lua.py --self-test` — кадр `<u64 LE><Lua>` собирается верно (`size=15`);
- отправка пробы (4 135 Б) на mock-загрузчик 9026: кадр принят (`payload_frames=1, sizes=[4135]`),
  ответ и **кадр краха разобраны** (`SIGSEGV at 0xdeadbeef`, rip/rsp/rdi);
- success-path: локальный сервер, отвечающий маркером → `[send] completion marker seen`, exit 0;
- `yarpe_hello_9025.py` — py2-совместимый синтаксис + сверка API с `src/sc.py`, `src/utils/unsafe.py`,
  `src/main.py` репозитория yarpe (протокол 9025: сырой текст без длины).

Чего на ПК проверить **нельзя**: исполнение на консоли, работу `memory.*`/`sc.mem`, шифрование
сейва (PS4-savedata требует консоли/ключей), импорт сейва на 14.22.

## 8. Чек-лист проверки на консоли 14.22

1. **PSN-активированный профиль** на PS5 (обязательно; offline-активация не подойдёт).
2. **JB-PS4** с прошивкой **≤ прошивки PS5** (таблица Build Strings) + **Apollo Save Tool** —
   для расшифровки/перешифровки PS4-сейва под тот же hex Account ID.
3. Игра: для LUA — **Hamidashi Creative Demo (CUSA27390)**; для YARPE — **Arcade Spirits: The New
   Challengers PS4 (CUSA32096/97)** или **A YEAR OF SPRINGS PS4 (CUSA30428…)**.
   `НЕ ПРОВЕРЕНО`: доступны ли они в PSN на 14.22 (демо в своё время требовало «latest firmware»).
4. Сыграть 5 минут → экспорт сейва на USB → JB-PS4: Apollo-импорт/расшифровка → заменить файлы
   на бандл (`inject.iet` + `/savedata0/*` для LUA; `save.zip` для YARPE) → перешифровать →
   импорт на PS5.
5. Запустить игру: LUA → чёрный экран/уведомление «remote lua loader … listening on <ip>:9026»;
   YARPE → «Listening on port 9025 for stage 2 payload…».
6. С ПК: `python3 send_lua.py --host <ip> probe_14xx_entry.lua` (LUA) или отправить
   `yarpe_hello_9025.py` сырым текстом (YARPE). Успех = все `STAGE` OK и финальный маркер.
7. Что фиксировать в лог: `STAGE 0` (исполнение Lua/Python), `STAGE 1` (R/W памяти), `STAGE 2`
   (syscall), `sc.version`/`FW_VERSION`, pid/uid.

**Что это докажет:** userland-вход на 14.22 работает и даёт R/W в процессе игры.
**Что не докажет:** kernel R/W, обход песочницы, HEN-функциональность.

## 9. Ссылки и HTTP-коды

| Ссылка | Что | HTTP |
|---|---|---|
| https://github.com/Helloyunho/yarpe | YARPE, 116★, Apache-2.0, archived | **200** |
| https://raw.githubusercontent.com/Helloyunho/yarpe/main/README.md | гайд + Python API (21 900 Б) | **200** |
| https://github.com/Helloyunho/yarpe/releases/tag/v3.3.0 | релиз v3.3.0 (2026-03-19) | **200** (API) |
| https://github.com/Helloyunho/yarpe/releases/download/v3.3.0/save.zip | готовый сейв-бандл, 695 529 Б | **200** |
| https://github.com/Helloyunho/yarpe/releases/download/v3.3.0/1-1-LT1.save | единый файл сейва, 1 025 612 Б | **200** |
| https://github.com/matem6/YarP2JB | KEX-порт p2jb на YARPE, 9.00–12.70 | **200** |
| https://github.com/itsPLK/ps5-yarpe-autoloader | автолоадер YARPE «up to 13.60» + game table | **200** |
| https://github.com/itsPLK/ps5-lua-autoloader | автолоадер LUA «up to 13.60», 18 игр, CUSA27390 | **200** |
| https://raw.githubusercontent.com/itsPLK/ps5-lua-autoloader/main/SETUP.md | требования PSN+JB-PS4 | **200** |
| https://github.com/itsPLK/ps5-y2jb-autoloader | Y2JB (YouTube) автолоадер | **200** |
| https://github.com/Gezine/Y2JB | userland через приложение YouTube | **200** |
| https://github.com/Gezine/Luac0re | Lua 5.3 JIT, PS2-игра, «arbitrary userland on latest FW» | **200** |
| https://github.com/n0llptr/remote_lua_loader | наш LUA-загрузчик, «not firmware dependant» | **200** |
| https://raw.githubusercontent.com/n0llptr/remote_lua_loader/main/README.md | 18 игр + заявление о FW | **200** |
| https://github.com/ZigZagBoi1/PS5-14.10-Research | 14.10: UL доказан, kernel — нет | **200** |
| https://raw.githubusercontent.com/ZigZagBoi1/PS5-14.10-Research/master/JAILBREAK_CHAIN_14_10.md | таблица гейтов | **200** |
| https://github.com/q7c/PS4-5JB-roadmap | вторичная сводка (Lua 9.00–12.02, Y2JB и др.) | **200** |
| https://github.com/qraillife/PS5-14.22-JB | «website launcher, not a jailbreak» | **200** |
| https://github.com/karter-captain/ps5-14.22-browser-probes | «No public exploit chain for 14.22 exists» | **200** |
| https://github.com/chw602608/ps5-yarpe-autoloader | форк автолоадера (2026-10-29), «up to 13.60» | **200** |
| DuckDuckGo `html.duckduckgo.com` | поиск-попытка (анти-бот) | **202** |
| Bing `site:gbatemp.net "PS5 Exploit Guide"` | выдача санитизирована | **200**, но без результата |

## 10. YARPE как примитив для kernel-цепочки (мост `p`)

Узкий вывод, который важнее всего для jb1422: **YARPE даёт примитив без утечки адреса.** На 14.22
canvas-leak мёртв (`zero-at-free`, p691 вернул нули), а YARPE сразу даёт `sc.mem` — bytearray на всё
адресное пространство процесса игры, где индекс = `addr - 0x1000`
(`Helloyunho/yarpe/src/utils/unsafe.py: readbuf/writebuf`). Это готовый `p` для kernel-стадии.

### 10.1 Точные сигнатуры (первоисточники)

| Что | Сигнатура | Файл yarpe |
|---|---|---|
| Память | `mem[addr-0x1000 : addr-0x1000+n]` (чтение/запись), `readbuf(addr,n)`, `writebuf(addr,data)`, `readuint(addr,size)`, `writeuint(addr,value,size)` | `src/utils/unsafe.py` |
| Аллокация | `alloc(size) -> bytearray`, `addrof(obj) -> int` | `src/utils/etc.py` |
| Syscall по имени | `sc.syscalls.<name>(rdi,rsi,rdx,rcx,r8,r9) -> rax` (номер из `SYSCALL`) | `src/calls.py`, `src/constants.py` |
| Syscall по номеру | `Syscall(sc, num)(rdi..r9) -> rax` | `src/calls.py` |
| Вызов функций | `sc.functions.<name>(rdi..r9) -> rax` | `src/calls.py` |
| Подделка объектов | `fakeobj(addr)`, `fakeobj_once(addr)` | `src/utils/unsafe.py` |
| Контекст | `sc.platform` (`ps4`/`ps5`), `sc.version` (FW), `sc.is_jailbroken` | `src/sc.py` |
| TCP | `create_tcp_server(port)`, `accept_client`, `read_from_socket`, `write_to_socket` | `src/utils/tcp.py` |

### 10.2 Что реализовано в бандле

- `tools/lua-lab/bundle-1422/primitive.py` — класс `P`: `read1/4/8`, `write1/4/8`, `read/write`,
  `malloc(size,align)`, `ready() -> True`, `reason() -> "yarpe"`, `syscall(num,*args) -> int`,
  плюс hex-алиасы `read64/write64/read32/write32/add` из `tools/jb1422/js/primitive.js`.
  На ПК: `MockBackend` (словарь страниц + фейковые syscall'ы) — **23 проверки, PASS**.
- `tools/lua-lab/bundle-1422/kernel-runner.py` — бинарный TCP-сервер для JS-цепочки
  (`1 байт cmd + 8 байт addr + 8 байт len/data`, ответ зеркальный), режимы `--mock` (ПК),
  `--in-game` (внутри YARPE), `--relay` (ПК: бинарный кадр → line-протокол агента → игра).
  **20 операций read/write/syscall по TCP, PASS.**
- `tools/lua-lab/bundle-1422/yarpe_agent.py` — агент внутри YARPE (py2.7, `utils.tcp`, порт 9139);
  `agent_lua.lua` — тот же протокол через Lua-loader (9026, fd из `signal.fd_addr`).
- `tools/lua-lab/bundle-1422/bridge_server.py` — мост HTTP JSON (CORS) + line-протокол;
  `--self-test` = 12 контрактных проверок, PASS.
- `tools/lua-lab/bundle-1422/run.sh` — всё одной командой: **7/7 PASS**.

### 10.3 Что даёт и чего НЕ даёт

| Даёт | НЕ даёт |
|---|---|
| произвольное R/W памяти **процесса игры** (`sc.mem`), без утечки адреса | доступ к памяти ядра |
| `syscall(num, ...)` с возвратом rax (`Syscall(sc, num)`) | обход песочницы/`is_in_sandbox` |
| `malloc` в куче игры, `fakeobj` | root: `sc.is_jailbroken` = `getuid()==0 and is_in_sandbox()==0` → на не-jb 14.22 **False** |
| интерфейс `p`, ожидаемый `tools/jb1422/kernel/relapse1422.js` | перенос R/W между процессами (только игра; cross-process требует kernel) |
| TCP-мост для JS (бинарный и HTTP) | публичный KEX для 14.2x (последний — 13.60) |

### 10.4 Прошивки

Смещения YARPE (`src/offsets.py`) ключуются **игрой + изданием** (`GADGET_OFFSETS[game][PS4|PS5]`),
а не прошивкой: дизайн FW-независимый. Встроенный kernel-payload `payloads/lapse.py` покрывает
**4.03–12.02**; форки/автолоадеры заявляют «up to 13.60». Для 14.22 публичных подтверждений нет;
`sc.version` покажет фактическую прошивку — это и есть первый проверочный сигнал на консоли.

**Full-chain через YARPE-примитив (TCP, `demo-fullchain.py`):** стадий=13, OK=13, DEGRADED=0, FAIL=0 (done=true); для этого добавлены префетч-кэш чтения (иначе сканер стадии 5 упирался в бюджет), `p.pipeRead/p.pipeWrite` (стадия 8) и `options.triggerPayload` = `t1_aio_wait_race.elf` (стадия 13). Лог: `tools/lua-lab/bundle-1422/output/fullchain-over-tcp.log`.