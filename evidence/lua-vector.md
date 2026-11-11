# Вектор входа №2: Lua 5.1 через сохранение игры (TCP 9026)

Статус: в работе (разведка). Машина: Linux, без root, сеть через `socks5h://127.0.0.1:10810`.
Рабочая папка: `/home/oleg/Документы/ps5semulator/ps5jb`. Write-scope: `ps5jb/recon/`.

Задача: разобрать второй вектор входа — Lua 5.1 через сохранение игры (порт 9026), который
использует исследование PS5-14.10 (ZigZagBoi1/PS5-14.10-Research и связанная экосистема).

## 0. Легенда достоверности

| Метка | Значение |
|---|---|
| `ПОДТВЕРЖДЕНО` | есть первичный источник, прочитанный в этой сессии (файл/страница + HTTP-код) |
| `ЗАЯВЛЕНО АВТОРОМ` | так написано в репозитории/доке, независимой проверки нет |
| `НЕ ПОДТВЕРЖДЕНО` | источник не найден / не удалось получить |
| `ОПРОВЕРГНУТО` | найдено прямое противоречие |

Каждое утверждение сопровождается ссылкой и, где применимо, HTTP-кодом.

## 1. TL;DR

Вектор — **не эксплойт памяти, а легитимная функциональность игры**: демо японской визуальной
новеллы **Hamidashi Creative Demo** (CUSA27390; движок Artemis, встроенный Lua 5.1) при загрузке
сохранения исполняет
`inject.iet`, который через `include` подтягивает `/savedata0/main.lua`; этот файл — **remote lua
loader** (`n0llptr/remote_lua_loader`, ранее `shahrilnet`), поднимающий TCP-листенер на **9026**.
Дальше с ПК по TCP приходят Lua-скрипты, и в процессе игры появляется userland-примитив:
`memory.*` R/W, `make_syscall(N)`, ROP-цепочки, GPU mmap, редирект CClosure, потоки.

Итог исследования 14.10 (по их же README): userland-код **доказан**, а **kernel R/W — нет**;
поверхность ядра через Lua-загрузчик объявлена «исчерпанной» (0 указателей ядра на ~400
syscall и ~32M ioctl). То есть вектор даёт **userland R/W в адресном пространстве игры**, а не
jb сам по себе.

Практически неповторимо «в один клик»: нужна **free demo на японском PSN** (нужен JP-аккаунт),
**взломанная PS4** с Apollo Save Tool для расшифровки/перешифровки сейва под **совпадающий PSN
Account ID**, и сам payload — набор `.lua` + ELF. Payload при этом **полностью публичен**
(`n0llptr/remote_lua_loader`, а копия в `artifacts/` исследования байт-в-байт совпадает с ним).
Само исследование — **CC BY-NC 4.0**, у загрузчика лицензии нет вообще.

## 2. Журнал разведки

Сеть: прямой доступ к `api.github.com` — **HTTP 403** (DPI), через `-x socks5h://127.0.0.1:10810`
— **HTTP 200**. Все запросы ниже — через прокси. `gh api` авторизован (аккаунт `ccclosed`),
лимит 5000/ч; у неавторизованного curl осталось 1/60 — не использовать.

| # | Действие | Результат |
|---|---|---|
| 1 | `gh api repos/ZigZagBoi1/PS5-14.10-Research` | **HTTP 200**; 484★, 60 форков, ветка `master`, создан 2026-10-16, pushed 2026-11-10; лицензия в API — `other/NOASSERTION` |
| 2 | `gh api .../git/trees/master?recursive=1` | **HTTP 200**, дерево получено (3301 probe, 264 дока) |
| 3 | `git clone --depth 1` в `recon/_src/lua/zz` | **успешно**, 458 МБ |
| 4 | `grep -r 9026` | 550 файлов — вектор пронизывает весь репозиторий |
| 5 | `curl api.github.com` напрямую / через прокси | **403** / **200** |
| 6 | `codeload.github.com` tarball `n0llptr/remote_lua_loader` | **HTTP 200**, 505 662 Б, 59 файлов (есть `savedata/`, `SETUP.md`) |
| 7 | md5-сверка `artifacts/…_CUSA27390_savedata/` с upstream `savedata/` | **все 7 проверенных файлов идентичны** — это копия upstream |
| 8 | `raw.githubusercontent.com` (5 URL) | все **HTTP 200** — ссылки в §7 стабильны |
| 9 | `python3 tools/check_lua_syntax.py` (после установки `lupa==2.6`) | **`Compiled 2931 ... failures=0`** |
| 10 | `python3 tools/verify_offline.py` | **`Ran 356 tests in 4.728s — OK (skipped=3)`** |
| 11 | mock-загрузчик на `127.0.0.1:9026` + upstream `send_lua.py` | кадр 8-Б LE (size=20), команда `0xFFFFFFFF`+1, кадр краха `0x13371337` разобран (`SIGSEGV at 0xdeadbeef` + mcontext) |

## 3. Источники

Скачано в `recon/_src/lua/zz/` (shallow clone публичного репо, `master`, 458 МБ):

- `README.md` (42 КБ) — обзор, два вектора входа, лицензия
- `docs/USERLAND_ENTRY.md` (256 строк) — **полная инструкция по вектору** (игра, сейв, шаги)
- `tools/send_probe.py` (543 строки) — ПК-отправщик проб по TCP 9026
- `tools/README.md` — протокол (8-байтный LE-префикс + исходник Lua)
- `JAILBREAK_CHAIN_14_10.md` — карта гейтов: что доказано, что нет
- `CHANGELOG.md` (23 КБ), `CLAUDE.md` (106 КБ) — фазы и история
- `artifacts/usb_pre_reset_2026-10-20/PS4/APOLLO/1cabafc7_CUSA27390_savedata/` — **опубликованный
  payload сейва**: `inject.iet`, `main.lua`, 20+ `.lua` библиотек, `elfldr.elf`, `ps5-elfldr.elf`,
  `ps5-kexp.bin`, `saveg.dat`, `sce_sys/`
- `probes/` — 2930 Lua-проб; `results/` — 3468 захватов

Внешние репозитории (проверены `gh api`, HTTP 200):

- `n0llptr/remote_lua_loader` — 458★, язык Lua, ветка `main`, pushed 2026-06-20,
  `license.spdx_id = none` (файла лицензии GitHub не видит)
- `hammer-83/ps5-jar-loader` — 159★, Java, pushed 2025-03-09, лицензия не заявлена;
  оттуда взяты kernel-оффсеты (только fw 1.00–10.01)

## 4. Ответы на вопросы задачи

### 4.1 Какая игра и какое сохранение нужны

`ПОДТВЕРЖДЕНО` (`docs/USERLAND_ENTRY.md`, `README.md`):

- **Игра: Hamidashi Creative** (はみだしクリエイティブ), разработчик **Madosoft**, японская
  visual novel на движке **Artemis** со встроенным Lua-интерпретатором.
  В продаже — **бесплатная демо-версия в японском PSN** (нужен JP-аккаунт).
- **Почему именно она:** в `/savedata0/offsets.lua` есть таблицы ROP-гаджетов для 14 игр на
  Artemis; наблюдаемый стек-пивот (`pop rsp; ret`) по адресу eboot+0x9A2 совпадает ровно с
  записью `hamidashi_creative` и ни с одной другой. Игра определяется по последнему нибблу
  `luaB_auxwrap` в eboot (+ CRC32 первых 0xFF байт libc как тай-брейкер).
- **Title ID: CUSA27390** — в пробах и доках он назван «the running title»
  (`docs/GIC_COMMAND_14_10.md:91`, `probes/phase17_new_vectors/475c_gic_payload_shape.lua:7`),
  и именно так названа папка сейва в `artifacts/`: `1cabafc7_CUSA27390_savedata`.
- **Сейв:** обычное сохранение игры, созданное на PS5 (играть ~5 минут). В нём:
  `saveg.dat` (magic `BOWS`, далее zlib), `sce_sys/` (`param.sfo`, `keystone`, `icon0.png`).
  Loader запускается из **`inject.iet`** — скрипт Artemis:
  `[save file="save9999.dat"]` → `[lua] function include_lua(engine) e = engine;
  e:include("/savedata0/main.lua") end [/lua]` → `[calllua function="include_lua"]`.
  Т.е. игра сама, «легально», исполняет Lua из папки сохранения.

**Полная цепочка сейва** (`docs/USERLAND_ENTRY.md`, там же ASCII-схема):

```
PS5: играем, создаём сейв → USB-экспорт (запомнить hex PSN Account ID из имени папки сейва)
  → взломанная PS4: Apollo активирует профиль с ТЕМ ЖЕ Account ID
     → импорт сейва, расшифровка Apollo → USB → ПК: вкладываем Lua loader
  → USB → PS4: перешифровка сейва под тот же профиль → USB → PS5: импорт сейва
  → запуск игры → чёрный экран + уведомление «remote lua loader / listening on <ip>:9026»
  → ПК: send_probe.py шлёт Lua-скрипты по LAN
```

Шаги 1–12 пронумерованы в доке; ключевое ограничение выделено красным: **Account ID должен
совпадать, иначе PS5 отвергает сейв**. То есть **нужна jailbroken PS4** (для Apollo и
расшифровки/перешифровки savedata) — это не «только PS5».

### 4.2 Что даёт загрузчик

`ЗАЯВЛЕНО АВТОРОМ` (`README.md`, раздел «Entry Vector 1»; `docs/USERLAND_ENTRY.md`):

| Возможность | Что это | Ограничение |
|---|---|---|
| `memory.*` API | `read_byte/word/dword/qword`, `write_*`, `alloc` — произвольное R/W **памяти процесса игры** | userland, не ядро |
| `make_syscall(N)` | вызов syscall по номеру в обход Lua-side фильтра | «kernel restrictions still apply» |
| `syscall.resolve()` | штатный, **отфильтрованный** путь | фильтр на стороне Lua |
| GPU mmap | большие куски heap R/W: 256+ страниц, **без guard-страниц** | только GPU-апертура |
| CClosure redirect | подмена указателя функции в CClosure → вызов существующих C-функций Lua | «arbitrary target/ABI and ROP support remain unverified» |
| `native.fcall_with_rax` | вызов произвольной userland-функции с контролем RAX | userland |
| `thr_create(430)`, `thr_new(455)` | потоки с полным контролем регистров / доставкой аргументов | fork/rfork заблокированы |
| Child-thread ROP | syscall с 5 аргументами из дочернего потока через native-гаджеты | — |
| ROP-цепочка | структура 0x300 байт: `fn_addr`, 6 слотов аргументов, stack pivot | нужны гаджеты из eboot |
| Per-connection ASLR | **новый процесс на каждое TCP-соединение** | все адреса выводятся заново |

Их собственные выводы (`JAILBREAK_CHAIN_14_10.md`, гейты):

- Gate 0 «userland entry» — **Proven**: «Lua loader on TCP 9026, when its worker answers».
- Gates 1–6 (kernel bug → primitive → адрес → kernel R/W → привилегии → полный jb) — **Open**.
- Прямая цитата: «Userland heap R/W, SROP syscall invocation, and CClosure redirection do not by
  themselves satisfy either gate» — т.е. сам автор не считает это ядром.

### 4.3 Ограничения

`ЗАЯВЛЕНО АВТОРОМ` (`README.md` «Key Constraints», `docs/USERLAND_ENTRY.md`,
`JAILBREAK_CHAIN_14_10.md`, `docs/DEAD_ENDS.md`):

- **W^X**: `mmap(RWX)` даёт RW; `mprotect(EXEC)` всегда падает.
- **XOM**: `.text` системных библиотек execute-only — чтение падает; eboot — RX.
- **SMAP**: нет таймингового различия mapped/unmapped kernel VA.
- **Нет указателей ядра**: ~400 syscall, ~32M ioctl, все известные info-leak — ноль.
- **Нет оффсетов ядра для 14.10**: `kernel_offset.lua` покрывает только fw 1.00–10.01
  (из `hammer-83/ps5-jar-loader`). `kernel.lua` содержит технику kernel R/W через IPv6
  pktopts-overlap, но ей нужны валидная база ядра + оффсеты символов.
- **KASLR**: база образа восстанавливается «oracle по fault-коду» (присутствие, не содержимое),
  но чтения памяти нет.
- **/dev/dmem0** — только GPU-апертура, не CPU/ядро.
- **Порты**: `bind()` возвращает -1 для портов ≥ 40000; годятся 1024–32767 (9026 попадает).
- **Чёрный экран**: пока loader работает, игра висит на чёрном экране (?), т.е. консоль занята.
- **Jailbroken PS4 обязательна** на этапе сборки сейва (см. 4.1).

### 4.4 Что нужно, чтобы повторить на 14.2x

`НЕ ПОДТВЕРЖДЕНО` — в клонированном репозитории **нет** заявлений о работе Lua-вектора на
14.20/14.22; упоминания `14.2x` относятся к Canvas2D UAF (WebKit) и к проверкам, а не к Lua.
Что известно и что из этого следует:

1. **Совместимость игры/прошивки не привязана к 14.10**: вектор использует легальную
   функциональность Artemis+Lua и сохранение. Ограничение — запускается ли Hamidashi Creative
   (демо) на 14.2x и создаётся ли сейв. `НЕ ПРОВЕРЕНО` — ни в репо, ни в issues это не описано.
2. **Нужен payload, собранный под конкретную игру**: `offsets.lua` (гаджеты eboot конкретной
   сборки) и `kernel_offset.lua` (символы ядра). Для 14.2x оффсетов ядра **нет** (проект сам
   пишет, что для 14.10 их тоже нет). Для userland-этапа (`memory.*`, syscall через libc)
   оффсеты ядра не нужны — нужны только гаджеты eboot.
3. **Ограничение на стороне Account ID** — не зависит от версии прошивки, зависит от наличия
   jailbroken PS4.
4. Если цель — только userland R/W (не jb), то на 14.2x теоретически достаточно повторить
   пайплайн сейва и иметь рабочий `main.lua`+`inject.iet`; это `ГИПОТЕЗА`, не подтверждено.

### 4.5 Что можно проверить на ПК, и что именно тогда проверяется

Всё ниже **реально прогнано на этой машине** (Linux, без root, Python 3.14), а не пересказ доков.
Проверки собраны в запускаемую лабораторию `ps5jb/tools/lua-lab/` — см. §9 (одна команда `./run.sh`).

**A. Протокол загрузчика — проверен против mock-сервера.** Поднят локальный сервер
`127.0.0.1:9026` (скрипт в `/tmp/mock_loader.py`), к нему отправлен upstream-отправщик
`n0llptr/remote_lua_loader:payloads/send_lua.py`:

- путь payload: сервер принял **8-байтный LE размер = 20** и ровно 20 байт
  `print("hello 9026")\n` — подтверждает кадрирование «длина qword + сырой Lua»;
- путь команды: `--enable-signal-handler` → сервер увидел **`command_magic = 0xFFFFFFFF`**
  плюс **1 байт команды = 1** (enable);
- путь краха: сервер вернул кадр `0x13371337` + 16 байт (код сигнала, адрес) + `0x100` байт
  `mcontext`, и `send_lua.py` **корректно распечатал** `SIGSEGV at 0x00000000deadbeef` и все
  регистры (rdi/rsi/…/rip/rsp). Значит ПК-парсер аварийных дампов рабочий.

Что именно проверяется: формат кадра, длина-префикс, командный канал, декодер `mcontext`.
Что НЕ проверяется: поведение настоящего загрузчика (нормальный ответ, реальные регистры).

**B. Компиляция Lua 5.1 (lupa) — проверено на всём корпусе.** Поставлен `lupa==2.6`
(wheel cp314 manylinux x86_64, `https://files.pythonhosted.org/.../lupa-2.6-cp314-cp314-manylinux2014_x86_64...whl`,
**HTTP 200**, 2 073 458 Б), `from lupa.lua51 import LuaRuntime` → `_VERSION = "Lua 5.1"`.
Запуск `python3 tools/check_lua_syntax.py`:

```
Compiled 2931 Lua 5.1 probe sources; failures=0
```

(в README заявлено 2930 — расхождение на 1 файл, инвентарь дрейфует). Проверяется: пробы
компилируются как Lua 5.1 (нет `goto`/`continue`, нет BOM-ошибок). Не проверяется: семантика
выполнения на консоли.

**C. Исполнение Lua со стабами — возможно, но только для логики.** В репо есть тесты, которые
грузят пробу в `lupa` и подменяют `memory`/`syscall`/`native` заглушками
(`tools/test_probe58e.py`, `tools/test_bounds_fuzz.py`, `tools/test_syscall_isolation_sweep.py`;
опциональные зависимости — `requirements-offline-optional.txt`: `lupa==2.6`, `capstone==5.0.6`).
Так проверяются: порядок вызовов, форма аргументов, записи в контролируемые буферы, разбор вывода.
Так НЕ проверяются: реальные адреса, XOM/W^X/SMAP, поведение ядра.

**D. Hardware-free регрессия — зелёная.** `python3 tools/verify_offline.py` →
**`Ran 356 tests in 4.728s — OK (skipped=3)`**, только stdlib. Проверяет: артефакты, декодеры,
пиннинг evidence, инварианты документов.

**E. Разбор сохранения — частично.** `saveg.dat` имеет magic `BOWS`, далее zlib-поток
(`78 da …`); рядом `sce_sys/param.sfo`, `keystone`, `icon0.png`. На ПК разбирается контейнер и
структура папки — **шифрование PS4-savedata на ПК не проверяется** (нужна консоль/ключи).

**F. ELF-payload'ы — только заголовки.** Прогнано локально:
`elfldr.elf` → `ELF 64-bit LSB pie executable, x86-64, stripped`;
`ps5-elfldr.elf` → то же (`readelf -h`: ELF64, DYN/PIE, Little-endian);
`ps5-kexp.bin` (18 КБ) → сырой blob, `file` угадывает «DOS executable (COM)», т.е. это не ELF;
`saveg.dat` → `data` (внутри `BOWS`+zlib). Проверяются тип/архитектура/класс; запуск и
поведение — нет.

**Итог по ПК-проверяемости:** воспроизводимы транспорт, Lua 5.1-компиляция, логика проб со
стабами, оффлайн-регрессия, разбор сейва-контейнера и ELF. **Ни одна из этих проверок не
доказывает работоспособность на 14.2x** — она подтверждает только, что инструментарий и payload
внутренне согласованы.

### 4.6 Уточнения, найденные при сверке источников (правки к первой версии)

- `CUSA27390` — это **Hamidashi Creative Demo**, а не полная игра; полная — `CUSA27389`
  (`https://raw.githubusercontent.com/n0llptr/remote_lua_loader/main/README.md`, **HTTP 200**).
  В списке загрузчика 18 игр; у демо помечено «Requires latest firmware to download from PSN».
- `kernel_offset.lua` в опубликованном payload покрывает **1.00–12.02** (есть `10.50/10.70/10.71`,
  `11.00/11.02`, `11.50/11.52`, `12.00/12.02`), а не «1.00–10.01», как написано в
  `docs/USERLAND_ENTRY.md`. Для неизвестной прошивки `get_ps5_kernel_offset()` возвращает пустую
  таблицу (совпадения по `FW_VERSION` нет) → kernel-примитивы недоступны.
- `make_syscall(N)` — **не API загрузчика**, а локальный helper внутри проб: копия таблицы
  `syscall.pipe` с подменой `syscall_no` (1516 проб определяют его сами). Точная формулировка
  README «Syscall invocation via `make_syscall(N)` (bypasses Lua-side filter)» — неточна:
  фильтруется `syscall.resolve()` (именованная таблица), а прямой номер идёт через тот же
  trampoline.
- «CClosure function pointer redirect» из README **опровергнут их же документами**: проба 80x
  показала `lua_closure=true` для `syscall.pipe.__call`, т.е. это Lua-замыкание, а не C-указатель
  (`docs/2026-10-19-loader-reset.md`); сам README в таблице добавляет «arbitrary target/ABI and
  ROP support remain unverified».
- Опубликованный в `artifacts/` payload **байт-в-байт совпадает** с upstream: md5 `main.lua`
  `5793a9fd…`, `syscall.lua` `1416a67f…`, `memory.lua` `eef1254f…`, `kernel.lua` `f46b6daf…`,
  `offsets.lua` `4c92925f…`, `inject.iet` `cd1afea4…`, `saveg.dat` `672cf215…` — одинаковы в обоих
  архивах. То есть это не «их форк», а копия публичного проекта.
- Протокол точнее, чем в `tools/README.md`: помимо 8-байтной длины есть (1) `maxsize = 500*1024`,
  причём условие строгое `size < maxsize`; (2) `command_magic = 0xffffffff` + 1 байт команды
  (0 — выключить signal handler, 1 — включить); (3) кадр краха `0x13371337` + 16 Б + `0x100` Б
  `mcontext`; (4) лог пишется в `/av_contents/content_tmp/loader_log.txt`.

## 5. Публичный код, инструкции, лицензии

- **Публичный код: да, полностью для userland-вектора.**
  - `artifacts/usb_pre_reset_2026-10-20/PS4/APOLLO/1cabafc7_CUSA27390_savedata/` — **полный
    payload сейва**: `inject.iet` (171 Б), `main.lua` (9 КБ), `lua.lua`, `syscall.lua`,
    `memory.lua`, `kernel.lua`, `kernel_offset.lua`, `offsets.lua` (46 КБ), `ropchain.lua`,
    `native.lua`, `thread.lua`, `gpu.lua`, `struct.lua`, `uint64.lua`, `bit32.lua`, `hash.lua`,
    `signal.lua`, `misc.lua`, `globals.lua`, `kernel_patches_ps4.lua`, `saveg.dat`,
    `elfldr.elf` (364 КБ), `ps5-elfldr.elf` (397 КБ), `ps5-kexp.bin` (18 КБ), `sce_sys/`.
  - Первоисточник: `https://github.com/n0llptr/remote_lua_loader` — **HTTP 200** (tarball
    `codeload.github.com`, **HTTP 200**, 505 662 Б, 59 файлов: `savedata/`, `payloads/`,
    `SETUP.md`, `UPDATE.md`, `README.md`). `shahrilnet/remote_lua_loader` редиректит сюда.
  - `payloads/` upstream: `send_lua.py`, `umtx.lua` (kernel-эксплойт umtx), `test_cases/`
    (threading, signal/SIGSEGV/SIGBUS, notification popup).
  - `probes/` — 2931 Lua-файл; `results/` — 3468 захватов; `tools/` — все ПК-инструменты.
- **Инструкции**: `SETUP.md` (2 варианта: JB-PS4+диск и цепочка через PS5; требования:
  **PSN-активированная PS5** + **JB PS4 с прошивкой ≤ прошивки PS5**, Apollo fake-activate
  аккаунта по hex Account ID; альтернатива — OffAct); `UPDATE.md` (обновление через
  Playstation-5-Save-Mounter); `docs/USERLAND_ENTRY.md` (их версия шагов);
  `JAILBREAK_CHAIN_14_10.md`; `docs/2026-10-19-loader-reset.md`.
- **Лицензии**:
  - ZigZagBoi1/PS5-14.10-Research — **CC BY-NC 4.0** (`LICENSE` raw, **HTTP 200**;
    © 2026 Marwan Mohamed / @ZiggyVall). Атрибуция обязательна, **коммерческое использование
    запрещено**. GitHub API отдаёт `other/NOASSERTION` (не SPDX-текст).
  - `n0llptr/remote_lua_loader` — **файла лицензии нет вообще** (проверены все 59 файлов
    tarball'а); `license.spdx_id = none`. Юридически «все права сохранены».
  - `Gezine/ArtemisLuaLoader` (первооткрыватель техники) — **GPL-3.0**, репозиторий **archived**,
    99★, «Run arbitrary lua script from savedata» (**HTTP 200**).
  - `hammer-83/ps5-jar-loader` — лицензия не заявлена (Java, другой вектор — BD-J; оттуда
    kernel-оффсеты для 1.00–10.01).
  - ⚠ Открытый юридический вопрос: `n0llptr`-загрузчик указывает в credits Gezine «for sharing the
    vulnerable games & ideas», но опубликован без GPL-3.0-файла. Код это или идея — не проверено.
- **Что НЕ опубликовано (зафиксировано явно)**: рабочие kernel-примитивы для 14.10. Прямая
  цитата `JAILBREAK_CHAIN_14_10.md`: «Candidate kernel findings and any working primitive stay in
  the **private staging** remote until the evidence and disclosure decision are settled». Также не
  опубликованы: kernel-оффсеты 14.10/14.2x, дампы ядра 14.10, приватные пробы с
  kernel-примитивами, и (по их словам) «a complete exploit is not demonstrated».

## 6. Открытые вопросы / пробелы

- `НЕ ПРОВЕРЕНО`: запускается ли Hamidashi Creative Demo (CUSA27390) на 14.2x и совпадает ли
  title ID/сейв-путь. Ни в README, ни в docs, ни в issues этого нет.
- `НЕ ПОДТВЕРЖДЕНО`: существует ли «private staging» remote и что в нём.
- `НЕ ПРОВЕРЕНО`: сохранилась ли совместимость PS4-savedata import на 14.2x (ограничение
  «PS4 fw ≤ PS5 fw» задано таблицей Build Strings, которую я не открывал).
- `НЕ ПРОВЕРЕНО`: нужен ли именно JP-аккаунт для демо на 14.2x (в SETUP сказано «requires latest
  firmware to download from PSN» — на момент публикации это была 10.40).
- Нет ПК-эмулятора загрузчика: чтобы гонять пробы без консоли, нужен свой стаб-харнесс
  (lupa + `memory`/`syscall`/`native` заглушки); в репо он есть только точечно (отдельные тесты).

## 7. Ссылки и HTTP-коды (проверено в этой сессии)

Все запросы — через `socks5h://127.0.0.1:10810`; прямой доступ к `api.github.com` даёт **403**.

| Ссылка | Что это | HTTP |
|---|---|---|
| https://api.github.com/repos/ZigZagBoi1/PS5-14.10-Research | репозиторий исследования (484★, 60 форков, master, created 2026-10-16) | **200** |
| https://github.com/ZigZagBoi1/PS5-14.10-Research | веб-страница | **200** |
| https://raw.githubusercontent.com/ZigZagBoi1/PS5-14.10-Research/master/README.md | обзор, 2 вектора, лицензия | **200** |
| https://raw.githubusercontent.com/ZigZagBoi1/PS5-14.10-Research/master/docs/USERLAND_ENTRY.md | полный setup-гайд вектора | **200** |
| https://raw.githubusercontent.com/ZigZagBoi1/PS5-14.10-Research/master/JAILBREAK_CHAIN_14_10.md | карта гейтов + правило публикации | **200** |
| https://raw.githubusercontent.com/ZigZagBoi1/PS5-14.10-Research/master/LICENSE | CC BY-NC 4.0 | **200** |
| https://github.com/n0llptr/remote_lua_loader | загрузчик (ex-shahrilnet), 458★, Lua, pushed 2026-06-20 | **200** |
| https://raw.githubusercontent.com/n0llptr/remote_lua_loader/main/README.md | список 18 игр, «not firmware dependant, tested on PS5 Pro 10.40» | **200** |
| https://raw.githubusercontent.com/n0llptr/remote_lua_loader/main/SETUP.md | требования и шаги (PS4+Apollo, PS5 import) | **200** |
| https://codeload.github.com/n0llptr/remote_lua_loader/tar.gz/refs/heads/main | tarball 505 662 Б, 59 файлов | **200** |
| https://github.com/Gezine/ArtemisLuaLoader | первооткрыватель техники, GPL-3.0, archived, 99★ | **200** |
| https://github.com/hammer-83/ps5-jar-loader | kernel-оффсеты 1.00–10.01 (BD-J вектор) | **200** |
| https://github.com/n0llptr/Playstation-5-Save-Mounter | обновление сейва без PS4 (метод 1) | **200** (API) |
| https://pypi.org/pypi/lupa/2.6/json | Lua 5.1 в Python (для ПК-проверок) | **200** |
| https://files.pythonhosted.org/packages/23/c6/a04e9cef7c052717fcb28fb63b3824802488f688391895b618e39be0f684/lupa-2.6-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl | wheel 2 073 458 Б, ставится без root | **200** |
| https://www.psdevwiki.com/ps5/Build_Strings | таблица «PS4 fw ≤ PS5 fw» (ссылка из SETUP.md) | **не открывал** |
| https://github.com/ps5-payload-dev/websrv/releases | OffAct (офлайн-активация) | **не открывал** |
| https://psn.flipscreen.games/ | получить PSN Account ID | **не открывал** |
| https://memorycorruption.net/posts/rce-lua-factorio/ | блог с идеями Lua-примитивов (credits) | **не открывал** |

Локальные артефакты: `recon/_src/lua/zz/` (shallow clone ZigZagBoi1, 458 МБ),
`recon/_src/lua/rll/` (upstream tarball, распакован), `/tmp/mock_loader.py` (mock-сервер 9026),
`/tmp/t.lua`, `/tmp/rll/payloads/send_lua.py`.

## 8. Итог для лида (одним абзацем)

Вектор Lua-9026 — это **легальная загрузка Lua из папки сохранения** в Hamidashi Creative Demo
(CUSA27390, движок Artemis) через `inject.iet` → `remote_lua_loader`; даёт **userland-примитив в
процессе игры** (R/W памяти, syscall по номеру, ROP, потоки, GPU mmap, дамп `mcontext` при крахе),
но **kernel R/W на 14.10 не даёт** — у авторов нет ни оффсетов ядра (таблица кончается на 12.02),
ни info-leak'а, и они сами объявляют поверхность ядра через Lua исчерпанной. Повторение требует
**PSN-активированной PS5 + взломанной PS4** (Apollo, совпадающий Account ID) и JP-аккаунта для
демо; загрузчик заявлен как firmware-independent (проверен на 10.40), но про 14.2x данных нет.
Код и payload **полностью публичны** (байт-в-байт upstream), лицензии: CC BY-NC 4.0 у исследования
и **отсутствие лицензии** у самого загрузчика. На ПК воспроизводимы протокол (mock-сервер),
компиляция 2931 пробы Lua 5.1 (0 ошибок), 356 оффлайн-тестов — но это не доказывает работу на 14.2x.

## 9. Как запускать лабораторию (`ps5jb/tools/lua-lab/`)

Проверки из §4.5 собраны в исполняемый каталог — консоль не нужна, root не нужен.

| Файл | Что делает |
|---|---|
| `mock_loader.py` | mock-сервер порта 9026: принимает `<u64 LE size><Lua source>` и `<u64 LE 0xFFFFFFFF><u8 cmd>`, отвергает кадр ≥ 500 KiB, отвечает баннером и синтетическим кадром краха `<0x13371337><signal,addr><0x100 mcontext>` |
| `lab_client.py` | шлёт четыре вида кадров и **разбирает** ответ: текст, кадр краха, 29 полей `mcontext` |
| `protocol_selftest.py` | поднимает mock на свободном порту (9026, если свободен) и прогоняет 6 проверок |
| `syntax_lua51.py` | компилирует `probes/**/*.lua` настоящим Lua 5.1 (lupa), без исполнения |
| `offline_suite.py` | обёртка над `tools/verify_offline.py` чекаута исследователей |
| `run.sh` | шаги 0–3 + сводная таблица; `--install-deps`, `--repo PATH`, `--port N`; лог в `output/run.log` |
| `README.md` | назначение, зависимости, границы применимости |

Запуск одной командой:

```bash
cd ps5jb/tools/lua-lab && ./run.sh
```

**Реальный вывод `./run.sh`** (2026-11-11 17:11:50 MSK):

```
PS5 Lua vector lab — 2026-11-11 17:11:50 MSK
  lab:  /home/oleg/Документы/ps5semulator/ps5jb/tools/lua-lab
  repo: /home/oleg/Документы/ps5semulator/ps5jb/recon/_src/lua/zz
  python: Python 3.14.7

=== 0. environment
python 3.14.7
lupa: OK (Lua 5.1)
--- environment: PASS (python+lupa ready)

=== 1. mock loader 9026 (frames 8-byte LE / 0xFFFFFFFF+cmd / 0x13371337+mcontext)
# protocol self-test: mock loader on 127.0.0.1:9026
[PASS] payload frame: 8-byte LE size + Lua source echoed :: text='[mock-loader] hello from fake loader'
[PASS] crash frame 0x13371337 decoded (signal + fault address) :: SIGSEGV at 0xdeadbeef; rip=0x800012345 rsp=0x7fff0000a000 rdi=0x1122334455667788
[PASS] mcontext register block parsed (29 fields) :: fields=29 cs=0x3b trapno=14
[PASS] command frame 0xFFFFFFFF + cmd=1  :: reply='command: Enabled signal handler'
[PASS] command frame 0xFFFFFFFF + cmd=0  :: reply='command: Disabled signal handler'
[PASS] oversized frame rejected (maxsize 500 KiB, strict <) :: reply='error: lua code exceed maxsize (given 512000 maxsize 512000)'
# mock stats: payload_frames=1 command_frames=2 oversized_frames=1 sizes=[28]
# protocol checks: 6/6 passed
RESULT: PASS
--- protocol self-test: PASS (mock 9026 answered all frame kinds)

=== 2. Lua 5.1 syntax gate over probes/ (lupa)
# probes root: /home/oleg/Документы/ps5semulator/ps5jb/recon/_src/lua/zz/probes
Compiled 2931 Lua 5.1 probe sources; failures=0
# elapsed 0.52s
RESULT: PASS
--- lua 5.1 syntax: PASS (2931 probes compiled, 0 failures)

=== 3. hardware-free suite (checkout tools/verify_offline.py)
# checkout: /home/oleg/Документы/ps5semulator/ps5jb/recon/_src/lua/zz
  test_no_uncorrected_corruption_claims_remain (tools.test_webkit_false_positive.RetractionTests.test_no_uncorrected_corruption_claims_remain) ... ok
  
  ----------------------------------------------------------------------
  Ran 356 tests in 4.949s
  
  OK (skipped=3)
Ran 356 tests, exit=0, wall=5.06s, status=OK
RESULT: PASS
--- offline suite: PASS (Ran 356 tests, exit=0, wall=5.06s, status=OK)

==================== SUMMARY ====================
environment            PASS  python+lupa ready  [40 ms]
protocol self-test     PASS  mock 9026 answered all frame kinds  [44 ms]
lua 5.1 syntax         PASS  2931 probes compiled, 0 failures  [570 ms]
offline suite          PASS  Ran 356 tests, exit=0, wall=5.06s, status=OK  [5101 ms]
------------------------------------------------
steps: 4, failed: 0
RESULT: ALL PASS
```

Ручной режим (сервер и клиент по отдельности, порт 9027):

```bash
python3 mock_loader.py --port 9027 --once &
python3 lab_client.py 127.0.0.1 9027
```

```
[PASS] payload frame: 8-byte LE size + Lua source echoed :: text='[mock-loader] hello from fake loader'
[PASS] crash frame 0x13371337 decoded (signal + fault address) :: SIGSEGV at 0xdeadbeef; rip=0x800012345 rsp=0x7fff0000a000 rdi=0x1122334455667788
[PASS] mcontext register block parsed (29 fields) :: fields=29 cs=0x3b trapno=14
[PASS] command frame 0xFFFFFFFF + cmd=1  :: reply='command: Enabled signal handler'
[PASS] command frame 0xFFFFFFFF + cmd=0  :: reply='command: Disabled signal handler'
[PASS] oversized frame rejected (maxsize 500 KiB, strict <) :: reply='error: lua code exceed maxsize (given 512000 maxsize 512000)'
# client checks: 6/6 passed
```

**Что лаборатория доказывает:** кадрирование (8-байтная LE-длина), командный канал
`0xFFFFFFFF`+cmd, разбор кадра краха `0x13371337` и полного `mcontext` (29 полей), совместимость
всего корпуса проб с Lua 5.1, зелёный offline-набор исследователей (356 тестов).

**Чего НЕ доказывает:** работу на реальной PS5 и на 14.2x. `memory.*`, `make_syscall`,
`thr_create`, GPU mmap, CClosure/native-вызовы и kernel R/W живут только в PS5-ELF и требуют
консоли; mock-сервер их не эмулирует — он проверяет транспорт и декодеры, а не примитивы.
