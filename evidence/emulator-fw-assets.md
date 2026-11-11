# 14.22: системные модули в эмуляторах, payload-проектах и игровых дампах

**Агент:** recon-kernel-dumps (task-20 передан в чате; см. «Конфликт владения» в конце)
**Дата:** 2026-11-11 · **Машина:** Linux, root НЕТ, сеть через `socks5h://127.0.0.1:10810`
**Правило:** каждое утверждение — с командой/ссылкой; непроверенное помечено. Всё, что «лежит в релизах», проверялось
скачиванием и распаковкой (где это возможно), а не только по README.

## 0. TL;DR (для лида)

1. **Ни один эмулятор/релинкер не поставляет системные модули 14.x (и вообще прошивочные модули).**
   SharpEmu и KytyPS5: релизы — только исполняемые файлы + host-библиотеки (Vulkan/Qt/FFmpeg); README прямо отрицают
   наличие firmware-компонентов. Скачал и распаковал linux-релизы обоих: 35 и 71 файл, **ни одного `.prx`/`sce_module`/firmware**.
2. **AnyPS5 — не эмулятор, а релинкер.** Его `libs/*.prx` — **open-source реимплементации** системных библиотек
   (GCC Ubuntu 15.2, source-paths `/home/runner/work/AnyPS5/AnyPS5/core/libs/prx/...`), не Sony-бинари. Релизный tarball
   (108 818 134 B) содержит 345 файлов host-библиотек и **0 prx**; от пользователя нужен его собственный чистый ELF + `sce_module`.
3. **Payload-проекты не имеют 14.20/14.22-офсетов/модулей:** kstuff-lite — офсеты только 3.00–12.70 (45 headers),
   `kstuff.elf` 1.5 MB; etaHEN 2.5B — 2025-12-25, без 14.x; itemzflow — релизы вообще без ассетов; порты etaHEN —
   «11.00–13.60». Поиск `14.20`/`14.22` в их коде — **0**. Значит, публичного доступа к 14.2x у этих проектов нет.
4. **Публичные наборы «system modules/firmware files» под 14.x не найдены.** Что есть: архив PS5 **SDK 4.00.07**
   (4 796 080 435 B zip, на archive.org с 2025-02-03 — старый SDK); **NOR-дамп PS5** (2 097 152 B, скачан, sha256
   `f889d657…` — boot-NOR, не модули); игровые дампы (54 GB ISO, 37 GB RAR) — игры, не прошивка. Перечень проверенного — §4.
5. **Гипотеза «модули из игровых дампов» ПОДТВЕРЖДЕНА структурно** (на локальном дампе Cyberpunk 2077 v02.120):
   в `sce_module/` лежат **6 настоящих Sony-модулей** — ELF64, OSABI FreeBSD, `e_type=0xfe18` (ET_SCE_DYNAMIC), с Sony
   build-путями `W:/Build/<job>/…/Prospero_Release/*.prx`. Т.е. игры действительно несут копии системных библиотек
   эпохи своей SDK. Размеры/хэши/пути — `fw/ps5-game-modules-index-cyberpunk.txt`.
6. **НО это не то, что нужно для 14.22:** (a) в `sce_module` только userland-библиотеки (`libc`, `libScePfs`, `libSceFace`,
   `libSceJobManager`, `libSceNpCppWebApi`, `libSceFaceTracker`) — **libkernel и ядровых модулей там нет**;
   (b) «эпоха» = SDK сборки игры, а не прошивка 14.22: наш Cyberpunk v02.120 требует FW **08.60** (по локальному
   `research/cyberpunk-ps5-dump.md`) ⇒ модули ~8.60-эпохи, не 14.x; (c) свежий дамп найден (**Code Violet PPSA26528
   v01.028**, archive.org, добавлен 2026-11-10, 37 310 167 854 B) — но не скачан (37 GB RAR), возраст его модулей **не подтверждён**.
7. **Вывод:** реальных 14.2x-бинарей в публичных эмуляторах/релизах/payload нет. Единственный реалистичный путь к
   «14.x-эпохе» без прошивки — свежий игровой дамп, но он даст SDK-эпоху **userland**-модулей (не ядро, не офсеты
   14.22). Для ядра 14.22 по-прежнему нужен PUP-ключ/консоль.

## 1. Задание и метод

Задача: проверить, не поставляют ли эмуляторы/хоумбрю-проекты системные модули, извлечённые из прошивок 14.x;
проверить kstuff/etaHEN/itemzflow на 14.20/14.22-офсеты/модули; поискать наборы system modules/firmware files на
GitHub Releases/LFS/archive.org под 14.x; отдельно — гипотезу «модули из свежих игровых дампов».

Метод: `gh api` (repo/tree/releases/contents; на части запросов 2026-11-11 ~14:56 UTC GitHub отдал
`403 API rate limit exceeded` — отмечено, что именно успели проверить до этого); `curl -x socks5h` для GitHub Releases,
archive.org API, web; скачивание и распаковка релизов (`tar tzf`, `7z`); анализ локального дампа Cyberpunk
(`file`, `readelf -h/-l/-d/-p`, python-разбор program headers); `strings`; sha256.

## 2. Эмуляторы и релинкеры: что требуют и что поставляют

| Проект | Тип | Требует от пользователя | Что в релизах | Версия FW/модулей | Что даёт нам для 14.22 |
|---|---|---|---|---|---|
| **SharpEmu** (`sharpemu/sharpemu`, 6 575★, push 2026-11-10) | эмулятор PS5 (C#) | «path to a legally obtained game's `eboot.bin`» + Vulkan | релиз `v0.0.7-pulse` (2026-11-01): `sharpemu-0.0.7-pulse-linux-x64.tar.gz` 66 875 306 B (dl 808), `…-win-x64.zip` 65 025 257 B (dl 5 598); **внутри 35 файлов — только бинарь+host-библиотеки, 0 prx/firmware** | модулей/прошивки нет: «This project does not contain any copyrighted system firmware, game data, or proprietary PlayStation assets» | ничего (нужен дамп игры от пользователя) |
| **KytyPS5** (`KytyPS5/KytyPS5`, 10 996★, push 2026-11-11) | эмулятор/трансляционный слой PS5 | легально полученные файлы игры | релиз `KytyPS5-2026-11-11-bc934ef`: linux tar 42 164 911 B (dl 138), macOS zip 55 121 837 B, win zip 26 892 772 B (dl 1 337); **внутри 71 файл — Qt/icu/ffmpeg и бинарь, 0 prx/модулей** | «does not distribute games or copyrighted system software»; «External low-level emulation modules are neither required nor planned» | ничего |
| **RPCSX** (`RPCSX/rpcsx`, 2 037★) | эмулятор **PS4** (наследник RPCS3), PS5 не запускает | файлы игры/прошивки PS4 | последний релиз `rpcsx-v20231111` (2023-11-10) 3 463 369 B | PS5-модулей нет | ничего |
| **AnyPS5** (`boykopovar/AnyPS5`, 52 519★) | **релинкер** (не эмулятор): «No emulation or separate runtime process» | свой чистый ELF игры + каталоги `sce_module/`, `sce_modules/` или `prx/` (USAGE.md) | релиз `AnyPS5-Desktop-linux-x64.tar.gz` 108 818 134 B (локально `anyps5-nightly/`): 345 файлов — Flutter/ffmpeg/прочие host-libs, **0 prx**; в репо `core/libs/prx/` — **реимплементации** системных prx | FW-специфичных модулей нет | полезны только как HLE-заглушки/ABI-референс, не как 14.x-бинарн |
| **claimore22/ps5rs** (157 MB) | фреймворк анализа/эмуляции SELF/ELF/PRX (Rust) | свой каталог `roms` (модулей) — `crates/ps5-firmware/src/catalog.rs: populate_from_roms()` | модулей не поставляет | — | парсер PRX/NID может пригодиться, но образцов 14.x нет |
| **drakmor/ampr_emu** (222★, push 2026-09-06) | AMPR userland emulation (payload) | PS5 с payload-загрузчиком | релиз `0.4.2.1`: `libSceAmpr.sprx` 423 350 B (+ test-варианты) — **кастомный homebrew-модуль**, не Sony-прошивочный | — | нет (не системный модуль Sony) |
| **Swordpdf/PS5SX2** | PCSX2-порт на PS5 (homebrew) | свои файлы | модулей нет; есть `ps5/proto/.../sce_module_writer.cpp` — тулинг сборки module | — | нет |

**Проверка скачиванием (команды и вывод):**

```
$ gh api repos/sharpemu/sharpemu/releases?per_page=2
rel v0.0.7-pulse … sharpemu-0.0.7-pulse-linux-x64.tar.gz 66875306 B dl=808
$ curl -x socks5h://127.0.0.1:10810 -L -o sharpemu.tar.gz <asset>
$ tar tzf sharpemu.tar.gz | wc -l
35
$ tar tzf sharpemu.tar.gz | grep -iE 'prx|sce_module|firmware|module|elf'
(пусто)

$ gh api repos/KytyPS5/KytyPS5/releases?per_page=2
rel KytyPS5-2026-11-11-bc934ef … KytyPS5-2026-11-11-bc934ef-Linux-x86_64.tar.gz 42164911 B
$ tar tzf kyty.tar.gz | wc -l
71
$ tar tzf kyty.tar.gz | grep -iE 'prx|sce_module|firmware|module'
(пусто)
```

**AnyPS5 — доказательство, что prx в `anyps5/libs/` не Sony-модули:**

```
$ ls anyps5/libs | wc -l ; du -sh anyps5/libs
390 ; 265M
$ file anyps5/libs/libSceAgc.prx
ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, BuildID[sha1]=0872e1…, not stripped
$ readelf -p .comment anyps5/libs/libSceAgc.prx
  [ 0]  GCC: (Ubuntu 15.2.0-16ubuntu1) 15.2.0
$ strings anyps5/libs/libkernel.prx | grep -E '/home/runner|FreeBSD 11'
/home/runner/work/AnyPS5/AnyPS5/core/libs/prx/libkernel/File/src/Open.cpp
FreeBSD 11.4-RELEASE
$ readelf -d anyps5/libs/libSceAgc.prx | head -6   # NEEDED: libSceAgcDriver.prx, libkernel.prx, libc.prx, libstdc++.so.6, libm.so.6
```

Это **открытые реимплементации**, собранные GCC/Ubuntu из исходников AnyPS5 — не извлечённые Sony-модули.

## 3. Payload-проекты: есть ли 14.20/14.22-офсеты/модули

| Проект | Релизы/ассеты | Поддержка FW | 14.20/14.22? | Проверка |
|---|---|---|---|---|
| `drakmor/kstuff-lite` | 8 релизов, единственный asset — `kstuff.elf` (1 524 280–1 558 040 B, dl до 15 742) | в репо `prosper0gdb/offsets/*.h` — 45 файлов 3.00–**12.70** (`offset_list.txt`, `struct offset_table`); 13.x/14.x нет | **нет** | `search/code?q=14.20 repo:drakmor/kstuff-lite` → 0; `14.22` → 0 |
| `ps5-payload-dev/kstuff` | `Payload.zip` 79 014 B / 1 969 088 B | репозиторий последний раз push 2025-01-25 — до эпохи 14.x | **нет** | `gh api repos/ps5-payload-dev/kstuff` |
| `etaHEN/etaHEN` (840★, push 2026-05-04) | релиз `2.5B` (2025-12-25) — `etaHEN-2.5B.bin` 4 678 728 B (dl 93 182) | README/CHANGELOG без 14.x | **нет** | `search/code?q=14.22 repo:etaHEN/etaHEN` → 0; `13.60` → 0 |
| `LightningMods/Itemzflow` (390★, push 2026-10-21) | релизы `1.08` (2026-05-31), `PS5-1.09` (2025-03-28) — **assets=0** (бинарников в релизах нет) | — | **нет** | `search/code?q=14.22 repo:LightningMods/Itemzflow` → 0; `releases[].assets` = 0 |
| `ydd33048/etahen-11.00-13.60` (неофиц. порт) | — | README: «port of etaHEN 2.5B … firmware versions 11.00 through 13.60» | **нет** (13.60 — максимум) | README §FAQ |
| `ArkSama/PS5-Lapy-JB-Daemon` | — | описание: «Multi-firmware (3.00 to 12.00)» | **нет** | repo search |

**Вывод §3:** ни один публичный payload-проект не содержит модулей/офсетов 14.20/14.22. Если бы кто-то имел доступ
к 14.2x, первым следом были бы per-FW offsets-заголовки или kstuff/etaHEN с поддержкой 14.20+; их нет (по состоянию
на 2026-11-11).

## 4. Публичные наборы «system modules / firmware files» под 14.x

| Источник | Что это | Размер/дата | Проверка | 14.x? |
|---|---|---|---|---|
| archive.org `ps5_sdk_4.00.07` (он же `ps5-sdk-4-00-07`) | **PS5 SDK 4.00.07** (архив, внутри SDK-модули 4.00-эпохи) | zip 4 796 080 435 B; added 2025-02-03 | `archive.org/metadata/ps5_sdk_4.00.07` → 9 files | **нет** (4.00) |
| archive.org `PS5_Unity_Fake` | «фейковый» Unity-слой PS5 | 3 832 126 633 B | metadata | нет |
| GitHub `ahlbornjagon/PS5_Dump` | **публичный NOR-дамп PS5** (`PS5_nor.bin`) | 2 097 152 B (2 MB); repo push 2026-06-19 | скачан: sha256 `f889d657402bbe429e3111f1bb8470fabb1a8031306181fc11437e1b7df9f8bc`; strings: `SONY COMPUTER ENTERTAINMENT INC.`; entropy 4.995 | **не модули** (boot NOR); версия FW не определена |
| archive.org `gbfr-dump` | дамп игры PS5 (GranBlue Fantasy: Relink) | `PS5VOLUME.iso` 54 022 963 200 B; added 2025-02-09 | metadata | игра, не прошивка |
| archive.org `codeviolet-ppsa-26528-usa-game-v-01.028-ps-5` | дамп игры PS5 (Code Violet PPSA26528 v01.028) | `[SuperPSX]-Code.Violet-PPSA26528-USA-Game-(v01.028)-PS5.rar` 37 310 167 854 B; added **2026-11-10** | metadata (5 файлов, один RAR) | игра, не прошивка; **самый свежий найденный дамп** |
| archive.org `ep-9000-ppsa-21567-…`, `barbie.-project.-friendship-ppsa-17465…` | свежие дампы игр (2026-09/10), ExFAT-образы | 38 722 459 683 B; 3 407 928 000 B | advancedsearch по `identifer:*-ppsa-*` | игры |
| GitHub Releases/LFS: поиск `ps5 modules`, `ps5 firmware dump`, `ps5 modules` repos | наборов модулей нет | — | repo search: `buzzer-re/PS5_kldload` (loader), `drakmor/dlc_emu` (заглушки DLC), `SvenGDK/SharpProspero` (SDK-заголовки), `claimore22/ps5rs` (парсер) | — | нет |

**Итог §4:** наборов именно **системных модулей 14.x** на GitHub Releases/LFS/archive.org не найдено.
Единственный «прошивочный» публичный артефакт — NOR-дамп (2 MB, boot flash) и старый SDK 4.00.07.

## 5. Гипотеза «модули из игровых дампов» — проверка

### 5.1 Что реально лежит в игровом дампе (локальный Cyberpunk 2077, PPSA04029, v02.120.000, exFAT)

`sce_module/` (и `modules/`) содержит настоящие PS5-модули: `file` → `ELF 64-bit LSB x86-64, version 1 (FreeBSD)`,
`readelf -h` → `OS/ABI: UNIX - FreeBSD`, `Тип: Специфичный для ОС: 0xfe18` (= **ET_SCE_DYNAMIC**), 14 program headers,
section headers отсутствуют. Из program headers извлекаются два SCE-специфичных сегмента:

- `PT 0x6fffff00` — SCE comment: `"PATH"+тип`, длина, затем **Sony build path** вида
  `W:/Build/J01625764/sys/internal/usermode/src/libc/Prospero_Release/libc.prx`;
- `PT 0x6fffff01` — SCE version: содержит имя модуля (`08 "libc"`, `08 "libScePfs"`, …).

Полный индекс (имена, размеры, sha256, build paths, version-сегменты) — **`fw/ps5-game-modules-index-cyberpunk.txt`**.
Сводка:

| Модуль | Размер, B | Sony build path (из PT_SCE_COMMENT) |
|---|---:|---|
| `libc.prx` | 1 352 554 | `W:/Build/J01625764/sys/internal/usermode/src/libc/Prospero_Release/libc.prx` |
| `libScePfs.prx` | 1 381 071 | `W:/Build/J01625764/sys/internal/usermode/src/libpfs/Prospero_Release/libScePfs.prx` |
| `libSceJobManager.prx` | 113 062 | `W:/Build/J01625764/sys/internal/usermode/src/job/job_manager/Prospero_Release/libSceJobManager.prx` |
| `libSceFace.prx` | 342 144 | `W:/Build/J01625795/opt/internal/face/libface-src/build-Orbis/Prospero_Release/libSceFace.prx` |
| `libSceFaceTracker.prx` | 2 644 167 | `W:/Build/J01625795/opt/internal/face/libface-src/build-Orbis/Prospero_Release/libSceFaceTracker.prx` |
| `libSceNpCppWebApi.prx` | 7 491 911 | `W:/Build/J01625767/vsh/sdk/target/sce_module/libSceNpCppWebApi.prx` |
| `libREDGalaxy64.prx` (игровой, CDPR) | 8 664 094 | `C:/GitLabRunner/builds/…/galaxy-core/Output/libREDGalaxy64.prx` |

Хэши (sha256, первые 64 бита): `libc` `e851775b…`, `libScePfs` `fbbf2217…`, `libSceJobManager` `2efd5736…`,
`libSceFace` `54b175c1…`, `libSceFaceTracker` `c2e80590…`, `libSceNpCppWebApi` `a0435b75…` — полностью в файле индекса.

**Вывод 5.1:** игры действительно **несут копии системных userland-библиотек Sony**, собранных из внутренних build-джобов
Sony (`Prospero_Release`). Гипотеза в этой части верна.

### 5.2 Какая это «эпоха» и что это НЕ даёт

- Наш дамп — Cyberpunk **v02.120.000**; по локальному `research/cyberpunk-ps5-dump.md` (список патчей игры) он требует
  **FW 08.60.00.04** ⇒ модули из его `sce_module` — ~8.60-эпохи, а не 14.x.
- В `sce_module` **нет `libkernel.prx`** и ядровых модулей: игры не поставляют kernel/системные модули прошивки.
  Следовательно, из игрового дампа **нельзя** получить 14.x-ядро, sysent-офсеты и т.п. — только userland-библиотеки SDK-эпохи.
- «Эпоха» модулей = **SDK, которым собрана игра**, а не версия прошивки консоли (игра может требовать FW 13.x, будучи
  собранной SDK 12.x/13.x). Поэтому даже самый свежий дамп даст «SDK-эпоху», а не 14.22.

### 5.3 Свежие дампы: что найдено и почему не проверено

- Найден **самый свежий** публичный дамп PS5: `codeviolet-ppsa-26528-usa-game-v-01.028-ps-5` на archive.org,
  added **2026-11-10T23:10:24Z**, один файл RAR **37 310 167 854 B**. Метаданные: title «Code Violet PPSA 26528 v01.028»,
  5 файлов (RAR + torrent + служебные). **Не скачан** (37 GB, RAR — выборочно распаковать `sce_module` нельзя без
  полной загрузки; Range-запросы к RAR не дают список файлов без полного архива).
- Меньшие свежие дампы (`barbie.-project.-friendship-ppsa-17465…`, 3.4 GB ExFAT; `ep-9000-ppsa-21567…`, 38.7 GB)
  — это игры 2024–2025, их SDK-эпоха заведомо ниже 14.x; также не скачивались.
- **Как проверить возраст модулей, когда дамп будет доступен** (скрипт/шаги):
  1. распаковать образ и найти `eboot.bin` + `sce_module/*.prx`;
  2. для каждого `.prx`: `readelf -h` (`e_type=0xfe18`, OSABI FreeBSD), затем распарсить program headers:
     `PT 0x6fffff00` → Sony build-path (job id `J0xxxxxxx`), `PT 0x6fffff01` → имя модуля;
  3. sha256 каждого модуля и сравнение с нашим индексом (`fw/ps5-game-modules-index-cyberpunk.txt`) и с будущими
     индексами из других дампов: совпадение хэшей = та же сборка; разные build-пути/даты = другая эпоха;
  4. для датировки: build-job id Sony (`J01625xxx` в нашем дампе) + сравнение с известными образами (SDK 4.00.07,
     дампы разных лет); прямых дат в SCE-сегментах нет.
  5. полезность: если игра собрана SDK 14.x — её `sce_module` даст userland-модули ~14.x для ABI/импорт-анализа;
     **ядра там всё равно не будет**.

## 6. Что это даёт для 14.22 (честная оценка)

| Вопрос | Ответ |
|---|---|
| Есть ли в публичных эмуляторах/релизах модули 14.x? | **Нет** (§2 — релизы проверены распаковкой) |
| Есть ли у payload-проектов 14.20/14.22-офсеты/модули? | **Нет** (§3) |
| Есть ли публичный набор system modules 14.x (GitHub/LFS/archive.org)? | **Нет** (§4); есть NOR-дамп 2 MB и SDK 4.00.07 |
| Даёт ли игровой дамп 14.x-модули? | Только **userland-библиотеки SDK-эпохи**; ядра нет; нужен дамп игры, собранной SDK 14.x, и он ещё не проверен (§5.3) |
| Что реально нужно для 14.22 | PUP-ключ (security processor) → расшифровка PUP → system-модули/ядро; либо консоль с 14.2x (нет публичных) |

## 7. Ограничения / что не проверено

1. GitHub API в ~14:56 UTC 2026-11-11 вернул `403 API rate limit exceeded` на часть запросов — не все repo-выборки
   удалось повторить; проверенное перечислено в §3–4, непроверенное не утверждается.
2. Свежий дамп Code Violet (37 GB RAR) не скачан — его модули не извлечены и не датированы; вывод о «14.x-эпохе»
   остаётся гипотезой (§5.3 даёт процедуру проверки).
3. SDK 4.00.07 (4.79 GB zip) не скачивался — состав подтверждён только метаданными archive.org (9 файлов, размер).
4. NOR-дамп (2 MB) скачан и опознан как NOR Sony, но версия FW/содержимое не разбирались (вне задачи).
5. Модули из дампа игры — copyrighted Sony-компоненты; в `fw/` сохранён только **индекс метаданных** и NOR-дамп
   (публичный артефакт), сами модули остались в локальном дампе игры.

## 8. Источники (проверено 2026-11-11)

| Источник | URL/доступ | Результат |
|---|---|---|
| SharpEmu repo/releases | `gh api repos/sharpemu/sharpemu` + releases; asset через `curl -x socks5h` | 6 575★, push 2026-11-10; v0.0.7-pulse (2026-11-01), 2 ассета; скачан linux tar 66 875 306 B → 35 файлов, 0 prx |
| KytyPS5 repo/releases | `gh api repos/KytyPS5/KytyPS5` + releases | 10 996★, push 2026-11-11; linux tar 42 164 911 B → 71 файл, 0 prx |
| RPCSX | `gh api repos/RPCSX/rpcsx` | 2 037★; последний релиз rpcsx-v20231111 (2023) 3 463 369 B |
| AnyPS5 | `gh api repos/boykopovar/AnyPS5/...` (README/USAGE); локальные `anyps5/libs`, `anyps5-nightly/*.tar.gz` | релинкер; libs — реимплементации (GCC Ubuntu 15.2); релиз 108 818 134 B → 345 файлов, 0 prx |
| kstuff/kstuff-lite | `gh api repos/drakmor/kstuff-lite` + releases + tree; `ps5-payload-dev/kstuff` | offsets 3.00–12.70; kstuff.elf 1.52–1.56 MB; push 2025-01-25 у ps5-payload-dev |
| etaHEN / itemzflow / порты | `gh api repos/etaHEN/etaHEN`, `LightningMods/Itemzflow`, `ydd33048/etahen-11.00-13.60`, `ArkSama/PS5-Lapy-JB-Daemon` | etaHEN 2.5B (2025-12-25) 4 678 728 B; itemzflow релизы без ассетов; порты 11.00–13.60 / 3.00–12.00 |
| archive.org PS5 SDK | https://archive.org/metadata/ps5_sdk_4.00.07 | zip 4 796 080 435 B, added 2025-02-03, 9 файлов |
| archive.org game dumps | `gbfr-dump`, `codeviolet-ppsa-26528-usa-game-v-01.028-ps-5` | 54 022 963 200 B (2025-02-09); 37 310 167 854 B (added 2026-11-10) |
| NOR-дамп | `gh api repos/ahlbornjagon/PS5_Dump`; raw `PS5_nor.bin` | 2 097 152 B; sha256 `f889d657…`; строки `SONY COMPUTER ENTERTAINMENT INC.` |
| Локальный дамп игры | `games/cyberpunk/anyps5-run/{sce_module,modules}/*.prx` | 6 Sony-модулей + 1 игровой; индексы/хэши/build paths — `fw/ps5-game-modules-index-cyberpunk.txt` |
| Локальный research | `research/cyberpunk-ps5-dump.md` (патчи/требуемые FW), `PS5-emulators-2026-11.md` | Cyberpunk 02.120 → FW 08.60; классификация эмуляторов |

**Артефакты в `fw/`:**
- `fw/PS5-nor-ahlbornjagon.bin` — публичный NOR-дамп PS5, 2 097 152 B, sha256 `f889d657402bbe429e3111f1bb8470fabb1a8031306181fc11437e1b7df9f8bc`;
- `fw/ps5-game-modules-index-cyberpunk.txt` — индекс игровых модулей: имена, размеры, sha256, SCE version, Sony build paths.

## 9. Легенда достоверности

| Метка | Значение |
|---|---|
| `ПОДТВЕРЖДЕНО` | скачано/распаковано/посчитан хэш/выведено командой в этой сессии |
| `НЕ ПРОВЕРЕНО` | не скачивалось/не распаковывалось (указано, почему) |
| `ИСТОЧНИК ТРЕТЬЕЙ СТОРОНЫ` | README/метаданные/описание без независимой проверки |
| `НЕ НАЙДЕНО` | искали и не нашли (перечень запросов — §3–4, §8) |

---

**Конфликт владения:** task-20 на доске **owned by `recon-relapse`** (status in_progress, revision 2) — claim с моей стороны
невозможен (`team_task_get` → «owned by another member»). Артефакт подготовлен мной в рамках чат-задания лида; при
необходимости — переоткрыть/переназначить task-20 на `recon-kernel-dumps` для фиксации выполнения.
---

## 11. Апдейт 2026-11-11 18:30: свежий дамп Code Violet — РЕАЛЬНЫЕ модули добыты (SDK 11.00)

Продолжение §5: вместо скачивания 37 ГБ RAR заголовки прочитаны по HTTP Range, нужные файлы извлечены
(sparse-образ + `bsdtar`), SELF развёрнуты. Результат — в `fw/game-modules/code-violet-ppsa26528-v01028/`:

- 5 Sony userland-модулей (`libc.prx` 1 911 850 B, `libSceFontGsm.prx` 289 539, `libSceJobManager.prx` 114 422,
  `libSceNpCppWebApi.prx` 7 971 719, `libScePfs.prx` 1 381 143) + их decrypted-SELF копии `.prxbak`
  + `param.json` + `package.manifest` + `eboot.bin`; хэши и build-пути — `MODULES.md` в каталоге.
- `param.json`: `sdkVersion = 0x1100000000000000` (**SDK 11.00**), `requiredSystemSoftwareVersion = 0x1270000000000000`
  (**FW 12.70**). **Это не 14.x.** Build-пути: `W:/Build/J03547016` (sys) и `J03547048` (vsh).
- Для сравнения: Cyberpunk v02.120 (FW 08.60) — `W:/Build/J01625764`, libc 1 352 554 B (+41% у Code Violet),
  плюс в Code Violet появился новый модуль `libSceFontGsm`. Калибровка: больший J-номер = новее эпоха.
- **`libkernel`/`libSceSysCore`/`libSceWebKit` в игровых дампах отсутствуют** — игры несут только userland-библиотеки,
  которые линкуют; syscall-таблица из них не извлекается (см. `recon/kernel-code-14x.md` §4).
- Инструменты: `fw/game-modules/tools/ffpfsc_remote.py`, `ffpfsc_get.py`, `module_meta.py`; для exFAT-дампов —
  ранее `exfat_remote.py`. Каталог свежих дампов и критерий отбора (`param.json` → FW ≥ 13.x/14.x) —
  `recon/fresh-dumps-2026.md`.

Подробности: `recon/kernel-code-14x.md` (разбор модулей и сравнение эпох), `recon/system-files-14x.md`
(почему системных файлов 14.x публично нет).
