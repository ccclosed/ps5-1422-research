# Свежие PS5-дампы (осень 2026): каталог, форматы, что добыто

**Агент:** recon-kernel-dumps · **дата:** 2026-11-11 · **связано:** task-28, task-33, `kernel-code-14x.md`
**Правило:** каждый факт — с URL/командой; скачанное — с хэшем. Скачиваниями «целиком» не злоупотребляем:
`.ffpfsc`/`.exfat` читаются по HTTP Range, RAR — заголовки по Range + sparse-образ.

## 0. TL;DR

1. На archive.org найдено **17** PS5-дампов с датой добавления ≥ 2026-09-01 и размером ≥ 1 ГБ (запрос:
   `advancedsearch.php?q=identifier:(*ppsa*) AND addeddate:[2026-09-01 TO *] AND item_size:[1000000000 TO *]`).
2. Форматы дампов: **`.ffpfsc`** (PFS→PFSC-контейнер, zlib-блоки по 64 КиБ) — большинство свежих;
   **`.exfat`** (сырой образ) — часть; **`.rar`** (single-archive) — Code Violet/RetroArch; **`.7z`** — пара items.
3. **Code Violet (2026-11-10) разобран полностью** (RAR по Range): добыты 5 Sony-модулей, `param.json` = **SDK 11.00 /
   required FW 12.70** (не 14.x). См. `kernel-code-14x.md` §2–§5.
4. **EA FC 27 (2026-10-18, .ffpfsc 91.4 ГБ)** — контейнер разобран, корень получен; `param.json`/`sce_module`
   добываются точечно (см. `kernel-code-14x.md` §7). Это быстрее, чем 91 ГБ: таблица блоков 25,7 МБ + точечные блоки.
5. **Дампы с `access-restricted-item: true`** (пример: 007 First Light, `ppsa-11386`, 87 ГБ exFAT) скачать нельзя без
   аккаунта Internet Archive — учитывать при планировании.
6. **Критерий «наш дамп»** — не дата загрузки, а `sce_sys/param.json`:
   `requiredSystemSoftwareVersion ≥ 0x1260…` (13.x) / `0x1400…` (14.x). Дата добавления на archive.org ≠ дата мастеринга
   (Code Violet добавлен 2026-11-10, но мастеринг — июнь 2026, SDK 11.00).

## 1. Каталог кандидатов (archive.org; проверено 2026-11-11)

| identifier | title | добавлен | размер, B | файл(ы) / формат | restricted? | sce_module | статус |
|---|---|---|---:|---|---|---|---|
| `codeviolet-ppsa-26528-usa-game-v-01.028-ps-5` | Code Violet PPSA26528 v01.028 | 2026-11-10 | 37 310 167 854 | `[SuperPSX]-….rar` (RAR5) | нет | **есть** (5 модулей + param.json) | **разобран**: SDK 11.00 / FW 12.70 |
| `ppsa-34015-ea-sports-fc-27` | PPSA 34015 EA SPORTS FC 27 | 2026-10-18 | 91 438 579 712 | `PPSA34015 EA SPORTS FC 27.ffpfsc` | нет | **есть** (в корне) | ffpfsc-декодер работает; param.json добывается |
| `ppsa-03671-marvels-wolverine` | PPSA 03671 Marvel's Wolverine | 2026-10-18 | 111 629 041 664 | `.ffpfsc` | нет | вероятно есть | не проверялся |
| `ppsa-23012-call-of-duty-modern-warfare-2` | PPSA 23012 CoD MW2 | 2026-10-17/18 | 123 639 496 704 | `.ffpfsc` | нет | вероятно есть | не проверялся |
| `ppsa-07570-mortal-kombat-1` | PPSA 07570 Mortal Kombat 1 | 2026-10-18 | 159 179 079 680 | `.ffpfsc` | нет | вероятно есть | не проверялся |
| `ppsa-03977-the-witcher-3-wild-hunt-complete-edition` | PPSA 03977 Witcher 3 CE | 2026-10-18 | 85 298 642 944 | `.ffpfsc` | нет | вероятно есть | не проверялся |
| `ppsa-15304-metal-gear-solid-snake-eater` | PPSA 15304 MGS Δ | 2026-10-15 | 99 673 702 400 | `.ffpfsc` | нет | вероятно есть | не проверялся |
| `ppsa-16384-the-dark-pictures-anthology-directive-8020` | PPSA 16384 Directive 8020 | 2026-10-14 | 38 014 222 336 | `.ffpfsc` (+torrent) | нет | вероятно есть | не проверялся |
| `ppsa-94424` | PPSA 94424 (Bloody Roar 2, PS1-classic wrapper) | 2026-10-09 | 1 257 242 624 | `PPSA94424.exfat` | нет | ?, мелкий образ | не проверялся (exfat_remote готов) |
| `ppsa-11386` | PPSA 11386 (007 First Light v01.018) | 2026-10-05 | 87 323 312 128 | `PPSA11386.exfat` | **ДА** (`access-restricted-item: true`) | неизвестно | **недоступен без IA-аккаунта** |
| `ppsa-36543-compressed.-7z` | PPSA 36543 / 25063 (7z) | 2026-10-05 | 14 582 601 832 | `PPSA36543-Compressed.7z` 9 086 105 515 + `PPSA25063-Compressed_2.7z` 5 496 403 436 | нет | ? | не проверялся |
| `ppsa-99169` | PS5 RetroArch PPSA 99169 | 2026-10-08 | 12 684 134 220 | `PPSA99169.rar` | нет | ? | не проверялся |
| `ppsa-11132` | PPSA 11132 (Ape Academy 2) | 2026-08-11 | 1 200 619 520 | `PPSA11132.exfat` | нет | ? | не проверялся |
| `barbie.-project.-friendship-ppsa-17465…` | Barbie Project Friendship v1.002 | 2026-10-05 | 3 407 928 000 | exFAT (в имени) | нет | ? | старая игра (2024) — не приоритет |
| `ep-9000-ppsa-21567-…` | EP 9000 PPSA 21567 (v0118) | 2026-09-23 | 38 722 459 683 | exFAT/образ | нет | ? | не проверялся |
| `ep-9000-ppsa-05684-…` | EP 9000 PPSA 05684 (Uncharted 4) | 2026-09-20 | 87 629 337 172 | exFAT/образ | нет | ? | не проверялся |
| `horizon-zero-dawn-remastered-ppsa-13428` | Horizon Zero Dawn Remastered | 2026-09-07 | 91 147 490 047 | образ | нет | ? | не проверялся |

Примечание: `item_size` в advancedsearch местами `None`; размеры выше — из `archive.org/metadata/<id>` (`files[].size`).

## 2. Форматы и инструменты чтения (без полного скачивания)

| Формат | Что это | Инструмент | Состояние |
|---|---|---|---|
| `.ffpfsc` | PFS-образ (блоки 0–5 = метаданные) с одним файлом внутри; файл = **PFSC-контейнер**: 0x30-байтный заголовок, таблица `n+1` u64-смещений на `+0x400`, блоки по 64 КиБ (zlib, если короче блока; иначе raw) | `tools/ffpfsc_remote.py` (наш, Range+zlib), `tools/ffpfsc_get.py` (точечные пути), `tools/ffpfsc_fast.py` (листинг) | **работает** (EA FC 27: листинг корня, 206 запросов/27 МБ/181 с) |
| `.exfat` | сырой exFAT-образ игры | `tools/exfat_remote.py` (команда) | работает (использовался для PPSA94424: загружен VBR) |
| `.rar` (RAR5) | один архив; файлы сжимаются/хранятся | RAR5-walker по Range (свой) + sparse-образ + `bsdtar` (libarchive) | **работает** (Code Violet: 84 записи, извлечены только `sce_module/*` и `param.json`) |
| `.7z` | 7z-архив | пока не реализовано (7z-заголовок LZMA-сжатый, нужен py7zr/декодер) | не начато |
| `.iso` | ISO9660 образ | не реализовано | не начато |

**Почему не качаем целиком:** Code Violet — 37,3 ГБ, `.ffpfsc` EA FC 27 — 91,4 ГБ при 195,7 ГиБ внутри.
Range-подход даёт нужные 5–30 МБ.

## 3. Что уже добыто

- **Code Violet PPSA26528 v01.028** → `fw/game-modules/code-violet-ppsa26528-v01028/` (5 модулей + SELF + param.json
  + package.manifest + eboot.bin, см. `MODULES.md`): SDK 11.00, required FW 12.70, build-пути `W:/Build/J03547016`/`J03547048`.
- **EA FC 27** → корень внутреннего образа получен (`eboot.bin` 330 649 402 B, `sce_module/`, `fakelib/`, `sce_sys/`,
  `Patch/`, `Data/`, `Scripts/`, `Engine.*.prx`); `sce_sys/param.json` — в процессе.
- Инструменты — `fw/game-modules/tools/` (см. `kernel-code-14x.md` §6).

## 4. Как проверить следующий дамп (порядок)

1. `archive.org/metadata/<id>` → имя и размер файла; проверить `access-restricted-item`.
2. **Сначала `sce_sys/param.json`** (не `sce_module`):
   - `.ffpfsc`: `python3 tools/ffpfsc_get.py --url <node-url> --size <bytes> --path /sce_sys/param.json`
   - `.exfat`: `python3 tools/exfat_remote.py --url … --size … --find param.json`
3. Декодировать `sdkVersion`/`requiredSystemSoftwareVersion` (BCD-пары; `PkgToolBox/PS5_Game_Info.py`, Kyty).
   Если FW < 13.x — дамп не наш (не тратить время).
4. Если FW ≥ 13.x/14.x — вытащить `sce_module/*` и прогнать `tools/module_meta.py` (sha256, PT_SCE_COMMENT, SCE_VERSION).
5. Помнить: `libkernel`/`libSceSysCore`/`libSceWebKit` в игровых дампах **не будет** — только userland-библиотеки.

## 5. Источники (проверено 2026-11-11)

- archive.org advancedsearch (запрос из §0) и `archive.org/metadata/<id>` для каждого пункта таблицы.
- Локальные копии метаданных: `fw/game-modules/evidence/meta-*.json` (от команды), `ps5-catalog.json` (Jamzi94/catalog-V2).
- Соседние отчёты: `recon/kernel-code-14x.md`, `recon/kernel-surface-1422.md`, `recon/1422-status.md`,
  `recon/alternative-1422-sources.md`, `recon/dump-1422-hunt.md`.