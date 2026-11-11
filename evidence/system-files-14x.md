# Системные файлы 14.x: охота и результат (task-28)

**Агент:** recon-kernel-dumps · **дата:** 2026-11-11 · **правило:** каждое «нет» — с перечнем проверенного и кодом/командой.
**Связано:** `kernel-code-14x.md`, `fresh-dumps-2026.md`, `emulator-fw-assets.md`, `kernel-dumps.md`.

## 0. TL;DR

1. **Ни одного системного файла 14.x (libSceSysCore / libkernel / libSceWebKit* / libSceAgcDriver) в публичном доступе
   не найдено** — ни целиком, ни фрагментом. Проверены: GitHub-репозитории и релизы 14.x-исследователей, артефакты
   ZigZagBoi1 (13.60/14.10), karter-captain (14.22 probes), kevinisgoated24-spec (14.20), Khal0da (14.20), payload-проекты
   (kstuff/etaHEN/itemzflow/ps5-payload-dev), archive.org, GitHub Releases/LFS.
2. **Ближайшее, что удалось добыть реально** — userland-модули Sony эпохи **SDK 11.00** из игрового дампа
   Code Violet (PPSA26528 v01.028): `libc`, `libSceFontGsm`, `libSceJobManager`, `libSceNpCppWebApi`, `libScePfs`
   (+ SELF-копии), `param.json`, `eboot.bin` — в `fw/game-modules/code-violet-ppsa26528-v01028/`.
   Это **не 14.x** (required FW 12.70), но реальный Sony-код новее нашего эталона 8.60.
3. **Принципиальное ограничение:** игровой дамп не содержит `libkernel`/`libSceSysCore`/`libSceWebKit` — эти модули
   system-resident (в прошивке), игра их только импортирует (`DT_NEEDED`). Поэтому из игровых дампов **нельзя**
   получить syscall-таблицу/NID→syscall mapping. Нужен прошивочный образ (PUP-ключ) или фрагмент оного.
4. Проверенные репозитории «заявляющих 14.2x» содержат только веб-пробы/HTML/доки/свои payload-ELF — системных
   файлов там нет (список §2).
5. Единственные публичные «firmware files» — NOR-дамп PS5 (2 МБ, boot-flash) и архив PS5 SDK 4.00.07 (4,79 ГБ zip,
   2025-02) — не 14.x (см. `emulator-fw-assets.md` §4).
6. Следующий шаг: дампы игр **после 19.11.2026** (требующие FW 14.22) — их `sce_module` даст userland-модули 14.22-эпохи;
   фильтр — `sce_sys/param.json` (`requiredSystemSoftwareVersion ≥ 0x1400…`). Ядро/`libkernel` там всё равно не будет.

## 1. Что искали и чем проверяли

Цель: любой файл 14.x — `libSceSysCore`, `libkernel`, `libSceWebKit*`, `libSceAgcDriver`, ядро — целиком или фрагментом
(первые мегабайты, hex-дамп), с магией/размером/build-строкой.
Инструменты: `gh api` (search/code, search/repositories, releases, trees), `curl -x socks5h://127.0.0.1:10810`,
`archive.org/metadata`/`advancedsearch`, скачивание+`file`/`readelf`/`strings`, `anyps5/unwrap_self.py`,
собственные Range-ридеры `fw/game-modules/tools/ffpfsc_remote.py`, `exfat_remote.py`.

## 2. Проверенные источники (отрицательный результат)

| Источник | Что проверено | Результат |
|---|---|---|
| `ZigZagBoi1/PS5-14.10-Research` (121 МБ, 9094 файла) | tree: все blob'ы с расширениями `.bin/.prx/.elf/.sprx` — 25 крупнейших просмотрены | **системных файлов 14.x нет**: только `docs/dumps_13.60/*` (13.60-дамп), свои ELF-пробы (`PS5_1410_RESEARCH*.elf` 30–149 КБ), `pup14/515_block141.bin` 100 КБ (шифрованный фрагмент PUP 14.10), `private_1360_umtx_454/*` (13.60 UMTX), `artifacts/usb_pre_reset…/goldhen.bin` и т.п. |
| `ZigZagBoi1/PS5-V13.60-Research` | tree + `docs/dumps_13.60/` | только 13.60-дамп и аналитика; модулей 14.x нет |
| `pastawithpesto/PS5-14.10-Jailbreak-Research` | tree, 1584 blob'а | только `shared/elfldr-ps5-v0.26.elf` (394 480 B), `shared/kexp-v0.8….bin` (18 208 B), результаты/доки; системных файлов нет |
| `logicalpeyote777/ps5-14.00-jailbreak-research` | tree (13 файлов) | только текст (PAPER.md и пр.); файлов нет |
| `karter-captain/ps5-14.22-browser-probes` | tree (11 файлов) | только HTML-пробы + README; файлов системы нет |
| `kevinisgoated24-spec/PS5-14.20-Jailbreak-Research` | tree (5 файлов) | README/JS/сервер/заметки; системных файлов нет |
| `Khal0da/PS5-14.20-WebKit-Research` | tree: payloads (13.60-эпоха `relapse.js`, `poops.js`), probes, docs | системных файлов 14.x нет; `13.60/payloads/*.elf` — payload'ы для 13.60 |
| `pastawithpesto`/`ZigZag` issues (поиск `search/issues`) | `aio_multi_delete`/`libkernel`/`dump` | ссылок на дампы модулей нет |
| kstuff/kstuff-lite (`drakmor`, `ps5-payload-dev`) | releases: `kstuff.elf` 1,5 МБ, offsets headers 3.00–12.70 | модулей 14.x/офсетов 14.x нет |
| etaHEN/etaHEN (`250?`) | релизы `etaHEN-2.5B.bin` 4 678 728 B (2025-12-25); порт `ydd33048` 11.00–13.60 | 14.x нет |
| `LightningMods/Itemzflow` | releases 1.08/PS5-1.09 — **assets=0** | файлов нет |
| GitHub Releases/LFS, repo search (`ps5 modules`, `ps5 firmware dump`, `ps5 prx`, `ps5 sdk`) | выдало `buzzer-re/PS5_kldload` (loader), `drakmor/dlc_emu` (DLC-заглушки), `SvenGDK/SharpProspero` (SDK-заголовки), `claimore22/ps5rs` (парсер) | системных файлов нет |
| archive.org | `PS5 SDK` → `ps5_sdk_4.00.07` (4 796 080 435 B zip, added 2025-02-03); `PS5_Unity_Fake` 3 832 126 633 B; NOR-дамп `ahlbornjagon/PS5_Dump` 2 097 152 B (скачан, sha256 `f889d657…` — boot NOR, не модули) | 14.x системных файлов нет |
| archive.org game dumps | 17 items ≥2026-09 (см. `fresh-dumps-2026.md`), из них проверен Code Violet (модули — SDK 11.00) | 14.x модулей пока нет |
| Telegram/форумы | доступ к каналам/поиску без авторизации ограничен; проверка не дала артефактов | `НЕ ПРОВЕРЕНО` (нет доступа) |

## 3. Что добыто вместо 14.x

`fw/game-modules/code-violet-ppsa26528-v01028/` — 5 модулей Sony (SDK 11.00 / FW 12.70) + SELF + `param.json`
+ `package.manifest` + `eboot.bin`; подробности и хэши — `MODULES.md`, разбор — `kernel-code-14x.md` §2–§5.
Способ: RAR5-заголовки по HTTP Range + sparse-образ + `bsdtar` (37 ГБ не скачивались).

## 4. Вывод

- «Фрагменты 14.x» публично **не выложены** (по крайней мере в проверенных местах); охоту нужно повторить после
  появления дампов игр, требующих FW 14.2x (после 19.11.2026), и фильтровать их по `param.json`.
- Для настоящего kernel-кода (таблица syscall, NID→syscall) игровые дампы непригодны в принципе — нужен
  расшифрованный системный образ (PUP-ключ) или фрагмент системного модуля, выложенный кем-то с консолью 14.2x.