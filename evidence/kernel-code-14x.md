# Реальный код 14.x из свежих игровых дампов: что добыто

**Агент:** recon-kernel-dumps · **задачи:** task-33 (+task-28/task-20) · **дата:** 2026-11-11
**Правило:** каждый факт — команда/файл/хэш; непроверенное помечено. Всё скачанное — в `ps5jb/fw/game-modules/`.

## 0. TL;DR (для лида)

1. **Кода 14.x пока нет.** Ни один проверенный публичный дамп не имеет `requiredSystemSoftwareVersion` ≥ 13.x.
   Самый свежий (Code Violet PPSA26528 v01.028, archive.org, добавлен 2026-11-10) — это **SDK 11.00 / требует FW 12.70**
   (`param.json`: `sdkVersion=0x1100000000000000`, `requiredSystemSoftwareVersion=0x1270000000000000`).
   Это **не 14.x**, но это реальный Sony userland-код **новее нашего эталона 8.60**.
2. **Добыто и лежит на диске** (`fw/game-modules/code-violet-ppsa26528-v01028/`) — 5 настоящих Sony-модулей
   + SELF-копии + `param.json` + `package.manifest` + `eboot.bin`:

| модуль | размер, B | sha256 (полный — в `MODULES.md` каталога) | PT_SCE_COMMENT (Sony build path) |
|---|---:|---|---|
| `libc.prx` | 1 911 850 | `6a8a23a3…b65508f40` | `W:/Build/J03547016/sys/internal/usermode/src/libc/Prospero_Release/libc.prx` |
| `libSceFontGsm.prx` | 289 539 | `7f01d30d…cb8211c9` | `W:/Build/J03547016/sys/build/integration/orbis-build_0005c/package/target/phase2/usermode/src/font/sdk/libSceFontGs/libSceFontGsm.prx` |
| `libSceJobManager.prx` | 114 422 | `dfa4aac4…befab3158` | `W:/Build/J03547016/sys/internal/usermode/src/job/job_manager/Prospero_Release/libSceJobManager.prx` |
| `libSceNpCppWebApi.prx` | 7 971 719 | `2db2d64e…12193402b0` | `W:/Build/J03547048/vsh/sdk/target/sce_module/libSceNpCppWebApi.prx` |
| `libScePfs.prx` | 1 381 143 | `20ffe8ce…73f9e9c8` | `W:/Build/J03547016/sys/internal/usermode/src/libpfs/Prospero_Release/libScePfs.prx` |

3. **libkernel / libSceSysCore / libSceWebKit в игровых дампах НЕТ** — и не будет: `sce_module/` содержит только те
   userland-библиотеки, которые линкует игра. `libc.prx` лишь **импортирует** их (`NEEDED: libkernel.prx,
   libSceLibcInternal.prx, libSceSysmodule.prx`). Поэтому «NID→syscall mapping» и таблицу syscall-номеров из игрового
   дампа получить **нельзя** — только из прошивочного образа. Это надо зафиксировать как ограничение подхода.
4. **SELF:** `.prxbak` рядом с каждым `.prx` — decrypted SELF (PS4-магия `0x1D3D154F`, версия/attrs класса A/B);
   `anyps5/unwrap_self.py` разворачивает все 5 в ELF (размер на 48 B меньше `.prx` — разница в пересобранных
   program headers, содержимое — тот же образец). `.prx` уже является развёрнутым ELF (ET_SCE_DYNAMIC, OSABI FreeBSD).
5. **Калибровка J-номеров:** Cyberpunk v02.120 (required FW 08.60) — `W:/Build/J01625764`, libc 1 352 554 B;
   Code Violet (SDK 11.00 / FW 12.70) — `W:/Build/J03547016`, libc 1 911 850 B (**+41%**), плюс новый модуль
   `libSceFontGsm`. То есть **больший J-номер = новее эпоха**; для 14.x ожидаем J-номера существенно больше J03547xxx.
6. **EA FC 27 (PPSA34015, `.ffpfsc`, 91.4 ГБ)**: контейнер `.ffpfsc` разобран и читается по HTTP Range без скачивания
   (`fw/game-modules/tools/ffpfsc_remote.py` + `ffpfsc_get.py`); корень дампа получен: `eboot.bin`, `sce_module/`,
   `fakelib/`, `sce_sys/`, `Patch/`, `Data/`, `Scripts/`, `Engine.*.prx`. Декод `sce_sys/param.json` (FW/SDK эпохи) —
   в процессе (см. §7); `sce_module` там тоже есть, но `libkernel`/`SysCore`/`WebKit` не будет по той же причине.
7. **Критерий отбора дампов на будущее:** читать `sce_sys/param.json` ПЕРВЫМ (не `sce_module`): нужен
   `requiredSystemSoftwareVersion` ≥ `0x1260…` (13.x) или `0x1400…/0x1420…` (14.x). Игры, требующие 14.22, появятся
   после релиза 19.11.2026 — они и дадут настоящие 14.22-модули userland (но всё равно не ядро).

## 1. Декодирование версий из `param.json`

Формат `requiredSystemSoftwareVersion` / `sdkVersion` — **BCD-пары** (`0x` + пары hex-цифр как десятичные):
`0x1270000000000000` → пары `12`,`70` → **FW 12.70**; `0x1100000000000000` → **11.00** (SDK).
Подтверждение: `seregonwar/PkgToolBox tools/PS5_Game_Info.py` (`_format_version`: «dotted BCD pairs»),
`KytyPS5/src/launcher/src/configurationListWidget.cpp:525` (по данным лида). Сверка на нашем материале:
Cyberpunk v02.120 — по локальному research требует **08.60** (список патчей), что соответствует BCD-схеме.

## 2. Code Violet PPSA26528 v01.028 — как добыто (без 37 ГБ)

1. `archive.org/metadata/codeviolet-ppsa-26528-usa-game-v-01.028-ps-5` → один файл
   `[SuperPSX]-Code.Violet-PPSA26528-USA-Game-(v01.028)-PS5.rar`, 37 310 167 854 B, added 2026-11-10T23:10:24Z.
2. **RAR5-заголовки прочитаны по HTTP Range** (свой walker: ~84 записи, таблица стабов не нужна): найдены
   `eboot.bin`, `package.manifest`, `sce_sys/param.json`, `sce_module/libc.prx` (+`libSceFontGsm`, `libSceJobManager`,
   `libSceNpCppWebApi`, `libScePfs`) и их `.prxbak`-копии, а также игровые `.ucas/.pak`.
3. Собран **sparse-образ** (37 310 167 854 B, реально занято ~5 МБ) с заголовками всех записей + данными нужных
   файлов; `bsdtar` (libarchive, понимает RAR5 и seeks по «дырам») извлёк только `sce_module/*`, `sce_sys/param.json`,
   `package.manifest`, `eboot.bin`. Полные 37 ГБ не скачивались.
4. `.prxbak` → `anyps5/unwrap_self.py` → ELF (OK для всех 5): это **decrypted SELF** (класс A/B из `recon/self-classes.md`).
5. Всё сложено в `fw/game-modules/code-violet-ppsa26528-v01028/`; индекс с хэшами — там же `MODULES.md`
   (создаётся/обновляется скриптом `tools/module_meta.py`).

### 2.1 `param.json` (ключевые поля, дословно)

```
contentVersion               = 01.000.028
masterVersion                = 01.00
targetContentVersion         = 01.000.027
sdkVersion                   = 0x1100000000000000     -> SDK 11.00
requiredSystemSoftwareVersion= 0x1270000000000000     -> FW 12.70
contentId                    = UP5503-PPSA26528_00-0656994000407395
pubtools.toolVersion         = 3.13
```

### 2.2 Датировка образа

- mtime файлов в RAR: `eboot.bin`/`.prxbak`/`param.json` — **2026-06-03 12:04** (мастеринг/упаковка дампа);
  `.prx` — 2026-11-10 (время распаковки-переупаковки дампа).
- в строках `eboot.bin` найдена SDK-строка `2024-11-25 12:07:48 b95d11e9…` (build-stamp SDK; согласуется с SDK 11.00).
- Job-номера Sony: `J03547016` (sys) / `J03547048` (vsh) — см. калибровку §5.

## 3. Почему Code Violet — не 14.x (и что это значит)

`requiredSystemSoftwareVersion = 12.70` ⇒ игра мастерилась под FW 12.70 (эпоха до 13.00/14.00), её `sce_module` —
копии системных userland-библиотек SDK 11.00. Это **эталон «младшей эпохи»**, но не 14.x. Тем не менее это первый
реальный Sony-код новее 8.60 в нашем распоряжении: он даёт современные ABI-структуры libc/libScePfs и пример
изменений между эпохами (см. §5).

## 4. Что реально можно (и нельзя) извлечь из игрового дампа

| Есть в `sce_module/` игры | Чего там НЕТ |
|---|---|
| `libc.prx`, `libScePfs.prx`, `libSceJobManager.prx`, `libSceFontGsm.prx`, `libSceNpCppWebApi.prx` (и др. по игре) | `libkernel.prx`, `libSceSysCore.prx`, `libSceWebKit*.prx`, `libSceAgcDriver.prx` — это system-resident модули прошивки |
| зависимости модулей в `DT_NEEDED` (например, `libc` → `libkernel.prx`, `libSceLibcInternal.prx`, `libSceSysmodule.prx`) | тела этих system-модулей → **таблица syscall-номеров и NID→syscall mapping недоступны** |
| собственный игровой код (`eboot.bin`, `Engine.*.prx`) | ядро/гипервизор |
| в части дампов — `fakelib/*.sprx` (fake libs, класс A SELF) | настоящие Sony `libSceSysCore` |

Вывод: гипотеза «игровой дамп = вход в 14.x kernel-эксплойт» **неверна по своей сути**: userland-модули дают ABI и
импорт-таблицы, но не syscall-обёртки ядра. Для syscall-таблицы нужен именно прошивочный образ (PUP-ключ/дамп).

## 5. Сравнение эпох: Cyberpunk v02.120 (08.60) vs Code Violet v01.028 (SDK 11.00)

| Модуль | Cyberpunk 08.60 | Code Violet SDK 11.00 | Δ |
|---|---:|---:|---:|
| `libc.prx` | 1 352 554 B (`e851775b…`) | 1 911 850 B (`6a8a23a3…`) | **+41,3%** |
| `libScePfs.prx` | 1 381 071 B (`fbbf2217…`) | 1 381 143 B (`20ffe8ce…`) | +0,005% |
| `libSceJobManager.prx` | 113 062 B (`2efd5736…`) | 114 422 B (`dfa4aac4…`) | +1,2% |
| `libSceNpCppWebApi.prx` | 7 491 911 B (`a0435b75…`) | 7 971 719 B (`2db2d64e…`) | +6,4% |
| `libSceFontGsm.prx` | — | 289 539 B (`7f01d30d…`) | **новый модуль** |
| SCE_VERSION | `…6c6962633a040000310000021100000211` | `…6c6962633a11000040000000011100004000000001` | формат/ABI изменён |
| Build job | `J01625764` (`sys/internal/usermode/src/libc`) | `J03547016` | +19,2 млн (≈2,2×) |

Калибровка (эпохи по J-номеру; для 14.x ожидается существенно больше J03547016):
`J01625xxx` → FW 8.60; `J03547xxx` → SDK 11.00 / FW 12.70.

## 6. Инструменты, созданные под задачу (в `fw/game-modules/tools/`)

| Файл | Что делает |
|---|---|
| `ffpfsc_remote.py` | читает внутренний exFAT из `.ffpfsc` (PFS)→PFSC zlib-блоки по HTTP Range; кэш таблицы блоков на диске |
| `ffpfsc_get.py` | точечное чтение путей (`/sce_sys/param.json`, `/sce_module`, …) из `.ffpfsc` без полного обхода |
| `ffpfsc_fast.py` | листинг/поиск/извлечение по `.ffpfsc` (ленивый FAT) |
| `exfat_remote.py` | (был раньше, от команды) чтение чистого `.exfat`-образа по Range |
| `module_meta.py` | метаданные PS5 PRX/SELF: sha256, PT_SCE_COMMENT, SCE_VERSION, NEEDED |

## 7. EA FC 27 (PPSA34015, `.ffpfsc`, 91 438 579 712 B) — прогресс

- Контейнер: PFSC v6, block=0x10000, `data_at=0x1880000`, logical inner image = **210 180 767 744 B (195,7 GiB)**,
  inner name `PPSA34015.exfat` (видно в uroot PFS-образа).
- Корень внутреннего exFAT (получен, 206 запросов/27 МБ, 181 с): `eboot.bin` 330 649 402 B, `sce_module/`, `fakelib/`,
  `sce_sys/`, `Patch/`, `Data/`, `Scripts/`, `Engine.MovieVLC.LibVLC.prx` 3 339 443 B,
  `Engine.Render.Core2.PlatformPs5.prx` 3 925 528 B, `ampr_emu.index`, `dlc_emu.ini`, `package.mft`,
  `Runtime_Ps5_retail.BuildSettings`.
- `sce_sys/param.json` и листинг `sce_module/` — добываются отдельным точечным прогоном (`ffpfsc_get.py`,
  прямой node-URL `ia600602.us.archive.org/30/items/…`). По состоянию на 18:34 MSK прогон не завершился:
  archive.org отдаёт часть Range-запросов с HTTP 500/таймаутами (нагрузка/три агента параллельно), ретраи
  съедают время. Таблица блоков (25 656 840 B) уже закэширована (`/tmp/ffpfsc-table-33cc7146b2251d7d.bin`),
  поэтому повторный прогон будет заметно быстрее. Команда повторного запуска:

  ```bash
  cd ps5jb/fw/game-modules/tools
  python3 ffpfsc_get.py \
    --url 'https://ia600602.us.archive.org/30/items/ppsa-34015-ea-sports-fc-27/PPSA34015%20EA%20SPORTS%20FC%2027.ffpfsc' \
    --size 91438579712 --path /sce_sys/param.json --path /sce_module --outdir /tmp/fc27meta
  ```

  Ожидание: `param.json` → `sdkVersion`/`requiredSystemSoftwareVersion`; если FW < 13.x — дамп не наш.
  Root-листинг уже подтверждает наличие `sce_module/` и `sce_sys/` (см. выше), т.е. модули там есть;
  вопрос только в том, какая у них эпоха.

## 8. Как проверять следующие дампы (быстрый конвейер)

1. `archive.org/metadata/<id>` → имя/размер файла: `.ffpfsc` / `.exfat` / `.rar` / `.7z` / `.iso`.
2. Для `.ffpfsc`: `python3 tools/ffpfsc_get.py --url <download-url> --size <bytes> --path /sce_sys/param.json`
   (первый запуск ~3–5 мин: качается таблица блоков; далее кэш). **Сначала param.json**:
   `sdkVersion`/`requiredSystemSoftwareVersion` → декод в FW/SDK. Если FW < 13.x — дамп не наш.
3. Если FW ≥ 13.x: `--path /sce_module` (листинг) → вытащить все `.prx`; прогнать `module_meta.py`; сравнить build-пути.
4. Для `.exfat`: `exfat_remote.py --find param.json` / `--find sce_module`.
5. Для `.rar`: RAR5-walker + sparse-image + `bsdtar` (метод §2) — позволяет не качать десятки ГБ.

## 9. Итог по task-33 (честно)

- «Настоящий 14.x-код» **не добыт**: публичных дампов с FW ≥ 13.x по состоянию на 2026-11-11 не найдено/не подтверждено.
- Получен **реальный Sony userland-код эпохи SDK 11.00** (Code Violet) — 5 модулей с хэшами, build-путями и
  развёрнутыми SELF; это ближайшая доступная точка для сравнения ABI.
- **Syscall-таблица/NID→syscall mapping из игровых дампов принципиально недоступны** (нет `libkernel`/`libSceSysCore`).
- Создан рабочий конвейер добычи из свежих дампов (`.ffpfsc`/`.exfat`/`.rar`) без полного скачивания — под дампы,
  которые появятся после 19.11.2026 (игры, требующие 14.22).

## 10. Источники

| Источник | URL/доступ | Результат |
|---|---|---|
| Code Violet item | `archive.org/metadata/codeviolet-ppsa-26528-usa-game-v-01.028-ps-5` | RAR 37 310 167 854 B, added 2026-11-10 |
| EA FC 27 item | `archive.org/metadata/ppsa-34015-ea-sports-fc-27` | `.ffpfsc` 91 438 579 712 B, added 2026-10-18 |
| ffpfsc формат | `phantomptr/ps5upload` `engine/crates/ps5upload-fpkg/src/ffpfsc.rs`, `ffpfsc_block.rs` | layout PFS+PFSC, zlib-блоки |
| Декод версий | `seregonwar/PkgToolBox tools/PS5_Game_Info.py`; KytyPS5 `configurationListWidget.cpp:525` | BCD-пары |
| Эталон 8.60 | `games/cyberpunk/anyps5-run/sce_module/*.prx`, `research/cyberpunk-ps5-dump.md` | v02.120, FW 08.60 |

**Артефакты:** `fw/game-modules/code-violet-ppsa26528-v01028/` (модули+параметры), `fw/game-modules/tools/ffpfsc_*.py`,
`fw/game-modules/tools/module_meta.py`; подробности хэшей — в `MODULES.md` соответствующего каталога.