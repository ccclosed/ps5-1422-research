# GTA 6: какие пути запуска есть вообще (наша машина, 2026-11-11)

Проверено фактами с URL/кодами/датами. Всё, что не подтверждено источником, помечено
как **[оценка]**. До релиза GTA 6 — 8 дней (19.11.2026).

Наша машина (проверено командами, §4): i5-12400F, 15.8 ГБ RAM, RTX 2060 SUPER 8 ГБ,
190 ГБ свободно на `/home`, **оптического привода нет** (`/dev/sr*` отсутствует).

## 0. Итоговая таблица путей

| # | Путь | Что нужно | Статус (проверено) | Вердикт для нашей машины |
|---|---|---|---|---|
| 1 | **ПК-версия нативно** (Rockstar Launcher / Steam / Epic) | ПК-релиз | **Не анонсирован.** На rockstargames.com/VI чипы платформ только `PlayStation 5` и `Xbox Series X\|S`, слов `Windows`/`Rockstar Games Launcher` — **0**. Steam search API: `Grand Theft Auto VI` → 1 результат (Vice City DE, не GTA6), `GTA 6` → **0**. Слух: GamesBeat/TweakTown — порт **янв–март 2027**, Rockstar не подтверждал. | **Сейчас пути нет.** Ждать анонса; по слуху — 2027. Требований к ПК не существует, пока нет страницы игры → сравнить не с чем. |
| 2 | **Xbox Cloud Gaming (стриминг на ПК)** | Подписка/стриминг-план + аккаунт + поддерживаемый регион; интернет | **Есть.** The Verge (через Notebookcheck 07.10.2026): Xbox Cloud Gaming — единственный стриминг GTA 6 на релизе; Xbox CSO уточнил, что «эксклюзивной сделки нет», но права на облачный стриминг у Microsoft есть. Стриминг доступен на ПК/ноутбуках/смартфонах/ТВ. С ноября 2026 у Game Pass лимиты **5–15 ч/мес**, обещан pay-as-you-go без подписки. | **Единственный реальный «играть с 19.11.2026» путь.** GPU/CPU не важны (рендеринг в облаке); нужны аккаунт/подписка/регион. |
| 3 | **PS5-дамп + эмулятор** (KytyPS5 / SharpEmu / AnyPS5) | Консоль PS5 c FW ≥14.10 **+ дамп игры** + эмулятор, умеющий игру | **Закрыто с двух сторон:** (а) дампа GTA 6 нет ни у нас в каталоге (1446 пакетов, 0 упоминаний PPSA01547/GTA VI), ни на archive.org (только мод «GTA VC Mod GTA VI» 1.5 ГБ и видео); (б) скопировать игру с консоли нельзя: нужен hypervisor-exploit, публично он работает только **до 13.60** (трекер `gta_status.json`, 2026-10-21). Эмуляторы: Kyty compat-DB (442 записи) — **0** упоминаний GTA; SharpEmu `sharpemu.app/game/PPSA01547` — «No compatibility report yet»; трекер: у всех трёх проектов по GTA 6 статус `null`. | **Невозможно сейчас** — ни дампа, ни способа его сделать. Даже с дампом: ни один эмулятор GTA 6 не запускал. |
| 4 | **PS4-версия (shadPS4)** | PS4-версия игры | **Версии не существует.** Википедия (инфобокс): платформы — PS5, Xbox Series X/S, Xbox One (только через Xbox Cloud Gaming). PS4 нет. | **Путь не существует.** |
| 5 | **Xbox Series X\|S (эмулятор)** | Публичный эмулятор Series X\|S + дамп | **Эмулятора нет.** xemu — «Original Xbox Emulator»; Xenia — «Xbox 360 Emulator Research Project». Публичного эмулятора Xbox Series не существует. | **Путь не существует.** Xbox-путь возможен только через облако (п.2). |
| 6 | **Диск PS5** | Привод + консоль | Диск требует консоли с FW ≥14.10 (как и цифра). У нас **нет оптического привода** (`ls /dev/sr*` → нет файла; `lsblk` — только NVMe). | **Путь невозможен** физически. |

## 1. Детали и чем подтверждено

### 1.1 ПК-версия: не анонсирована

Проверки:

```bash
# 1) страница Rockstar VI: только консольные платформы
curl -sL -o rsvi.html https://www.rockstargames.com/VI        # HTTP 200, 1 233 788 Б
grep -o 'Xbox Series' rsvi.html | wc -l        # 5 вхождений (чипы платформ)
grep -o 'PlayStation 5' rsvi.html | wc -l      # 14
grep -o 'Windows' rsvi.html | wc -l            # 0
grep -o 'Rockstar Games Launcher' rsvi.html | wc -l   # 0
# в тексте страницы: "Coming November 19, 2026" и
# "Grand Theft Auto VI pre-loading is now available for everyone who has pre-ordered"
```

```bash
# 2) Steam: страницы GTA VI нет
curl -s 'https://store.steampowered.com/api/storesearch/?term=Grand%20Theft%20Auto%20VI&cc=us&l=en'
#   total: 1 -> 1546990 Grand Theft Auto: Vice City – The Definitive Edition
curl -s 'https://store.steampowered.com/api/storesearch/?term=GTA%206&cc=us&l=en'
#   total: 0
```

Слух о ПК-порте: GamesBeat (пересказ TweakTown, статья «Report: GTA VI PC port coming
Jan - Mar 2027», https://www.tweaktown.com/news/114065/report-gta-vi-pc-port-coming-jan-mar-2027/index.html —
заголовок получен, тело отдаёт Cloudflare 403 для curl) — цитируется в трекере:
`"pc_version": "Rockstar hasn't announced a PC version. GamesBeat reports one for early 2027, citing four industry sources."`
**Это не подтверждение Rockstar.**

### 1.2 Xbox Cloud Gaming — реальный путь на релизе

Источник: Notebookcheck 07.10.2026, «GTA 6 to stream exclusively on Xbox Cloud Gaming on
release date, benefiting PC gamers» (обновление: Xbox CSO Matthew Ball — «эксклюзивной
сделки по стримингу GTA 6 с Rockstar нет»).
https://www.notebookcheck.net/Xbox-Cloud-Gaming-to-stream-GTA-6-exclusively-on-release-date-benefiting-PC-gamers.1417471.0.html
Первичный источник: The Verge, https://www.theverge.com/report/1005859/microsoft-xbox-gta-6-streaming-rights

Ограничения (по той же статье и связанным): с ноября 2026 у Game Pass лимиты **5–15 часов
в месяц**; Microsoft вводит pay-as-you-go без подписки; обслуживаемые устройства — ПК,
ноутбуки, консоли, смартфоны, ТВ.

### 1.3 PS5-путь: нет дампа и нет способа его сделать

Требование прошивки (см. §2): GTA 6 требует **14.10.00.00**, копирование игры с консоли
требует hypervisor-exploit; последний публичный работает только **до 13.60**.

Трекер PS5-эмуляции (обновляется каждые 3 часа), `gta_status.json`, `updated: 2026-10-21`:

```bash
curl -sL https://raw.githubusercontent.com/alan-r-henry/ps5-emu-tracker/main/web/public/data/gta_status.json
# {
#   "updated": "2026-10-21",
#   "copyable": false,
#   "copy_blocker": "GTA 6 reportedly needs PS5 firmware 14.10 or newer. Copying a PS5 game
#                    off the console takes a hypervisor exploit, and none is public for 14.10:
#                    the last known one works only up to firmware 13.60 and was reported to Sony.",
#   "firmware": "GTA 6's PlayStation Store listing reportedly requires firmware 14.10 or newer.
#                That comes from a datamine; Rockstar and Sony haven't confirmed it.",
#   "pc_version": "Rockstar hasn't announced a PC version. GamesBeat reports one for early 2027..."
# }
```

Тот же трекер, `gta.json` — статусы по эмуляторам:

```bash
curl -sL https://alan-r-henry.github.io/ps5-emu-tracker/data/gta.json
# gta6: titleIds ["PPSA01547","PPSA29660","PPSA38500"], released 2026-11-19,
#       projects: {AnyPS5: null, KytyPS5: null, SharpEmu: null}
# gtav: AnyPS5 {stage: menus, 2026-09-30}, KytyPS5 {stage: ingame, 2026-10-07},
#       SharpEmu {stage: ingame, 2026-10-03}
```
Т.е. отсутствие GTA 6 в трекере — не «трекер не умеет», а реально «ни один эмулятор не запускал».

Эмуляторы по отдельности:

```bash
# KytyPS5: официальная база совместимости (442 записи) — GTA нет вообще
curl -sL https://kytyps5.github.io/data/compatibility.json | python3 -c 'import json,sys;d=json.load(sys.stdin);print(len(d), sum("gta" in json.dumps(v).lower() for v in d.values()))'
#   442 0
# SharpEmu: страница GTA VI есть, но отчёта нет
curl -sL https://sharpemu.app/game/PPSA01547 -o se.html
#   HTTP 200, <title>Grand Theft Auto VI — SharpEmu compatibility</title>, текст: "No compatibility report yet"
```

Дампа нет:

```bash
# наш локальный каталог дампов (1446 пакетов PS5: title, version, mirrors)
grep -c "PPSA01547\|GTAVI\|Grand Theft Auto VI" ps5jb/fw/game-modules/ps5-catalog.json   # 0
# в каталоге только: GTA V (PPSA04263/PPSA04264, v01.010/v01.011), трилогия DE 2021
# archive.org: единственный «GTA 6» — это мод, а не игра
curl -s https://archive.org/metadata/grand-theft-auto-6_202512
#   title "Grand Theft Auto 6", описание "GTA VC Mod GTA VI", файл Grand_Theft_Auto_6.rar 1 561 829 822 Б
```

### 1.4 PS4 / Xbox — версий или эмуляторов нет

* Версии: Википедия, инфобокс — платформы `PlayStation 5`, `Xbox Series X/S`,
  `Xbox One` (только через Xbox Cloud Gaming). PS4 в списке нет.
  https://en.wikipedia.org/wiki/Grand_Theft_Auto_VI
* Эмуляторы Xbox: xemu — «Original Xbox Emulator for Windows, macOS, and Linux»
  (GitHub API `xemu-project/xemu`), Xenia — «Xbox 360 Emulator Research Project».
  Публичного эмулятора Xbox Series не существует.
* Диск: у нашей машины нет оптического привода (`ls /dev/sr*` → «Нет такого файла»,
  `lsblk` — только `zram0` и `nvme0n1`), и PS5-диск всё равно требует консоли.

## 2. Прошивка: что именно требует GTA 6 и чем это подтверждается

**Минимум — 14.10.00.00** (не 14.22; 14.22 — просто более новая, чем минимум).

Источник: datamine аккаунта PlayStation Game Size (пост в X), изложено Notebookcheck
03.10.2026 «GTA 6 PS5 will require 14.10.00 firmware update on release date, blocking jailbreak»:
«A datamine leak revealed GTA 6 will boot only using Sony's October 14.10.00.00 update on its
release date». Там же: Relapse-эксплойт работал на 13.60 (июль), сентябрьское 14.00 (16.09.2026)
создало проблемы, октябрьское 14.10 (01.10.2026) — новые фиксы безопасности.
**Rockstar и Sony официально не подтверждали.**

Локальное соответствие PUP → версия (из `ps5jb/recon/pup-1420-vs-1422-delta.md`):

| файл | версия |
|---|---|
| `fw/PS5UPDATE-sys-2026_0928.PUP` | **14.10** |
| `fw/PS5UPDATE-sys-2026_1014.PUP` | **14.20** |
| `fw/PS5UPDATE-sys-2026_1027.PUP` | **14.22** |

Вывод: 14.22 ≥ 14.10, т.е. «GTA 6 требует 14.22» — неверная формулировка; требование —
14.10+, и наша 14.22 его перекрывает. Но **это ничего не даёт для запуска на ПК**:
прошивка нужна консоли, на которой игру запускают/дампят, а для дампа нужен эксплойт,
которого для 14.10+ публично нет.

## 3. Наша машина: проверка (команды и вывод)

```bash
df -h /home
# /dev/nvme0n1p5  665G  473G  190G  72%  /home
free -g | head -2
# Mem: total 15, available 8
lscpu | grep 'Model name'
# 12th Gen Intel(R) Core(TM) i5-12400F
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
# NVIDIA GeForce RTX 2060 SUPER, 8192 MiB
ls /dev/sr*        # -> нет файла (оптического привода нет)
```

* **Стриминг (п.2)**: наша машина подходит — нужны только браузер/приложение и сеть; GPU не важен.
* **ПК-версия (п.1)**: требований нет, пока нет страницы игры. Косвенный ориентир
  **[оценка]**: GTA V Enhanced (Steam API, appid 3240220) требует i7-4770/FX-9590, 8 ГБ RAM,
  GTX 1630 4 ГБ — наша машина заметно выше. Но GTA 6 — другая игра; переносить требования нельзя.
* **Место [оценка по слуху]**: Cyberleek (через Notebookcheck 12.10.2026) утверждает
  «GTA 6 build is 200 GB+». Если так, наших **190 ГБ свободных не хватит** под установку
  (без учёта распаковки/патчей). Это слух, официально размер не подтверждён.

## 4. Вердикт

1. **Сегодня единственный работающий путь «поиграть в GTA 6 на нашей машине» — Xbox Cloud
   Gaming** (стриминг; подписка/регион; лимиты 5–15 ч/мес с ноября 2026).
2. **ПК-версии нет** (не анонсирована); по слуху — янв–март 2027; тогда потребуется
   отдельная оценка по требованиям (сейчас их не существует), а 8 ГБ VRAM / 190 ГБ диска
   могут оказаться на границе.
3. **PS5-путь (дамп + эмулятор) закрыт наглухо**: игра требует FW 14.10+, публичный
   гипервизор-эксплойт — только ≤13.60, дампа GTA 6 не существует, ни один PS5-эмулятор
   игру не запускал (Kyty — 0 записей, SharpEmu — «No compatibility report yet», трекер —
   null у всех трёх).
4. **PS4-версии и эмулятора Xbox Series не существует** — эти пути не рассматриваются.
5. **Диск** — невозможен: у нас нет привода, а диск всё равно требует консоли 14.10+.

## 5. Все проверки одним списком (URL → код → вывод)

| проверка | URL/команда | результат |
|---|---|---|
| платформы на сайте Rockstar | `rockstargames.com/VI` | HTTP 200; только PS5 + Xbox Series X\|S; `Windows` 0; «Coming November 19, 2026»; «pre-loading is now available» |
| Steam | `store.steampowered.com/api/storesearch` | GTA VI → 1 (Vice City DE); «GTA 6» → 0 |
| PS Store (предзаказ) | `store.playstation.com/product/EP1004-PPSA01547_00-GTAVIULTIMATE001` | HTTP 200, «Grand Theft Auto VI: Ultimate Edition» |
| Википедия | `en.wikipedia.org/wiki/Grand_Theft_Auto_VI` | релиз 19.11.2026; платформы PS5, Xbox Series X/S, Xbox One (cloud) |
| требование FW | `notebookcheck.net/...requiring-14-10-00-firmware.1414828.0.html` | датамайн: 14.10.00.00; Relapse работал на 13.60, 14.00/14.10 — фиксы |
| трекер GTA | `alan-r-henry.github.io/ps5-emu-tracker/data/gta.json` | gta6: все эмуляторы `null`; gta5: ingame (методика рабочая) |
| трекер, блокеры | `.../raw/.../gta_status.json` | `copyable: false`; hypervisor ≤13.60; PC не анонсирован (GamesBeat: early 2027) |
| Kyty compat | `kytyps5.github.io/data/compatibility.json` | 442 записи, GTA — 0 |
| SharpEmu | `sharpemu.app/game/PPSA01547` | HTTP 200, «No compatibility report yet» |
| Xbox Cloud | `notebookcheck.net/...benefiting-PC-gamers.1417471.0.html` | единственный стриминг на релизе; эксклюзивной сделки нет; лимиты 5–15 ч/мес |
| ПК-порт (слух) | `tweaktown.com/news/114065/...` | заголовок «Report: GTA VI PC port coming Jan - Mar 2027» (тело: Cloudflare 403) |
| дампа нет | `grep` по `ps5jb/fw/game-modules/ps5-catalog.json` | 0 упоминаний PPSA01547/GTA VI (в каталоге только GTA V и трилогия) |
| archive.org | `archive.org/metadata/grand-theft-auto-6_202512` | это мод «GTA VC Mod GTA VI», 1.5 ГБ — не игра |
| xemu | GitHub API `xemu-project/xemu` | «Original Xbox Emulator» — Series не эмулирует |
| Xenia | GitHub API `xenia-project/xenia` | «Xbox 360 Emulator» |
| наша машина | `df`, `free`, `lscpu`, `nvidia-smi`, `ls /dev/sr*` | 190 ГБ свободно, 15.8 ГБ RAM, RTX 2060S 8 ГБ, привода нет |