# GTA 6 (PS5): чем привязан к 14.22 / 14.10 и можно ли обойти

**Задача:** task-31. **Агент:** recon-relapse. **Дата:** 2026-11-11.
**Вопрос лида:** чем именно GTA 6 привязан к 14.22 — и можно ли эту привязку обойти (консоль / эмулятор).
**Правило:** каждое утверждение — ссылка/команда; отдельно помечено, что **без консоли/дампа не проверить**.

> ⚠️ **Ключевой контекст даты:** на момент исследования игра **ещё не вышла** — релиз
> `2026-11-19T05:00:00Z` (из официальной страницы PS Store, см. §1). Значит **публичного дампа,
> param.json и eboot.bin не существует**, и все «требует 14.xx» — это **предрелизный датамайн**,
> а не факт из самой игры.

---

## 0. TL;DR

| Вопрос | Ответ | Достоверность |
|---|---|---|
| Title ID GTA 6 (PS5) | **`PPSA01547`** (standard: `EP1004-PPSA01547_00-GTAVISTANDARD001`, ultimate: `…GTAVIULTIMATE001`) | **подтверждено** официальной страницей PS Store (HTTP 200) |
| Минимальная прошивка | **14.10.00.00** — по датамайну PlayStation Game Size; **не 14.22** | датамайн (пресса), Sony/Rockstar не подтверждали |
| Откуда взялось «14.22» | пост в Telegram-канале JAILBROKEN_PS4_PS5_UNIVERSAL («14.22 is the firmware GTA 6 requires») | **неподтверждённый слух**, ссылок на файлы нет |
| Чем технически «требует» | поле `requiredSystemSoftwareVersion` (и `sdkVersion`) в `sce_sys/param.json` пакета + PlayGo-метаданные | поле и его чтение подтверждены реальным param.json и кодом эмулятора Kyty |
| Новые syscall/библиотеки? | **неизвестно**; публичных данных нет. Проверяется только по дампу `eboot.bin`/`libSce*` 14.x | `НЕ ПРОВЕРЕНО` |
| Запустить на консоли ниже 14.22 | **нет** в обозримом будущем: нужны kernel-эксплойт + hypervisor-bypass (публично ≤13.60) + backport с библиотеками 14.x (их нет публично) | вывод из трёх независимых фактов |
| Запустить в эмуляторе (если дамп появится) | проверка FW там **не барьер** (Kyty читает `requiredSystemSoftwareVersion` только для отображения), но **дампа нет и взять его негде** (нужен hypervisor-эксплойт), а совместимость 2026-AAA в KytyPS5/SharpEmu неизвестна | частично проверено кодом эмулятора |

---

## 1. Идентификация игры (официальные данные)

Страница PS Store: `https://store.playstation.com/en-us/product/EP1004-PPSA01547_00-GTAVISTANDARD001`
проверена `curl` → **HTTP 200, 466 068 байт**. Внутри (JSON-данные страницы):

```
"name":"Grand Theft Auto VI"
"category":"Game Bundle"
"sku":"EP1004-PPSA01547_00-GTAVISTANDARD001"
"platforms":["PS5"]
"publisherName":"Rockstar Games"
"releaseDate":"2026-11-19T05:00:00Z"
"price":79.99           // ultimate-издание — EP1004-PPSA01547_00-GTAVIULTIMATE001, $99.99
"Concept:10000730"      // concept id
"compatibilityNoticesByPlatform":{"PS5":[PS5_VIBRATION/OPTIONAL, PS5_TRIGGER_EFFECT/OPTIONAL, GRAPHICS_ENHANCED/true]}
"webctas":["GameCTA:PREORDER:BUY_NOW:EP1004-PPSA01547_00-GTAVISTANDARD001-U001:OUTRIGHT"]
```

Перекрёстные подтверждения title ID `PPSA01547`:
* каталог магазина [`Ephellon/game-store-catalog/ps5/g.json`](https://raw.githubusercontent.com/Ephellon/game-store-catalog/main/ps5/g.json) —
  запись `"name":"Grand Theft Auto VI"`, `"href":"…EP1004-PPSA01547_00-GTAVISTANDARD001"`, `"platforms":["PS5"]`, $79.99;
* GitHub code search `q=PPSA01547` → 632 файла в 10+ репозиториях (трекеры цен, каталоги, краулеры);
* страница-краулер `mifasarw-mfs/mifasa-crawl/s/MN202611_f6td52thyc.html` — та же store-ссылка.

**Вывод §1:** title ID = **`PPSA01547`**. Регион в content id — `EP1004` (EU/Rockstar Europe);
US-SKU, вероятно, `UP1004-PPSA01547_00-…` (**НЕ ПРОВЕРЕНО** — US-страницу не открывал).
Издания: Standard `…GTAVISTANDARD001` ($79.99), Ultimate `…GTAVIULTIMATE001` ($99.99), категория «Game Bundle».
Платформа в магазине — **только PS5** (Xbox-версия в PS Store не отображается; Wikipedia в инфобоксе
перечисляет PS5 / Xbox Series X|S / Xbox One — `https://en.wikipedia.org/wiki/Grand_Theft_Auto_VI`).

Важно: **в HTML страницы магазина нет ни «14.10», ни «14.22»** (проверено `grep '14\.10|14\.22'` → 0 совпадений).
Т.е. требование прошивки **не публикуется в витрине** — оно лежит в метаданных пакета (см. §2).

---

## 2. «Требует 14.22»: что это значит технически

### 2.1. Две конкурирующие цифры

| Утверждение | Источник | Статус |
|---|---|---|
| **14.10.00.00** | датамайн **PlayStation Game Size** → статья Notebookcheck (2026-10-03): *«A datamine leak revealed GTA 6 will boot only using Sony's October **14.10.00.00** update on its release date»* — https://www.notebookcheck.net/GTA-6-blocks-PS5-jailbreak-and-piracy-on-release-date-requiring-14-10-00-firmware.1414828.0.html (проверено: HTTP 200, текст найден) | датамайн; Rockstar/Sony не подтверждали |
| **14.22** | пост Telegram-канала `JAILBROKEN_PS4_PS5_UNIVERSAL`: «…**14.22 is the firmware GTA 6 requires**» (зафиксировано в `recon/dump-1422-hunt.md:80`; ссылок на файлы/дампы в посте нет) | **слух**, ничем не подкреплён |
| «14.10 или новее» + «copying requires hypervisor exploit, none public for 14.10» | [`alan-r-henry/ps5-emu-tracker` → `web/public/data/gta_status.json`](https://raw.githubusercontent.com/alan-r-henry/ps5-emu-tracker/main/web/public/data/gta_status.json), `updated: 2026-10-21`; там же ссылки на Notebookcheck, TweakTown (PC-порт в 2027) и YouTube-разбор | сводка трекера со ссылками |
| «требует как минимум 14.10» | LavX News, 2026-10-25 (локальная копия `recon/_src/t14/lavx-prolapse-2026-10-25.txt`): *«Data mining indicates Grand Theft Auto 6 will require at least firmware 14.10 to launch»* | пресса |

**Итог §2.1:** первичная цифра — **14.10**, а «14.22» — вторичный слух. Для нашей задачи это важно:
привязка к 14.22 не доказана, привязка к 14.10 — датамайн из стора.

### 2.2. Где именно живёт требование (проверено на реальных файлах/коде)

PS5-игра описывается `sce_sys/param.json`. Реальный пример (репо [`Swordpdf/PS5SX2`](https://raw.githubusercontent.com/Swordpdf/PS5SX2/main/ps5/sce_sys/param.json), проверен curl):

```json
"requiredSystemSoftwareVersion": "0x0000000000000000",
"sdkVersion": "0x0000000000000000",
"titleId": "PPSA99203",
"contentId": "UP9000-PPSA99203_00-PCSX2ORBIS00001",
"masterVersion": "02.40", "contentVersion": "02.400.000", "versionFileUri": ""
```

* `requiredSystemSoftwareVersion` — минимальная прошивка (в примере нулевая, у retail-игр — реальное значение);
* `sdkVersion` — SDK, на котором собран проект;
* `titleId`/`contentId` — идентификаторы (у GTA 6: `PPSA01547` / `EP1004-PPSA01547_00-GTAVISTANDARD001`).

Эмулятор **KytyPS5** это поле читает (проверено по исходникам):
* `src/launcher/include/configuration.h:96-98`:
  `QString title_id; /* Serial / title id from sce_sys/param.json */`,
  `QString gameVersion; /* appVersion / contentVersion from sce_sys/param.json */`,
  `QString firmwareVer; /* requiredSystemSoftwareVersion from sce_sys/param.json */`;
* `src/launcher/src/configurationListWidget.cpp:525-527`: `GetFirmwareVersion()` → читает
  `requiredSystemSoftwareVersion`;
* `src/launcher/src/configurationItem.cpp:209-210`: значение выводится в **колонку** «Firmware version».

То есть в Kyty это **отображаемое поле конфигурации игры**, а не жёсткий запрет запуска
(в исследованных файлах проверки-блокировки нет; **глубже ядро эмулятора не смотрел — НЕ ПРОВЕРЕНО**).

### 2.3. Есть ли за этим новые syscall'ы / библиотеки?

Публичных данных нет. Что известно достоверно:
* по состоянию на 2026-11-11 ни один публичный разбор GTA 6 (`eboot.bin`, импорты `libSce*`, sysent)
  не существует — игры нет в продаже, дампа нет (§1, дата релиза);
* наши собственные материалы по 14.x не фиксируют новых syscall'ов: в `recon/kernel-surface-1422.md`
  расписаны только **известные** AIO-векторы (662 `aio_multi_delete` = Prolapse, 663 `aio_multi_wait` = Relapse),
  добавлений API в 14.x не подтверждено (`НЕ ПОДТВЕРЖДЕНО`, там же §2, §5);
* «требует 14.10» из датамайна — это **поле в метаданных** (иначе PlayStation Game Size не увидел бы его
  в сторе), а не список новых API. Иными словами: **доказанная часть привязки — метаданные**, а
  «использует новые API 14.x» — пока лишь гипотеза.

**Как проверить (когда появится дамп):** распаковать `param.json` (поля выше), вытащить `eboot.bin`
(SELF→ELF), сравнить таблицу импортов `libSce*` с 13.60 и прогнать `tools/payload/scan_1322.py` по
ядру 14.10/14.22 (см. `docs/KERNEL-INGEST.md`). **Без консоли/дампа — невозможно.**

---

## 3. Как в сцене делают backport (понижение требований)

### 3.1. PS5: что патчится

Источник — README инструмента **PS5 UltraPack** (knutwurst),
[github.com/knutwurst/ps5-ultrapack](https://github.com/knutwurst/ps5-ultrapack); в проекте лежит
локальная копия: `recon/_src/t3-ku/README.md`, раздел «Backporting», строки 103-140. Дословно:

> *«A backport lowers the SDK version the game declares in `eboot.bin` and its modules. If the older
> firmware is missing functions the game uses, the game also needs patched system libraries in its
> `fakelib/` folder, which ShadowMountPlus loads instead of the system ones.»*

> *«The app does the SDK part itself, also on fake-signed files (**only the two SDK values inside the
> signature change**). It doesn't ship any system libraries. You extract them from your own firmware,
> and the app can apply the public patches for you.»*

Таблица целей из того же README:

| Цель | Что делает |
|---|---|
| **7.61** | публичные патчи библиотек существуют; «обычный маршрут» |
| **6.02** | экспериментально, меньший набор патчей, работают не все игры |
| **10.xx** | «SDK only, for games slightly newer than the console» |
| любая FW из папки | SDK-значения берутся из библиотек этой FW |

Из CHANGELOG PS5 UltraPack (локальная копия `recon/_src/t3-ku/CHANGELOG.txt`):
* стр. 110 — *«a backport or patch with eboot.bin and param.json»*;
* стр. 320-322 — *«firmware lowered to the console's (the backport), PlayGo tables … URL in param.json
  (`versionFileUri`)»*, т.е. правится ещё и ссылка обновления, чтобы консоль не тянула апдейт.

Патчи библиотек — BPS-файлы из [`BestPig/BackPork`](https://github.com/BestPig/BackPork)
(API: `"description":"Lets you sideload system libraries into PS5 games"`, ветка `master`, push 2026-01-22).
Т.е. backport = 1) понизить SDK-значения в eboot/модулях, 2) подложить в `fakelib/` пропатченные
системные библиотеки старой FW (их грузит `ShadowMountPlus` вместо системных), 3) поправить `param.json`
(прошивка, `versionFileUri`).

### 3.2. Как выглядят PS5-патчи бинаря (формат)

Репозиторий [`sharpemu/ps5patches`](https://github.com/sharpemu/ps5patches) (PS5-патчи для эмулятора) —
формат XML, адреса — **файловые смещения относительно `ImageBase`**:

```xml
<Metadata Title="Uncharted 4: A Thief's End" Name="Debug Menu" Author="illusion"
          AppVer="01.000.000" ImageBase="0x01000000" AppElf="eboot.bin">
    <PatchList><Line Type="bytes" Address="0x01578838" Value="eb2a"/></PatchList>
</Metadata>
```

Плюс `patches.json` привязывает файл патча к title ID и версиям игры
(`PPSA01339/…` для Demon's Souls, `PPSA05389/…` для Uncharted). Это иллюстрирует общую механику
«патч = байты по смещению в eboot» — тот же принцип, что у backport'а SDK-значений.

### 3.3. Про «Backport 4.xx/5.xx/6.xx» у dlpsgame

Это **PS4-практика** (у PS4 другой формат: `param.sfo` с `SYSTEM_VER` + патч SELF/`eboot.bin`).
Для PS5 механика другая (§3.1): SDK-значения в eboot + `fakelib` с пропатченными библиотеками.
Смешивать их нельзя. PS5-backport'ы массово делаются целями **7.61/6.02**, т.е. **вниз**, а не вверх —
обратный путь (поднять требование) не имеет смысла.

**Вывод §3:** технически «привязка» — это 2 значения SDK в eboot/модулях + поле в param.json,
и они **патчатся**. Но если игре нужны функции, которых нет в старой FW, без пропатченных
системных библиотек (комплект для 14.x) она не заработает.

---

## 4. Можно ли запустить GTA 6 на прошивке ниже 14.22 (консоль)

Нужны **три** независимых условия; проверяем каждое:

| Условие | Статус на 2026-11-11 | Источник |
|---|---|---|
| 1. Kernel-эксплойт на нужной FW | 14.00/14.10 — **Prolapse** (aio_multi_delete), 14.20 — пропатчен; 14.22 (игра «требует» 14.10, но консоль с игрой может быть на 14.20/14.22) — **нет** | LavX: *«Prolapse works on firmware 14.00 and 14.10, though Sony patched it in the 14.20 update… targets a memory management flaw in aio_multi_delete»*; наш `recon/kernel-surface-1422.md` §1 |
| 2. Hypervisor-bypass (без него нельзя запускать backup'ы) | публично **только ≤ 13.60** (`Byepervisor-Reborn`, README: «Currently… 13.60, 13.20, 13.00»); 14.00 — «could work with modifications, but this is not provided here» | `recon/kstuff-1422.md` §1; README Byepervisor-Reborn |
| 3. Backport с библиотеками нужной FW | нужны библиотеки 14.x (их нет публично: PUP зашифрован, дампов 14.x нет — см. `docs/KERNEL-INGEST.md`); публичные наборы патчей — только 7.61/6.02 | `t3-ku` README §Backporting |

Косвенное подтверждение «потолка»: у самого инструмента backport'а (PS5 UltraPack, описание репозитория
через `gh api`, 2026-11-09) заявлено *«Verified launching on retail FW **11.60** with kstuff-lite 1.13+»* —
то есть даже рабочие fPKG-запуски проверены далеко не на 14.x.

Отдельно: Notebookcheck предполагает, что **дисковая** версия может ставиться на более старую FW
(*«Physical media may be compatible with older firmware, while Xbox and PS Store downloads can be easily
revised»*), но это домысел автора статьи, а не факт: диск PS5 всё равно содержит пакет с
`requiredSystemSoftwareVersion`. **Проверить нельзя без диска/дампа.**

**Вывод §4:** на консоли ниже 14.22 — **нет** (и даже на 14.10/14.20 — нет, потому что нет hypervisor-bypass
и нет библиотек 14.x для backport). Единственный теоретический путь: приватный hypervisor-эксплойт
для 14.10+ (о котором пишет cyber-forge: «wait for private WebKit/hypervisor chains»), затем backport
на 14.x-библиотеках. Публично этого нет.

---

## 5. А если дамп появится — реально ли в эмуляторе?

| Аспект | Ответ | Основание |
|---|---|---|
| Проверка `requiredSystemSoftwareVersion` в эмуляторе | **не барьер**: Kyty читает поле из `param.json` и показывает в колонке «Firmware version»; в launcher'е нет проверки-блокировки | KytyPS5 `configurationListWidget.cpp:525-527`, `configurationItem.cpp:209-210` |
| Патчи подмены/обхода проверок | есть готовый механизм: `sharpemu/ps5patches` (XML-патчи байтов по смещениям в `eboot.bin`), плюс `ps5patches/patches.json` с привязкой к title ID | репозиторий sharpemu/ps5patches |
| Где взять дамп | **негде**: `gta_status.json` → `"copyable": false`, `"copy_blocker": "…Copying a PS5 game off the console takes a hypervisor exploit, and none is public for 14.10: the last known one works only up to firmware 13.60"` | ps5-emu-tracker, `updated 2026-10-21` |
| Совместимость 2026-AAA в эмуляторах | **неизвестна/маловероятна**: KytyPS5/SharpEmu/anyps5 сейчас запускают единичные игры; наш локальный anyps5-run крутит Cyberpunk 2077 c 22 fps на RTX 2060 SUPER (`recon/emulation.md:171-180`) | локальные артефакты проекта |
| Если игра использует API 14.x, которых нет в эмуляторе | модуль не загрузится / упадёт на импорте — это уже **не** метаданные, а реальная несовместимость | `НЕ ПРОВЕРЕНО` (нужен дамп, чтобы увидеть импорты) |

**Вывод §5:** в эмуляторе привязка к FW как таковая **не мешает** (её можно игнорировать/пропатчить),
но запуск упирается в другое: (а) дамп получить нечем — нет hypervisor-эксплойта для 14.10+;
(б) совместимость незрелых эмуляторов с игрой 2026 года неизвестна; (в) если игра реально использует
новые библиотеки/вызовы 14.x, их придётся реализовывать.

---

## 6. Что нельзя проверить без консоли/дампа (честный список)

1. **Точное значение** `requiredSystemSoftwareVersion` у GTA 6 (14.10 или 14.22) — нужно метаданные пакета
   (preload/дамп/диск) или PSN-эндпоинт с метаданными.
2. `sdkVersion` игры — там же.
3. Список импортов `libSce*` и наличие вызовов, появившихся в 14.x — только по `eboot.bin`.
4. Работает ли backport на библиотеках 14.x — нужны сами библиотеки из 14.x firmware (зашифрованный PUP).
5. Проверка версии в ядре при запуске процесса (какие именно проверки делает 14.x kernel для
   процесса с `sdkVersion` ниже системного) — нужен kernel 14.22 (см. `docs/KERNEL-INGEST.md`).
6. Дисковая версия и её требования — нужен диск.

---

## 7. Итоговая сводка

1. **Title ID: `PPSA01547`** (подтверждено официальной страницей PS Store; standard/ultimate — разные
   content id, но один title id). Релиз `2026-11-19`, платформа PS5, издатель Rockstar.
2. **Заявленное требование — 14.10.00.00** (датамайн PlayStation Game Size → Notebookcheck / LavX /
   ps5-emu-tracker). **«14.22» — неподтверждённый Telegram-слух.**
3. **Доказанная часть привязки — метаданные**: `requiredSystemSoftwareVersion` + `sdkVersion` в
   `sce_sys/param.json` (+ PlayGo/`versionFileUri`). В публичной витрине PS Store этих полей нет
   (проверено grep'ом HTML).
4. **Обойти метаданные технически можно** — это и есть backport (PS5 UltraPack): понизить SDK-значения в
   `eboot.bin`/модулях, подложить пропатченные системные библиотеки в `fakelib/` (BPS-патчи
   `BestPig/BackPork`), поправить `param.json`.
5. **Но запустить на консоли ниже 14.22 нельзя** по другой причине: нужен hypervisor-bypass, а он
   публично есть только до 13.60; плюс нет библиотек 14.x для fakelib.
6. **В эмуляторе привязка к FW не барьер**, но барьер — отсутствие дампа (его нельзя снять без
   hypervisor-эксплойта) и незрелость эмуляторов для AAA 2026 года.

---

## 8. Источники и как проверялись

| Источник | URL | Проверка |
|---|---|---|
| PS Store — GTA VI (Standard) | https://store.playstation.com/en-us/product/EP1004-PPSA01547_00-GTAVISTANDARD001 | curl → **200**, 466 068 Б; grep найдены `PPSA01547`, `releaseDate 2026-11-19`, `platforms ["PS5"]`, `sku`, `Concept:10000730`; `14.10/14.22` — **0** |
| Каталог магазина (JSON) | https://raw.githubusercontent.com/Ephellon/game-store-catalog/main/ps5/g.json | curl → 200; запись GTA VI, `platforms ["PS5"]`, цены $79.99/$99.99 |
| Notebookcheck (датамайн 14.10) | https://www.notebookcheck.net/GTA-6-blocks-PS5-jailbreak-and-piracy-on-release-date-requiring-14-10-00-firmware.1414828.0.html | curl → 200; текст «datamine leak revealed GTA 6 will boot only using Sony's October 14.10.00.00 update» найден |
| ps5-emu-tracker gta_status.json | https://raw.githubusercontent.com/alan-r-henry/ps5-emu-tracker/main/web/public/data/gta_status.json | curl → 200; `copyable:false`, тексты про 14.10 и hypervisor |
| LavX News (Prolapse/14.10) | https://news.lavx.hu/article/ps5-kernel-exploit-prolapse-works-on-firmware-14-10-but-gta-6-piracy-remains-unlikely-for-now | локальная копия `recon/_src/t14/lavx-prolapse-2026-10-25.txt`, HTTP 200 |
| Telegram-слух 14.22 | `t.me/s/JAILBROKEN_PS4_PS5_UNIVERSAL` (выдержка в `recon/dump-1422-hunt.md:80`) | текст зафиксирован, ссылок на файлы нет |
| Реальный `param.json` PS5 | https://raw.githubusercontent.com/Swordpdf/PS5SX2/main/ps5/sce_sys/param.json | curl → 200; поля `requiredSystemSoftwareVersion`, `sdkVersion`, `titleId`, `contentId` |
| KytyPS5 (парсинг FW) | `KytyPS5/KytyPS5` → `src/launcher/include/configuration.h:96-98`, `src/launcher/src/configurationListWidget.cpp:525-527`, `src/launcher/src/configurationItem.cpp:209-210` | raw-файлы получены, строки проверены |
| **PS5 UltraPack** (как работает backport) | [knutwurst/ps5-ultrapack](https://github.com/knutwurst/ps5-ultrapack); локальная копия `recon/_src/t3-ku/README.md` §Backporting, `CHANGELOG.txt` стр. 110, 320-322 | файлы в репозитории проекта; repo check через gh api |
| BackPork (sideload библиотек) | https://github.com/BestPig/BackPork | `gh api` → `"Lets you sideload system libraries into PS5 games"`, master, push 2026-01-22 |
| SharpEmu PS5-патчи (формат) | https://github.com/sharpemu/ps5patches → `patches.json`, `prospero_patches/*.xml` | raw-файлы получены, формат проверен |
| Wikipedia GTA VI | https://en.wikipedia.org/wiki/Grand_Theft_Auto_VI | curl → 200; «Platforms PlayStation 5 Xbox Series X/S Xbox One», «Release 19 November 2026» |
| Наши материалы | `recon/kernel-surface-1422.md` (§AIО-векторы 662/663), `recon/kstuff-1422.md` (§Byepervisor), `docs/KERNEL-INGEST.md` | в репозитории проекта |

**Команды, которыми это проверялось (воспроизводимо):**

```bash
export ALL_PROXY=socks5h://127.0.0.1:10810
curl -sS -x socks5h://127.0.0.1:10810 -o store.html \
  "https://store.playstation.com/en-us/product/EP1004-PPSA01547_00-GTAVISTANDARD001"
grep -oE '"sku":"[^"]+"|"releaseDate":"[^"]+"|"platforms":\[[^]]*\]|PPSA[0-9]{5}' store.html | sort -u
grep -c 'requiredSystemSoftware' store.html          # → 0 (в витрине нет)
gh api "search/code?q=PPSA01547" --jq '.total_count'  # → 632
curl -sS -x socks5h://127.0.0.1:10810 \
  https://raw.githubusercontent.com/Swordpdf/PS5SX2/main/ps5/sce_sys/param.json
curl -sS -x socks5h://127.0.0.1:10810 \
  https://raw.githubusercontent.com/KytyPS5/KytyPS5/main/src/launcher/src/configurationListWidget.cpp \
  | grep -n -A3 "GetFirmwareVersion"
```
---

## 7. ОБНОВЛЕНИЕ 2026-11-03: требование сменилось на 14.22

Первичный источник: аккаунт **PlayStation Game Size** (отслеживает данные PlayStation Store),
твит <https://x.com/PlaystationSize/status/2117174273852792952>, пересказан Hi-Tech Mail
(<https://hi-tech.mail.ru/news/159621-dlya-gta-6-na-ps5-mozhet-ponadobitsya-bolee-novaya-proshivka/>,
3 ноября 2026, HTTP 200):

> «Для запуска Grand Theft Auto VI на PlayStation 5 может потребоваться системное ПО версии
> 14.22.00.00 или новее. … Ранее он указывал в качестве минимальной версию 14.10.00.00.»

Оговорки из того же текста: это данные магазина, а не официальное требование; Sony и Rockstar
минимум не подтверждали; до релиза цифра может измениться.

**Что это меняет (и не меняет):**
- лид прав: актуальный датамайн говорит **14.22**, а не 14.10. Наши прежние записи про 14.10 —
  устаревшая итерация того же источника, не ошибка;
- для легальной консоли это ничего не усложняет: обновился до 14.22 и играешь;
- для взломанной консоли это плохо: рабочие цепочки публично есть только ≤13.60 (kernel) и
  userland-вход на 14.22, но kernel-доступа на 14.22 нет ⇒ запустить игру на прошитой консоли нельзя;
- единственный обход для прошитой консоли — **backport** (снижение sdkVersion в eboot + fakelib),
  но он требует **расшифрованного eboot** игры, то есть дампа, а дамп снять нечем: копирование
  с консоли требует hypervisor-эксплойта, публично существующего только ≤13.60.

Итог: круг замыкается — GTA 6 требует 14.22, 14.22 не имеет публичного kernel-доступа,
дамп без kernel-доступа не снять, backport без дампа не сделать.
