# Реальные артефакты с консолей 14.2x: что опубликовано, а что пересказ

Дата работы: 2026-11-11. Задача task-22. Искались **файлы**, а не пересказы: логи, дампы,
probe-выводы, скриншоты с адресами, бинарь WebKit, userland-дампы — по всем, кто заявляет
работу на PS5 14.20/14.22.

Легенда:
`АРТЕФАКТ` — файл/лог, скачанный и проверенный (размер+sha256 ниже);
`АРТЕФАКТ-В-КОММЕНТАРИИ` — «сырой» лог/JSON, опубликованный текстом в issue-треде (не файл);
`ПЕРЕСКАЗ` — только слова, без логов/файлов;
`РЕЛАБЕЛ` — файлы одной прошивки, переименованные в другую (доказано хешами);
`НЕ НАЙДЕНО` — проверено, отсутствует.

Всё скачанное лежит в `recon/_src/artifacts-1422/`, манифест: **`recon/_src/artifacts-1422/MANIFEST.sha256`**
(38 файлов, sha256+путь). Клоны репозиториев — там же, коммиты зафиксированы в
`recon/_src/artifacts-1422/metadata.json`.

---

## 1. Итоговая таблица доказательств

| Автор / репозиторий | Что показал на 14.2x | Файл / ссылка | Что из этого следует |
|---|---|---|---|
| **TFujiwara** (форк `ZigZagBoi1/PS5-14.10-Research`, ветка `research/tfujiwara-v919-v929-campaign`, head `16e7c9e2`, 2026-11-11) | **Единственный найденный реальный набор артефактов с 14.22**: 30 result-файлов, в тексте которых есть `PS5 14.22` (большинство — `Target: PS5 14.22`), 60 beacon-логов от клиента `192.168.0.39` (27 796 beacon-строк), 2 лога с UA `PlayStation 5/14.22` | [v900](https://github.com/TFujiwara/PS5-14.10-Research/blob/research/tfujiwara-v919-v929-campaign/results/phase13_webkit/v900_fw1422_recon_20261105.txt), [p553](https://github.com/TFujiwara/PS5-14.10-Research/blob/research/tfujiwara-v919-v929-campaign/results/phase13_webkit/p553_write_confirm_14.22_20261105.txt), [лог v900](https://github.com/TFujiwara/PS5-14.10-Research/blob/research/tfujiwara-v919-v929-campaign/tools/browser_runner/beacon_logs/beacons_20261105_172139.log), [лог p553](https://github.com/TFujiwara/PS5-14.10-Research/blob/research/tfujiwara-v919-v929-campaign/tools/browser_runner/beacon_logs/beacons_20261105_175742.log) | **14.22 (как отгружена) НЕ закрывает входной canvas-баг**: `A-OK stale!=live`, `P553 … BIDIRECTIONAL ALIAS`, `FULL BIDIRECTIONAL R/W CONFIRMED`. Дальше — zero-at-free, нет лика/адреса, JIT off |
| **TFujiwara** (там же) | FontFace write-after-free ложится на 14.22 (`P640-HIT 56:loaded:zz56`), zero-at-free, стиль-канал; APNG no-IDAT убивает WebProcess | [p640](https://github.com/TFujiwara/PS5-14.10-Research/blob/research/tfujiwara-v919-v929-campaign/results/phase13_webkit/p640_writeback_14.22_lands_20261106.txt), [v909](https://github.com/TFujiwara/PS5-14.10-Research/blob/research/tfujiwara-v919-v929-campaign/results/phase13_webkit/v913_fontface_pair_no_reclaim_14_22_20261106.txt), [v930/v931](https://github.com/TFujiwara/PS5-14.10-Research/blob/research/tfujiwara-v919-v929-campaign/results/phase13_webkit/v930_branch_b_degraded_backing_20261111.txt) | На 14.22 живы два userland-вектора (canvas alias, FontFace WAF); лика/arb-RW нет |
| **elanonimo832** (14.20 Pro) | Полный JSON feature-пробника + сырые beacon-логи p553/p567/p554d текстом в issue | [ZZ #184](https://github.com/ZigZagBoi1/PS5-14.10-Research/issues/184), дубль [PP #63](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/issues/63); сохранено: `elanonimo_1420/1420_pro_feature_probe_2026-11-04.json` (`6ff36e6f…`) | `АРТЕФАКТ-В-КОММЕНТАРИИ`: 14.20 Pro, UA 14.20, p553 3/3 cold boot, RAB **есть**. Файлов/логов в репо нет |
| **nuzDop** (14.20) | Подробный отчёт «probe ladder на 14.20»: что выжило/регрессировало | [PP #59](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/issues/59); сохранено `elanonimo_1420/nuzDop_1420_probe_ladder_2026-10-29.txt` (`324a90e6…`) | `ПЕРЕСКАЗ`: только текст, «Migrated to private tracking», ни логов, ни файлов |
| **devravik** (репо «14.20») | «Устройство 14.20», лог с UA 14.20 | [repo](https://github.com/devravik/PS5-14.20-Jailbreak-Research); улики: `forensics/devravik-relabel-proof.json` (`c7761c84…`), `forensics/devravik_v480-log-14.20-RELABELED.txt` (`a25db604…`) vs `forensics/pp_v480-log-original-14.10.txt` (`bfc4b4fd…`) | **РЕЛАБЕЛ**: 1579/1579 файлов совпадают с репо pastawithpesto (14.10); 108 из 109 «различий» исчезают при замене `14.10`→`14.20` в байтах pp. Новых файлов — 0. Лог = pp-лог с заменой UA |
| **Mohabbadi11** (репо «14.20») | То же, что devravik | [fork devravik/PS5-14.20-Jailbreak-Research](https://github.com/Mohabbadi11/PS5-14.20-Jailbreak-Research) | **РЕЛАБЕЛ-форк** devravik: README md5 `06e2c8a0…` совпадает, v480-лог md5 `c6e18b84…` совпадает |
| **Khal0da** (репо «14.20») | Derived JSON «capture windows» по V923C/H/V973 + doc-отчёты; **сырых логов в репо нет** (в `.gitignore`: `*.log`, `host-beacons.log`); 1 569/1 584 файлов — копия pp 14.10 | [repo](https://github.com/Khal0da/PS5-14.20-WebKit-Research), `khal0da_1420/v923c-windows-2026-11-08.json` (`dbbcd914…`), [issue #3](https://github.com/Khal0da/PS5-14.20-WebKit-Research/issues/3) | `АРТЕФАКТ` (производный): окна/crash-метки есть; собственные доки честно пишут «UAF suspected, not confirmed; no native stack/klog». Их же issue #3 подтверждает: **14.20 dump/бинарь отсутствует публично** |
| **kevinisgoated24-spec** (репо «14.20») | Заявление «порт на 14.20» + «14.22 добавила guard» | [repo](https://github.com/kevinisgoated24-spec/PS5-14.20-Jailbreak-Research) (23 КБ, 5 файлов: README, canvas_uaf.js, canvas_serve.html, memory_layout.md, https_server.py) | `ПЕРЕСКАЗ`: ни одного лога/скрина. **Опровергнуто** артефактом TFujiwara v900 (14.22 UA, `A-OK`) |
| **qraillife** (дэшборды 14.20/14.22) | «Диагностика» в браузере + пустой module-host | [PS5-WebKit-14.20](https://github.com/qraillife/PS5-WebKit-14.20), [PS5-14.22-JB](https://github.com/qraillife/PS5-14.22-JB), `PS5-14.22-Jailbreak` (0 КБ) | `ПЕРЕСКАЗ/инструмент`: в коде прямо «firmware 14.20 is **user-reported**», `modules.json = []`, результатов нет. Картинки — стоковые logo/console, не скрины с адресами |
| **karter-captain** (14.22 probes) | Статические страницы-пробы (`index/webkit-sniff/…`), панель «RESULTS» | [repo](https://github.com/karter-captain/ps5-14.22-browser-probes) | `ПЕРЕСКАЗ/инструмент`: «No public exploit chain for 14.22 exists», результатов/логов не публикует |
| **ZigZagBoi1** (14.10) | 14.2x-файлов в репо нет (UA в логах только 14.10); но его issue-треды содержат 14.20/14.22 логи | [ZZ #184](https://github.com/ZigZagBoi1/PS5-14.10-Research/issues/184), [ZZ #216](https://github.com/ZigZagBoi1/PS5-14.10-Research/issues/216) | 14.10-репо само по себе 14.2x не доказывает; доказательства — в комментариях (см. выше) |
| **pastawithpesto** (14.10) | 14.2x-файлов нет; 14.20-отчёт в issue #59 | [repo](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research), [PP #59](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/issues/59) | Для 14.2x — только issue-текст |
| **logicalpeyote777** (14.00) | 14.2x-артефактов нет; упоминания 14.20/14.22 только в PAPER.md | [repo](https://github.com/logicalpeyote777/ps5-14.00-jailbreak-research) (клонирован, 4.9 МБ; файлов results/logs/artifacts — 0) | `ПЕРЕСКАЗ` для 14.2x |
| **cobrajet302gt, 4TheDoctor и др.** | Бенчи 14.10; в issue #216/#184 **арбитрируют** 14.22-строки TFujiwara | [cobrajet302gt #10/#19](https://github.com/cobrajet302gt/PS5-14.10-Jailbreak-Research), бенч-логи 4TheDoctor в ZZ-репо | 14.22-файлов нет; их реплики — независимая проверка 14.22-артефактов (не наши) |

---

## 2. Единственный реальный набор артефактов с 14.22 — TFujiwara

### 2.1. Где лежит и чем подтверждается

- Репозиторий: форк `TFujiwara/PS5-14.10-Research`, **ветка `research/tfujiwara-v919-v929-campaign`**,
  head `16e7c9e20cf4ff57de8953b121b21e7c46a83f2c` (коммит `2026-11-11T11:33:47Z`
  «docs: cobrajet inversion — v904 = band answer…»). Ветка публична; четыре ключевые ссылки ниже проверены `curl -L -o /dev/null` → HTTP 200.
- Метрики набора (посчитано по клону ветки):
  - result-файлов, в тексте которых есть `PS5 14.22` — **30** (большинство с `Target: PS5 14.22`;
    плюс 7 файлов с `14.22`/`14_22` в имени);
  - beacon-логов от клиента `192.168.0.39` — **60**, суммарно **27 796** beacon-строк;
  - файлов, содержащих UA-строку `PlayStation 5/14.22` — **4**: result `v900`, `p553` и два
    beacon-лога (`beacons_20261105_172139.log`, `beacons_20261105_175742.log`).
- Ключевой факт атрибуции: в логах 14.10-бенча клиент — `192.168.1.37`, в 14.22-бенче —
  `192.168.0.39` (совпадает с содержимым result-файлов: `Client: 192.168.0.39`).
  UA-строка в логе — прямое байтовое доказательство прошивки, а не пересказ.

### 2.2. Ключевые файлы (скачаны, размер+sha256)

| Файл | Размер | sha256 | Что внутри |
|---|---|---|---|
| `results/phase13_webkit/v900_fw1422_recon_20261105.txt` | 3 036 | `2776c0a0e4537b075d5fd01d79ad256117e2659ea451bf2bdd974b6541d0833c` | «14.22 Recon»: UA, `A-OK stale!=live (UAF present on 14.22)`, `ALIAS lw=811 idx=11`, `CAPS-OFF wasm,sab,webgl,offscreencanvas` |
| `results/phase13_webkit/p553_write_confirm_14.22_20261105.txt` | 2 548 | `e8f68d0bcb3d0fb204da2b66e59874df6c0621846adb60263169006f2af60e23` | `P553-WRITE-OK`, `P553-ALIAS-FOUND: spray[10]`, `P553-REVERSE-OK: FULL BIDIRECTIONAL R/W CONFIRMED`, все 7 numeric-каналов, save/restore, getTransform |
| `results/phase13_webkit/v651_v904_14.22_chain_health_20261106.txt` | 3 913 | `bc3ea8ff1fb1dd686381d82a961d4590ae31319d03ee574914de68b6e5e3c69c` | alias/stateStack/lineDash/gradient/getTransform живы; AB(768) забирает слот; 265 forged reads — 0 |
| `results/phase13_webkit/p640_writeback_14.22_lands_20261106.txt` | 2 370 | `83eaba3fd9b2882b1ca1828839a9dd0a724b7f056873d5f19f9cbf11d4d0e234` | `P640-HIT 56:loaded:zz56` ×2 — FontFace WAF алive на 14.22 |
| `results/phase13_webkit/v911_full_grid_close_14_22_20261109.txt` | 7 715 | `a8f3cd3bfe2546d55c0c00752fd0c3815845785d976b475c0bec84538ddc4a82` | двух-армный grid 6300 целей: `SURV 0`, `PAIR 0`, `RECON 0` |
| `results/phase13_webkit/v911_band0_complete_3072_20261107.txt` | 637 006 | `123fb4094a9d9a4b3a28ee4c3fd89faa1034c9503fc041e3f7f6f4a9cc9188aa` | сырой лог band 0 (3072 цели) |
| `results/phase13_webkit/v925_interpreter_only_decider_20261109.txt` | 2 374 | `49a184f16116dcffb5d57acfc5ec577e63ec831de3e7c06feca6a053d89d39d9` | `typeof WebAssembly = undefined` на 14.22 → LLInt-only |
| `results/phase13_webkit/p691_walk_14_22_noleak_zeroed_20261110.txt` | 3 144 | `dc60e2fbf97d8a0247baec10f85ad091d600b60c5d75de4eea763a1eb0c0d603` | walk-forge исполняется, лик-слоты `0x0` — NOLEAK |
| `results/phase13_webkit/v929_census_clean_descriptor_20261110.txt` | 2 883 | `60dfd565e30e1d69ea9dffe8656bc3ad626a4945e8539e34ff3ffa5363a68a21` | style-канал читает «normal» для winner и pristine |
| `results/phase13_webkit/v930_branch_b_degraded_backing_20261111.txt` | 5 940 | `ad21ca99f39ca9914b84a7ea8115dd6774e3cf354fa22915834ee070c923a178` | impl-scale corruption witness без адреса; winner `status=error` |
| `results/phase13_webkit/v931_style_map_selective_zeroing_20261111.txt` | 4 340 | `dff1089d82f37b654533456384c79adcfc8b8896b599913799df52f9e1337a5d` | 54/54 italic→normal, 53/53 oblique→normal, 0 аномалий |
| `results/phase13_webkit/p674_kit_14_22_preRegistered_decode_20261109.txt` | 4 087 | `d4965ce0fc2ab9bc548b89b1712741361a0d71e6f78fc307d96f4a2b6a32f7d6` | kit cobrajet302gt: (b) FIRES (1651 line не воспроизведён), APNG no-IDAT (c) FIRES |
| `logs/beacons_20261105_172139.log` | 583 | `36c5fb813d033f630d07c90796d3f598562f8f13589fbf955bb6206b8f6eef7a` | **сырой лог v900**: UA 14.22 + A-OK + ALIAS + PLAT + CAPS-OFF |
| `logs/beacons_20261105_175742.log` | 1 937 | `d3a79e3de7ebbd16e6d44dde746201660ed73b10e61ff3ab70188f1f1422c66e` | **сырой лог p553**: 18 beacon-строк, включая `P553-REVERSE-OK` |
| `logs/beacons_20261105_203251.log` | 3 728 | `66f564a83efa4b6f476c62f271046399842a6cbf3d3e7d22b674fa334cff5107` | 17 циклов v904: `V904-UAF inner=OK outer=OK same=false` |

Результат-файл `v909_sync_free_state_buffer_20261106.txt` в ветку не попал (в results есть v900, v901, v905, затем v910+);
строки про v909 (6/6 смертей на первом чтении) цитируются внутри `p640_writeback…` и `v931`, а сырой лог
`beacons_20261105_203251.log` покрывает v904/V651.

### 2.3. Что именно доказано артефактами (не пересказом)

1. **14.22 отгружена с открытым реентерабельным Canvas UAF.** Прогон v900 сделан
   **2026-11-05** — после релиза 14.22 (2026-11-02); UA в логе — `PlayStation 5/14.22`.
   Строка `[A-OK] stale!=live (UAF present on 14.22)` — это тот же дискриминатор, что в
   нашей пробе `p1` (`outer !== inner`). Плюс `[ALIAS] lw=811 idx=11 in-range=true`.
2. **Полный двунаправленный alias-R/W воспроизводится на 14.22 без модификаций**
   (p553: запись/чтение через stale wrapper; `P553-PROP-ALIAS` даёт 7 numeric-каналов —
   lineWidth, globalAlpha, shadowBlur, shadowOffsetX/Y, miterLimit, lineDashOffset;
   плюс `STATE-RESTORE1/2` и `MATRIX` через getTransform).
3. **Второй вектор — FontFace write-after-free — тоже жив** на 14.22 (p640, carrier 56),
   хотя первый прогон v901 (2026-11-05) ошибочно объявил его «dead»; p640 (2026-11-06)
   это отменил, и в файле v901/p553 есть явная запись об отзыве.
4. **Ограничения 14.22 (не закрытие, а последствия):** zero-at-free (v909: 6/6 смертей на
   первом чтении без реклейма — цитируется в p640/v931; независимо v913: hits=0),
   AB(768), напылённый первым, забирает слот (v904), а canvas-only спрей даёт alias;
   forge-сетка 6300 целей — `SURV 0`; текстовая база не добыта
   (p691 NOLEAK; CE-108262-9 history без адресов); JIT off (`typeof WebAssembly=undefined`).
   Это не патч входа, а другой layout/политика аллокатора.
5. **Публикация:** прогоны 5–11 ноября; коммиты в ветку — 2026-11-10/11 (head 2026-11-11
   11:33Z). То есть 14.22-специфичные **артефакты** появились после релиза, но сам баг был
   публичен с 2026-10-23 (pp V573/V630) — Sony имела 4 дня до метки образа `2026_1027` и
   всё равно не закрыла (это ответ на вопрос лида в task-17: «закрыть не могли» неверно,
   но «закрыли» — тоже неверно: **не закрыли**).

### 2.4. Чего в наборе нет (ограничения)

- **Нет нативных стеков/klog/panic/minidump** — только JS-beacon'ы; падения выводятся
  по схеме `*-PRE → следующий load = CRASH pending=…`. Это прямо признано в
  `docs/P0_WEBKIT_UAF_EVIDENCE_BASELINE.md` репозитория Khal0da и в комментариях #216.
- **UA-строка есть только в 2 логах**; остальные 28 result-файлов атрибутированы по
  `Client: 192.168.0.39` и датам, но не по UA. Для строгого доказательства хватает двух
  (это один и тот же бенч/консоль), но это надо помнить.
- **Нет бинаря WebKit/дампов памяти 14.22** — ни в этом наборе, ни где-либо публично
  (см. §5).

---

## 3. Артефакты с 14.20 (не 14.22)

### 3.1. elanonimo832 — PS5 Pro 14.20 (`АРТЕФАКТ-В-КОММЕНТАРИИ`)

- Полный JSON feature-пробника: [ZZ #184](https://github.com/ZigZagBoi1/PS5-14.10-Research/issues/184)
  (2026-11-04T03:18Z), дубль в [PP #63](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/issues/63).
  Сохранён как `elanonimo_1420/1420_pro_feature_probe_2026-11-04.json`, 3 905 Б,
  sha256 `6ff36e6f938c81e21e202f8828cce2a2144154b4db2427a985f1ea04f9c6bf7a`.
- Внутри: `userAgent … PlayStation 5/14.20 …`, `now: 2026-11-04T03:12:15.294Z`,
  `hardwareConcurrency 4`, JIT-тайминги (5M adds = 202 мс), RAB **present**, WebGL/WASM/SAB — нет.
- Сырые beacon-логи текстом в комментариях #184: p553 3/3 cold boot (20 маркеров),
  p567 `HIT 58:loaded:zz58`, p554d (alias spray[9], cross-draw), p600 (Gigacage ON).
  Файлов/логов в репо у автора нет — только эти вставки.

### 3.2. nuzDop — 14.20 (`ПЕРЕСКАЗ`)

- [PP #59](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/issues/59)
  (2026-10-29): «14.20 results: RAB removed, AB reclaim occupies-but-zeroes the slot».
  Сохранён текст: `elanonimo_1420/nuzDop_1420_probe_ladder_2026-10-29.txt`, 2 838 Б,
  sha256 `324a90e61d1e32985282216a8f9c816e653c382045cb88b6675e94d7c1eb7e8e`.
- Ни логов, ни файлов; комментарий автора темы: «Migrated to private tracking» (2026-10-29T20:44Z).
- **Противоречие с другими 14.20-данными:** nuzDop утверждает «RAB removed on 14.20»,
  а elanonimo832 (#184 JSON) и Khal0da (#3) — «RAB available». Оба — заявления/вставки,
  файлов нет; вопрос остаётся открытым (RAB-статус 14.20 не доказан ни одной стороной).

### 3.3. devravik + Mohabbadi11 — `РЕЛАБЕЛ`, не артефакты 14.20

Доказательство (файл `forensics/devravik-relabel-proof.json`, sha256 `c7761c84…`):

| Метрика | Значение |
|---|---|
| Файлов в pp (14.10) | 1 584 |
| Файлов в devravik («14.20») | 1 579 |
| Общих | 1 579 (**все** файлы devravik есть в pp; новых — 0) |
| Байт-в-байт идентичных | 1 470 |
| «Различий» | 109 |
| Из них исчезают при замене `14.10`→`14.20` в байтах pp | **108** |
| Осталось иных различий | 1 (`README.md`) |
| md5 `v480-fixed-literal-results.txt` | pp: `cc59b35c3714c610c893777bdd4945bc`; devravik: `c6e18b848519bde952d0c4b86d343dc4` |

То есть «лог 14.20» — это лог pp 14.10, в котором заменена строка UA. Репозиторий создан
2026-10-24 (`gh api repos/devravik/PS5-14.20-Jailbreak-Research` → `created=2026-10-24T19:14:51Z`,
`pushed=2026-10-24T19:21:33Z`, 3 391 КБ).
`Mohabbadi11/PS5-14.20-Jailbreak-Research` — **форк devravik** (`fork=true`,
`parent=devravik/...`), создан 2026-11-06, README md5 `06e2c8a0…` и v480-лог md5 `c6e18b84…`
совпадают с devravik. **Ни одного независимого 14.20-артефакта эти два репозитория не дают.**

### 3.4. Khal0da — 14.20 (`АРТЕФАКТ` производный, сырые логи отсутствуют)

- Репозиторий [Khal0da/PS5-14.20-WebKit-Research](https://github.com/Khal0da/PS5-14.20-WebKit-Research):
  создан 2026-11-05, 16 681 КБ; **1 814 файлов**, и все 1 584 файла pp (14.10) в нём присутствуют:
  **1 569 идентичны байт-в-байт**, 15 отличаются (правки/переименования), 230 файлов новые: `13.60/` — 53 файла
  публичных payload'ов/офсетов, 142 пробы, 16 доков, 6 результатов).
- **14.20-артефакты, которые есть:**
  `results/vc04/v923c-windows-2026-11-08.json` (21 011 Б, sha256 `dbbcd914…`),
  `v923h-windows-2026-11-08.json` (7 378 Б, `c30b629d…`),
  `v973-2026-11-09-windows.json` (8 772 Б, `66ea6621…`) — «capture windows» с timestamps,
  `outcome=crash-or-reload-after-pre`, `devMs`.
- **Сырых логов, из которых они построены, в репо НЕТ**: JSON ссылается на
  `results\beacon-logs\p0-2026-11-08\v923c-beacons.txt` и т. п., но в дереве только
  `.gitkeep`, pp-шный `session10-beacons.txt` и `v480-fixed-literal-results.txt`.
  `.gitignore` прямо исключает `*.log` и `host-beacons.log`.
- **Документы честно фиксируют ограничение** (`docs/P0_WEBKIT_UAF_EVIDENCE_BASELINE.md`,
  sha256 `5b3c1d77…`): «UAF claim level remains: **suspected, not confirmed**»;
  «No native stack/klog/panic/sigsegv/minidump in beacons»; «VC-04 … INCONCLUSIVE».
  `FINAL_REPORT.md` (`16216183…`): «No viable info-leak or ASLR defeat primitive»;
  APNG-лик «not reproducible». Issue #3 — открытый запрос «14.20 dump + JSC/WebCore diff»,
  что само по себе подтверждает: **публичного 14.20-бинаря/дампа нет**.

---

## 4. Где искали и что нашли (объём проверки)

| Проверка | Результат |
|---|---|
| `results/`, `logs/`, `artifacts/` в репо кандидатов (6 репо склонированы целиком) | См. §1–3; реальные 14.22-файлы только у TFujiwara; 14.20-логи — только в комментариях |
| Issue-треды: 260 issues в ZZ-репо и 69 в pp просмотрены по заголовкам; вручную прочитаны комментарии #184/#216/#59/#63/#61/#64/#67 (100+ КБ текста) | В этих тредах вложений-файлов **0** (`user-attachments`/gist/pastebin — ни одной ссылки). Логи — только текстом в комментариях |
| GitHub Discussions | GraphQL-запрос по `ZigZagBoi1/PS5-14.10-Research` вернул пустой список (возможно, discussions отключены) — **НЕ НАЙДЕНО** |
| Поиск репозиториев `ps5 14.22 ...`, `ps5 14.20 webkit`, `ps5 14.22 dump` | Найдено 4 репо по 14.20/14.22 (все разобраны §1) + сам TFujiwara-форк; репо с дампами/бинарями — 0 |
| Поиск кода `"26.07-14.22"`, `"PlayStation 5/14.22"` | Хиты: только списки прошивок/новости (`MewX/ps5-official-firmware-list` и т. п.); файлов-логов 14.2x в индексируемом коде — 0 (ветка TFujiwara не индексируется GitHub code search, но скачана нами) |
| Бинарь WebKit / userland-дампы 14.2x | **НЕ НАЙДЕНО**: в скачанных репо нет `*.sprx`, `*.dmp`, `libSceWebKit*`; 13.60-бинари в Khal0da — публичные payload'ы Relapse, к 14.2x не относятся; публичного 14.2x-дампа не существует (подтверждается issue #3 Khal0da и нашими task-10/11) |
| Скриншоты с адресами/версией с 14.2x | **НЕ НАЙДЕНО**: единственные картинки в 14.20/14.22-репо — стоковые `ps5-logo.png`/`ps5-console.png` (qraillife) и UI-не-скрины; в TFujiwara-ветке — только текстовые артефакты |

---

## 5. Проверка «а публиковал ли кто-нибудь вывод entry-1422-подобной пробы?»

Наш бандл печатает `P1-RESULT verdict=…`, `P2-FINGERPRINT band=…`. Публикаций ровно такого
формата (или любого аналога нашего `entry-1422`) **не найдено**: поиск кода по `"P1-RESULT"`,
`"entry-1422"`, `"stale!=live"` дал либо не-PS5 проекты, либо 0/1 нерелевантных хитов.

Но функциональные **эквиваленты** оракула на 14.22 опубликованы (TFujiwara):

| Наш дискриминатор | Аналог на 14.22 | Что показал |
|---|---|---|
| `p1`: same-type reentry 2d→2d, `outer === inner` = FIXED, `outer !== inner` = VULNERABLE | `v900` (bitmaprenderer-outer + alpha-getter, `stale!=live`) | `A-OK stale!=live` → **VULNERABLE** |
| `p1`: cross-type `bitmaprenderer`+`2d`, `outer === null` = FIXED | `v904`: `inner=OK outer=OK same=false` (17 циклов) | **VULNERABLE** |
| `p2`: полоса Safari по API | `v900`: `CAPS-OFF wasm,sab,webgl,offscreencanvas` + UA 605.1.15/17.0; `v925`: `WebAssembly=undefined` | движок 17.0-эры, LLInt-only |
| `p3`: crash-oracle | v909 (6/6 смертей на первом чтении freed ctx, цитата в p640/v931), v913 (hits=0) | crash да, но без адреса/нативного стека |

То есть ответ на вопрос «запускал ли кто нашу пробу» — **нет**, но **ответ на её главный
вопрос для 14.22 уже есть в публичных артефактах**: вектор открыт (VULNERABLE).

---

## 6. Карта доказательств по 14.2x (только то, что подтверждено файлами)

| Утверждение | Статус | Чем доказано |
|---|---|---|
| 14.22 отгружена с UA `605.1.15 / 17.0` (движок не ребейзнут) | `АРТЕФАКТ` | лог `beacons_20261105_172139.log` (UA 14.22), результат v900 |
| Canvas `getContext` reentrancy UAF жив на 14.22 | `АРТЕФАКТ` | v900 `A-OK`; v904 `same=false` ×17 |
| Full bidirectional alias R/W на 14.22 (7 numeric-каналов + state/transform) | `АРТЕФАКТ` | p553 result + лог p553 |
| FontFace write-after-free ложится на 14.22 | `АРТЕФАКТ` | p640 (`HIT 56:loaded:zz56`), v919, v930/v931 |
| Freed ctx chunk на 14.22 обнуляется при free | `АРТЕФАКТ` (observer-grade) | p640 (цитата v909: 6/6), v913 (hits=0) |
| AB(768) забирает слот раньше canvas (на 14.22) | `АРТЕФАКТ` | v904 (17 циклов) |
| Forge-сетка ~6300 целей: 0 SURV на 14.22 | `АРТЕФАКТ` | v911 close, сырой v911 band0 |
| JIT/LLInt: `typeof WebAssembly=undefined` на 14.22 | `АРТЕФАКТ` | v925; erratum v924 |
| Лик/адрес/ASLR на 14.22 не добыты | `АРТЕФАКТ` | p691 NOLEAK, CE-108262-9 history (нет адресов), v931 |
| Входной баг закрыт в 14.22 | **ОПРОВЕРГНУТО** | v900/p553/v904 (14.22 UA) |
| «14.22 добавила context-change guard» (kevinisgoated24) | `ПЕРЕСКАЗ`, опровергнут | у автора нет ни лога, ни теста; v900 показывает обратное |
| «14.20: RAB removed» (nuzDop) | `ПЕРЕСКАЗ`, противоречит | #184 JSON: RAB present; Khal0da #3: RAB available |
| 14.20 «лог 14.20» в репо devravik/Mohabbadi11 | `РЕЛАБЕЛ` | 108/109 различий = замена `14.10→14.20`; новых файлов 0 |

---

## 7. Что это меняет для task-17 (вердикт по 14.22)

В `recon/webkit-1422-verdict.md` §5 стояла `ОЦЕНКА`: «вход в 14.22, скорее всего, не закрыт,
но нужен тест на консоли». **Теперь это `ФАКТ` (публичный артефакт):**

- `[A-OK] stale!=live (UAF present on 14.22)` — `v900_fw1422_recon_20261105.txt`
  (прогон 2026-11-05, UA 14.22 в `beacons_20261105_172139.log`);
- `P553-REVERSE-OK: FULL BIDIRECTIONAL R/W CONFIRMED` — `p553_write_confirm_14.22_20261105.txt`
  (2026-11-05, UA 14.22 в `beacons_20261105_175742.log`);
- `V904-UAF inner=OK outer=OK same=false` ×17 — `beacons_20261105_203251.log`.

**Вывод task-17 уточняется:** вектор в 14.22 **не закрыт**; наша проба `p1` на консоли 14.22
дала бы `VULNERABLE` (если только Sony не выпустит 14.23+ с бэкпортом). Это не отменяет
пользу bundle: он даёт наш собственный контроль с логом `P1-RESULT` и не зависит от чужого
бенча. Добавлено в `recon/webkit-1422-verdict.md` (раздел «ОБНОВЛЕНИЕ после task-22»).

---

## 8. Ошибки/противоречия, найденные в публичных материалах (чтобы не тиражировать)

1. **devravik/Mohabbadi11 «14.20»** — механический релабейл pp 14.10 (§3.3). Все «14.20-логи»
   и «14.20-фингерпринты» из этих репо использовать нельзя.
2. **nuzDop #59** против **elanonimo832 #184** и **Khal0da #3**: «RAB removed» vs «RAB present»
   на 14.20. Оба — без файлов; фиксировать как открытое противоречие, не как факт.
3. **TFujiwara v901/p553**: «FontFace chain patched/dead» (2026-11-05) отменено их же
   p640 (2026-11-06) — в p553-файле отзыв есть, но в старых доках строка осталась.
4. **TFujiwara v924**: «JIT-PRESENT» (47 мс) отменено их же v925 (Wasm undefined, LLInt-only);
   в v924-файле и erratum это зафиксировано.
5. **ZigZag p635** ссылается на «WebKit fix commit 2693828e8d73» — это YARR-фикс от
   2026-02-18, не canvas-фикс (проверено в task-17); настоящий фикс — `040ef6e2…`.
6. **Khal0da/pp-копия**: 1 584 файла из pp 14.10 вошли в «14.20»-репо байт-в-байт; любые
   «14.10-выводы» там остаются 14.10-выводами, несмотря на заголовок 14.20.

---

## 9. Воспроизведение (команды)

```bash
# 1) ветка с 14.22-артефактами (спарс-клон только нужных каталогов)
git clone --depth 1 --filter=blob:none --sparse \
  --branch research/tfujiwara-v919-v929-campaign \
  https://github.com/TFujiwara/PS5-14.10-Research.git tfj
cd tfj && git sparse-checkout set results/phase13_webkit probes/phase13_webkit \
  tools/browser_runner/beacon_logs
grep -rl "PlayStation 5/14.22" results/ tools/ | head        # -> 4 файла
grep -rhoE "BEACON 192\.168\.0\.39" tools/ | wc -l          # -> 27796

# 2) релабейл-доказательство
git clone --depth 1 https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research.git pp
git clone --depth 1 https://github.com/devravik/PS5-14.20-Jailbreak-Research.git dv
# (результат сравнения — recon/_src/artifacts-1422/forensics/devravik-relabel-proof.json;
#  воспроизведение: md5 всех общих файлов двух клонов + замена 14.10->14.20 в байтах pp)

# 3) хеши всего скачанного
cd ps5jb/recon/_src/artifacts-1422 && sha256sum -c MANIFEST.sha256
```
---

## 10. ПРОДОЛЖЕНИЕ (по запросу лида): что есть у TFujiwara — полная инвентаризация

Проверено по клону ветки `research/tfujiwara-v919-v929-campaign`
(head `16e7c9e20cf4ff57de8953b121b21e7c46a83f2c`, 2026-11-11T11:33:47Z) и API GitHub.

### 10.1. Какие пробы гонялись на 14.22

В ветке **31 probe-файл** серии `v900–v931` (`probes/phase13_webkit/`; 26 из них с `v9xx`
в имени result-файла), и к ним **30 result-файлов** с `PS5 14.22` + **60 beacon-логов** от клиента
`192.168.0.39` (27 796 beacon-строк). Назначение серии:

| Проба | Что проверяла на 14.22 | Результат (файл) |
|---|---|---|
| v900 | рекогносцировка: UA/фичи + Canvas-UAF trigger + alias-reclaim | `A-OK stale!=live`, `ALIAS lw=811 idx=11` |
| v901 | FontFaceSet free-дискриминатор | сначала «dead», отменено p640 |
| v902/v903 | сканы 265 forged reads | 0 |
| v904 | reclaim-type discrimination (AB-first vs canvas) | 17 циклов, `same=false`, AB забирает слот |
| v905/v906/v907/v908/v909/v910 | stateStack-буфер/offset-invariant/dense sweep; zero-at-free | v905: 129/129 crash; v909 (цит.): 6/6 crash на первом чтении |
| v911 | двух-армный differential grid, band 0–5, ~6300 целей | `SURV 0`, `PAIR 0`, `RECON 0` (close 2026-11-09) |
| v912/v913 | AB(192)/FontFace pair-leak | v912: AB-смерть; v913: hits=0 |
| v914/v915/v916 | positive control / forge control / cell-everywhere | v914 refuted by design, v915 run-1 void (T-bug), v916 lane closed |
| v918–v923 | APNG (Bug 321753-class) recon/killer | no-IDAT APNG убивает WebProcess (DoS), no leak |
| v924/v925 | JIT/tier decider | v924 JIT-PRESENT **отменено**; v925 `WebAssembly=undefined` → LLInt-only |
| v926/v927/v928 | bitfit-192 каталог, 24213 float patterns, sort-shrink | v926 negative, v927-C retracted, v928 clean |
| v929/v930/v931 | FontFace census/style map (zero-at-free era) | v929 clean descriptor; v930/931 corruption witness без адреса |

Ключевые result-файлы уже скачаны в `TFujiwara_1422_bench/results/` (см. §2.2 и
`MANIFEST.sha256`); сырые логи — `TFujiwara_1422_bench/logs/`.

### 10.2. Есть ли userland-артефакты (дампы модулей, WebKit-бинарь, память процесса)?

**НЕТ.** Доказательства:

1. Diff ветки против `master` (GitHub compare `master...branch`): **ahead 98, behind 43**;
   изменено 191 файл. Все добавленные — `.md`, `.html`, `.js`, `.txt` (пробы/результаты/доки).
   Фильтр по расширениям `bin|elf|sprx|pkg|zip|7z|img|raw|dump|mem|dmp|so|exe` среди
   **added-файлов — 0**.
2. Крупные бинари, которые видны в дереве ветки, — **унаследованы из upstream master**,
   а не добавлены TFujiwara (проверено `gh api .../contents/...` в master):
   `docs/dumps_13.60/kernel_text.bin` — 15 132 096 Б (13.60!),
   `docs/dumps_13.60/kernel_data.bin` — 4 194 304 Б (13.60),
   `artifacts/pup14/deployed-elfldr-ps5-1360.elf` — 397 024 Б (13.60).
   К 14.22 они отношения не имеют.
3. В результатах 14.22 — только JS-beacon'ы и текстовые выписки. Нативных стеков/klog/
   minidump нет; единственный «ошибочный» артефакт — `CE-108262-9` error history,
   и он **generic** (0 hex, 0 кадров): `ce_108262_9_error_history_generic_20261109.txt`.
4. В PR #250 (30 файлов) — тоже только docs/probes, ни одного бинарного файла.

### 10.3. Автор и канал публикации

- **GitHub**: `TFujiwara` (id 10372989), аккаунт с 2015-01-02; профиль: «Sysadmin. Anime en
  general e Initial D. CEO de FUKRE eSports. Aficionado a la ciberseguridad…»,
  company «Soluciones Cuatroochenta», location Vila-Real (Spain), blog
  `blog.tfujiwara.tech`, Twitter **@TFujiwara86**, 21 публичный репозиторий, 14 подписчиков.
- **Канал публикации 14.22-артефактов**: (1) форк `TFujiwara/PS5-14.10-Research`,
  ветка `research/tfujiwara-v919-v929-campaign`; (2) **PR #250** в `ZigZagBoi1/PS5-14.10-Research`
  «Research/tfujiwara v919 v929 campaign» — **open**, создан 2026-11-10T22:48:51Z,
  обновлён 2026-11-11T11:42:02Z, 30 файлов, ревью ArjunD717 (механические замечания:
  p690/p691 закоммичены в UTF-16LE); (3) комментарии в issue **#216** и **#184** того же
  репозитория (там же — сырые логи текстом). PR body пуст (`body: null`). **Ни Telegram,
  ни внешних файлохранилищ в PR/комментариях/README не найдено** (grep по `telegram|discord|
  mega|drive.google|dropbox|gist|upload`); в README **родительского** репозитория есть общий
  Discord проекта — `discord.gg/aznssydKrx` — но это общий канал проекта, не TFujiwara и не
  канал публикации артефактов.
- В upstream master артефактов 14.22 **нет** (проверено: `v900_fw1422_recon…` и др. в
  дереве master отсутствуют), т.е. публикация = форк + PR + issue-треды.

### 10.4. Что это добавляет к доказательной базе (и чего не добавляет)

- Добавляет: **не 2 лога, а 60** beacon-логов от того же клиента `192.168.0.39`
  (суммарно 27 796 beacon-строк) + 30 result-файлов с разбором; UA 14.22 — в 4 файлах
  (2 result, 2 лога). Набор внутренне последователен и прошёл независимую ревизию
  cobrajet302gt/4TheDoctor в #216 (включая self-retractions автора: v901→p640, v924→v925,
  erratum по часовому поясу).
- Не добавляет: дампов, WebKit-бинаря, памяти процесса, kernel-адресов. Адрес/лик на 14.22
  не добыты (p691 NOLEAK, v911 grid zero, CE history generic) — цепочка до kernel R/W
  по-прежнему упирается в отсутствие leak. Ветка не смержена (PR open), upstream master
  её не содержит.
