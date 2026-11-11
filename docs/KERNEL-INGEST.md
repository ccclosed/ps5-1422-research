# KERNEL-INGEST: как из образа ядра PS5 получить константы Relapse одной командой

**Аудитория:** тот, у кого в руках оказался расшифрованный образ ядра 14.22 (или любой другой PS5).
**Инструмент:** `tools/payload/scan_1322.py` — конвейер: *образ ядра + версия → JSON со всеми константами*.
**Статус:** отлажен и проверен на реальном дампе ядра **13.60** (18 констант сверены с публичным
`offsets/13.60.js`, расхождений 0; единственный WARN — `nodeMutex`, разобран ниже).
**Дата:** 2026-11-11.

---

## 0. TL;DR — что делать, когда придёт образ

```bash
cd /home/oleg/Документы/ps5semulator/ps5jb

# 1) один запуск: образ + версия -> JSON со всеми константами
python3 tools/payload/scan_1322.py --image <путь к образу ядра> --fw 14.22

# 2) результат: tools/payload/offsets-14.22.json (+ готовый JS-блок, если нужен)
python3 tools/payload/scan_1322.py --image <образ> --fw 14.22 \
        --out tools/payload/offsets-14.22.json --js-out /tmp/offsets-14.22.js
```

Время: **~0.9 с на 103 МБ образа** (замер на 13.60: 0.82–0.87 с, пик RSS ~120 МБ). Никаких зависимостей, только stdlib Python 3.

До появления образа уже готов шаблон: `tools/payload/offsets-14.22.json` (Tier-1 из SDK заполнен,
остальное помечено `unknown`/`console`, есть поле `next_actions`).

---

## 1. Что нужно на входе

| Вход | Требование |
|---|---|
| Образ ядра | расшифрованный. Либо **плоский дамп памяти** `text+data` подряд, либо **ELF** (PT_LOAD разбираются автоматически) |
| Версия FW | `--fw 13.60`, `--fw 14.22`, … (влияет на per-FW таблицу SDK и поиск эталона `offsets/<fw>.js`) |
| SDK-дерево | `tools/fwsim/vendor/sdk/crt/kernel.c` (уже в репозитории; путь можно задать `--sdk`) |
| Раскладка (только для плоского дампа) | `--text-va <VA начала text>` и `--data-rva <RVA начала data>`; для 13.60 известна и подставляется сама |
| Эталон (опционально) | `offsets/<fw>.js` из клона Relapse в `recon/_src/relapse/*/offsets/` — тогда конвейер сразу сверяет значения |

Поддерживаемые варианты раскладки:

* **дамп, где file_offset == RVA** (как `fw/ps5-kernel-13.60-live.bin`: text с offset `0x0`,
  data с offset `0xCC0000` = `kernelData`) — самый удобный случай, ничего указывать не нужно;
* **ELF** — достаточно `--image file.elf`; для плоского нестандартного дампа — `--text-va/--data-rva`.

---

## 2. Что выдаёт конвейер (JSON)

`tools/payload/offsets-14.22.json` — схема `ps5-kernel-constants/1`:

```jsonc
{
  "schema": "ps5-kernel-constants/1",
  "firmware": "14.22",
  "status": "ok" | "waiting-for-image",
  "image": {"path", "kind": "flat|elf|absent", "size", "sha256", "text_va", "data_rva", "zero_pages"},
  "sdk": {"case": "0x14220000", "D", "A", "S", "R"},        // сырые смещения из kernel.c
  "reference": {"path": "…/offsets/13.60.js", "values": {…}}, // если эталон найден
  "constants": {
      "kernelData": {"value": 13500416, "hex": "0x00CE0000",
                     "source": "sdk", "evidence": "…kernel.c: case 0x14220000", "confidence": "exact"},
      "oid.a.base": {"value": …, "hex": …, "source": "scan", "evidence": "скан по имени 'cpus'…",
                     "reference": …, "reference_match": true}
      // …
  },
  "relapse_offsets_js": "…готовый блок window.KRW…",
  "notes": [ … самопроверки … ],
  "next_actions": [ … что делать дальше (только когда образа нет) … ],
  "summary": {"total", "by_source", "reference_matches", "reference_mismatches", "warnings",
              "critical_mismatches", "predictions"}
}
```

### Пометка источника — главное в формате

| `source` | Значение | Можно ли писать в `offsets/<fw>.js` |
|---|---|---|
| `sdk` | точно из per-FW таблицы `ps5-payload-dev/sdk` (`crt/kernel.c`) | **да**, это первоисточник |
| `scan` | найдено сканом по образу (те же признаки, что у `relapse-offset-dumper`) | **да**, если `confidence: exact` и `reference_match != false` |
| `predict` | предсказано по тренду соседних FW (для `kaslr.retStatic`) | **нет**, только как стартовая точка/окно поиска |
| `console` | из образа не извлекается в принципе | **нет**, нужен запуск на консоли |
| `unknown` | не найдено (нет образа или объект отсутствует) | нет |

`confidence`: `exact` — подтверждено чтением/сверкой; `exact-unverified` — из SDK, но образа нет;
`medium` — выведено из другого поля; `low` — эвристика/предсказание.

---

## 3. Что именно ищет конвейер (признаки)

| Константа | Признак | Ограничения |
|---|---|---|
| `kernelData`, `allproc`, `rootvnode`, `security_flags` (+`TARGETID`/`QA_FLAGS`/`UTOKEN_FLAGS`) | per-FW таблица SDK: `Relapse = D + X`, где `D = DATA_BASE − TEXT_BASE` | нужен `case` для FW в `kernel.c`; иначе `unknown` |
| `rodataProbe.rva` | строка `"_aio_submit_cmd"` с `\0` в `.rodata`; диапазоны `0x01000000–0x01400000`, затем `0x00800000–0x01800000` | если строку переименовали — не найдёт |
| `oid.a` | `struct sysctl_oid` с `kind==0x80048002` и `name == "cpus"` (поля `kind@+0x14`, `arg1@+0x18`, `number@+0x10`, `name@+0x28`, `handler@+0x30`) | `kind` у целевых OID может быть `0x7F048002` (как у `oid.b`) — поэтому идентификация по имени, а не только по kind |
| `oid.b` | `name == "maxcpus"` | то же |
| `oid.c` | `name == "priority_scheduling"` + `number == 8` | то же |
| `walkCounter` | `= oid.c.arg1Value − 4`, читается 32 бита | зависит от `oid.c` |
| `nodeMutex` | мьютекс, чей `lo_name(+0x00)` указывает на `"sysctl lock"` / `"sysctl"` | **эвристика ненадёжна**, см. §4 п.2 |
| `kaslr.retStatic` | предсказание `kernelData + delta` (delta: mean `−0x1D9797`, окно `−0x1E150F…−0x1CBE6F` по 33 FW) + список адресов возврата после `call rel32` в этом окне | **точно только с консоли** (RTM_GET) |
| `aio/proc/ucred/filedesc/pipe/dynlib` | не извлекаются: `console`/сверка с 13.60 | структуры ядра, а не адреса |

---

## 4. Проверка конвейера на реальном ядре 13.60 (что сошлось и что нет)

Команда: `python3 tools/payload/scan_1322.py` → лог `tools/payload/scan-13.60.log`,
JSON `tools/payload/offsets-13.60.json`.
Вход: `fw/ps5-kernel-13.60-live.bin` (103 546 880 Б, sha256 `c3f745e2…`), text_va `0xFFFFFFFF9E3F0000`.
Эталон: `recon/_src/relapse/*/offsets/13.60.js`.

**Итог: 33 константы, из них 18 сверены с эталоном — совпали все 18. Критических расхождений 0.**

| Константа | Получено | Эталон 13.60 | Вердикт |
|---|---|---|---|
| `kernelData` | `0x00CC0000` | `0x00CC0000` | ✅ |
| `allproc` | `0x03589E80` | `0x03589E80` | ✅ (`*allproc = 0xFFFF8E777997D9E0`, direct-map) |
| `security_flags` | `0x01A5C064` | `0x01A5C064` | ✅ (`* = 0x00000017`) |
| `rootvnode` | `0x03E0B510` | `0x03E0B510` | ✅ (`* = 0xFFFF8E77033BCF00`, direct-map) |
| `rodataProbe.rva` | `0x01379D6C` | `0x01379D6C` | ✅ |
| `oid.a.{base,kind,arg1,arg1Value}` | `0x028CEF68`, `0x028CEF7C`, `0x028CEF80`, `0x028CEF58` | те же | ✅ 4/4 |
| `oid.b.{base,kind,arg1,arg1Value}` | `0x028CEE40`, `0x028CEE54`, `0x028CEE58`, `0x028CED70` | те же | ✅ 4/4 (`kind=0x7F048002`) |
| `oid.c.{base,kind,arg1,arg1Value}` | `0x02BF1C38`, `0x02BF1C4C`, `0x02BF1C50`, `0x03D831BC` | те же | ✅ 4/4 |
| `walkCounter` | `0x03D831B8` | `0x03D831B8` | ✅ |

### Расхождения (3) — разобраны

1. **`nodeMutex`: конвейер даёт `0x0358A5A8`, эталон `0x01A9BAB8` → WARN, не ошибка.**
   Эвристика дампера (мьютекс с именем `"sysctl lock"`) находит **3 кандидата**:
   `0x0358A5A8` (`lo_name="sysctl lock"`), `0x01AD6030` и `0x0256A350` (`lo_name="sysctl"`).
   Фактическое значение из Relapse (`0x01A9BAB8`) — это мьютекс с `lo_name = "ntpadj"`
   (`+0x08 = 0`, не заблокирован), и ни один кандидат по имени на него не указывает.
   **Вывод:** `nodeMutex` нельзя брать из скана по имени; либо переиспользовать смещение при
   неизменной структуре, либо валидировать тестом UAF на консоли. Конвейер честно помечает его `low`.
2. **`kaslr.retStatic`: предсказание `0x00AE6869`, истина `0x00AE2DA0` → дельта `−0x3AC9`.**
   Истина **попала в предсказанное окно** `0x00ADEAF1…0x00AF4191` и является адресом возврата после
   `call rel32` (проверено). То есть окно рабочее, но точное значение — только с консоли.
3. **`kaslr.retLow16`**: младшие 16 бит предсказания (`0x6869`) не совпадают с эталоном (`0x2DA0`) —
   это следствие п.2, точное значение даёт тот же RTM_GET-лик.

---

## 5. Playbook: «пришёл расшифрованный образ 14.22»

Оценка времени — для человека, который делает это впервые; сам конвейер считает секунды.

| # | Шаг | Команда | Время |
|---|---|---|---|
| 1 | Положить образ в `fw/`, зафиксировать хеш | `sha256sum fw/<образ>` | 1 мин |
| 2 | Убедиться, что версия есть в SDK-таблице | `grep -n "case 0x14220000" tools/fwsim/vendor/sdk/crt/kernel.c` | 10 с |
| 3 | **Запустить конвейер** | `python3 tools/payload/scan_1322.py --image fw/<образ> --fw 14.22 --js-out /tmp/krw.js` | **1–2 с** |
| 4 | Прочитать сводку | в конце вывода: `ИТОГО: констант=… сверка: OK=… MISMATCH=…` | 1 мин |
| 5 | Проверить `status`/`source` в JSON | `jq '.status, .summary' tools/payload/offsets-14.22.json` | 1 мин |
| 6 | Если все `scan`-константы `exact` — перенести их в `offsets/14.22.js` вместе с SDK-частью | готовый блок — в `relapse_offsets_js` (или `/tmp/krw.js`) | 5 мин |
| 7 | Вручную добавить `kindByte3`/`arg1Byte1`/`deadSink`/`visible` (по образцу 13.60: `kind+3`, `arg1+1`, `a.base+0x20`, `b.base+0x50`) | см. §6 | 10 мин |
| 8 | Перенести `aio/proc/ucred/filedesc/pipe/dynlib` из 13.60 (если структуры не менялись) | сверить блоки в `offsets/*.js` | 15 мин |
| 9 | Измерить `kaslr.retStatic`/`retLow16` на консоли | `nc <ip> 9021 < relapse-dumper.elf` → `/data/relapse_dump/offsets.txt` | 10 мин |
| 10 | Прогнать тест цепочки на железе | host → User's Guide → Jailbreak | — |

**Итого: 30–45 минут** от появления образа до заполненного `offsets/14.22.js`, из которых секунды —
работа конвейера, остальное — ручная сборка полей и проверки.

### Если образа 14.22 пока нет (сегодняшнее состояние)

```bash
# шаблон с Tier-1 из SDK и заглушками на остальное:
python3 tools/payload/scan_1322.py --fw 14.22 --sdk-only
# -> tools/payload/offsets-14.22.json, status = "waiting-for-image", next_actions[...]
```

Уже заполнено (SDK, `kernel.c:567-576`, case `0x14220000`):

| Константа | 14.22 |
|---|---|
| `kernelData` | `0x00CE0000` |
| `allproc` | `0x035B9EA0` |
| `security_flags` | `0x01A84064` |
| `rootvnode` | `0x03E3B510` |
| `TARGETID` / `QA_FLAGS` / `UTOKEN_FLAGS` | `0x01A8406D` / `0x01A84088` / `0x01A840F0` |
| `VMSPACE_P_ROOT` / `VMSPACE_VM_PMAP` | `0x1d0` / `0x2e8` |
| `kaslr.retStatic` (предсказание) | `0x00B06869`, окно `0x00AFEAF1…0x00B14191` |

Остальные 15 констант (`rodataProbe`, `oid.*`, `nodeMutex`, `walkCounter`) — `unknown` до появления образа.

---

## 6. Чего конвейер НЕ делает (и почему)

1. **Точный `kaslr.retStatic`.** Это RVA адреса возврата, который утекает через живой `RTM_GET`
   на `PF_ROUTE`. В статическом образе такого «значения» нет — есть только код. Конвейер даёт
   предсказание + окно + список call-return кандидатов. Точное значение — `relapse-offset-dumper`
   на консоли (1 запуск) или собственный RTM_GET-лик.
2. **Производные байтовые адреса OID.** В `offsets/*.js` кроме `base/kind/arg1/arg1Value` есть
   `kindByte3` (= `kind+3`), `arg1Byte1` (= `arg1+1`), `deadSink` (= `base+0x20` в терминах 13.60),
   `visible`. Их конвейер не считает, потому что связь `deadSink`/`visible` с полями структуры
   проверена только на 13.60. Брать из `base` по образцу `offsets/13.60.js` и сверять глазами.
3. **Структурные смещения** (`aio.*`, `proc.*`, `ucred.*`, `filedesc*`, `pipe.*`, `dynlib.*`).
   Это не адреса, а layout структур ядра; на 7.00–13.60 они идентичны, но проверить их по дампу
   можно только сравнением структур. Если 14.22 их подвинула — узнаем лишь тестом/дизасмом.
4. **Достоверность `nodeMutex`** — см. §4 п.1.

---

## 7. Troubleshooting

| Симптом | Причина | Что делать |
|---|---|---|
| `ОШИБКА: для плоского дампа нужен --text-va` | дамп без известной раскладки | указать `--text-va` и `--data-rva` (data_rva обычно = `kernelData` из SDK) |
| `образ: ОТСУТСТВУЕТ — только SDK-часть` | нет файла | это и есть режим шаблона; положить образ или `--sdk-only` осознанно |
| `SDK: НЕ НАЙДЕНА` | нет `case` для FW в `kernel.c` | обновить SDK-дерево или указать `--sdk <путь>`; без таблицы SDK-часть будет `unknown` |
| много `unknown` после скана | образ не той версии / имена строк переименованы | проверить `--fw`, посмотреть `notes` (сколько OID с `kind=0x80048002` нашлось) |
| `zero_pages` большое (в 13.60 — 12 073) | в дампе есть несмонтированные страницы | норма для live-дампа; скан их переживает, но объект мог попасть в дыру — перепроверить по второму дампу |
| `reference_match: false` у `oid.*` | образ другой сборки или эталон от другой FW | доверять скану (он читает структуру), сверить `name`/`number` в `evidence` |
| расхождение `nodeMutex` | известная проблема эвристики | игнорировать значение, см. §4 п.1 |

---

## 8. Артефакты

| Файл | Что это |
|---|---|
| `tools/payload/scan_1322.py` | сам конвейер (stdlib-only, 923 строки, `--help`) |
| `tools/payload/offsets-14.22.json` | шаблон 14.22: Tier-1 из SDK заполнен, остальное `unknown`/`console` |
| `tools/payload/offsets-13.60.json` | результат прогона на реальном дампе 13.60 (валидация) |
| `tools/payload/scan-13.60.log` | полный вывод прогона 13.60 (таблица + самопроверки) |
| `tools/payload/scan-14.22-sdk-only.log` | вывод генерации шаблона 14.22 |
| `tools/payload/offsets-14.22.md` | пояснительная записка: откуда формула, что даёт SDK, оценки дрейфа |
| `recon/relapse-anatomy.md` §9 | «можно ли применить Relapse к 14.22» — выводы и риски |

Связанные данные: `fw/ps5-kernel-13.60-live.bin` (+ `ps5-kernel-13.60-sysent/DUMP_CAPTURE_README.md`),
`tools/fwsim/vendor/sdk/crt/kernel.c` (per-FW таблица), `recon/_src/relapse/*/offsets/*.js` (33 эталона).