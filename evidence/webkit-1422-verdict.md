# WebKit-вектор входа и прошивка 14.22: ревизия, фикс, даты

Дата работы: 2026-11-11. Задача task-17. Каждое утверждение помечено статусом и имеет
дату/ссылку/команду. Проверки выполнялись в этой сессии на машине `oleg` (Nobara, без root).

Легенда:
`ФАКТ` — проверено в этой сессии командой или первичным источником;
`ЗАЯВЛЕНО` — написано в публичном репозитории/статье, независимо не подтверждено;
`ОЦЕНКА` — мой вывод из дат/кода, не факт;
`НЕ ПРОВЕРЕНО` — не проверял.

---

## 0. ДОПОЛНИТЕЛЬНЫЙ ВОПРОС ЛИДА: успели ли Sony закрыть в 14.22 входные баги,
## публично отработанные на 14.10/14.20

### 0.1. Хронология публикаций (все даты UTC, GitHub API)

| Дата | Событие | Чем подтверждено |
|---|---|---|
| 2026-10-16 | `ZigZagBoi1/PS5-14.10-Research` создан (486★, «Kernel R/W … not demonstrated») | `gh api repos/ZigZagBoi1/PS5-14.10-Research` → `created=2026-10-16T00:46:59Z` |
| 2026-10-18 04:11 | `pastawithpesto/PS5-14.10-Jailbreak-Research` создан | `gh api repos/pastawithpesto/...` → `created=2026-10-18T04:11:40Z` |
| 2026-10-22 12:47 | zz: `probes/phase13_webkit/p166-canvas-reentrant-identity.js` — JS-оракул реентерабельного `getContext` | `gh api '…/commits?path=probes/phase13_webkit/p166-canvas-reentrant-identity.js'` → `2026-10-22T12:47:46Z feb485ad` |
| 2026-10-23 05:34 | pp: коммит `05c33ac7` «Add remaining 23 canvas UAF probes (v569-v599 + vshell)» | `gh api '…/commits?path=probes/canvas-uaf/v573.html'` → `2026-10-23T05:34:26Z 05c33ac7` |
| 2026-10-23 06:40 | pp: коммит `15fc5328` «Add V600-V643 probes, update findings: **CVE-2026-43720 full R/W confirmed**» | `gh api '…/commits?per_page=40'` (тот же список) |
| 2026-10-26 13:59/15:10 | zz: коммиты `ac94ee84`, `9f624fc4` — рабочий Canvas-UAF пробник `p550` («desynchronized trigger, same-type R/W») | `gh api '…/commits?path=probes/phase13_webkit/p550-canvas-uaf-transform-leak.js'` |
| 2026-10-27 | **метка образа 14.22 = `2026_1027`** (URL Sony `…/image/2026_1027/sys_b0d5818d…/PS5UPDATE.PUP`, HTTP 200, 1 266 091 008 Б) | `recon/1422-exists.md:17`, проверено `curl`/`tools/pup/fetch.py` |
| 2026-10-29 18:59–19:17 | zz: публикация «43 WebKit evidence files» — файлы прогонов p551/p553/p565 и др. | `gh api '…/commits?path=results/phase13_webkit/p551_…txt'` → `2026-10-29T19:1x` |
| 2026-10-31 | pp issue #61: «[FW 14.00] Independent Canvas getContext re-entry: 2 DIFF / 2 MATCH + negative controls» — независимое репро на **14.00** | `gh api 'repos/…/issues?state=all'` → `61 created=2026-10-31T02:58:28Z` |
| 2026-11-02 | релиз 14.22 (`26.07-14.22.00`), официальные примечания: «We've made some security fixes to the system software» | `recon/1422-status.md:26-27, 64` (GBAtemp/IGN как вторичные) |
| 2026-11-04/05 | pp/zz: публикация p553 (bidirectional R/W на 14.10) и p635 (CVE-2026-43720 VULNERABLE на 14.10) | `gh api '…/commits?path=results/phase13_webkit/p553_…txt'` → `2026-11-05T01:07:32Z`; `p635…` → `2026-11-05T03:26:36Z` |
| 2026-11-09 | zz `docs/ISSUE_RESPONSES_2026-11-09.md`: «elanonimo832 also independently confirmed the Canvas2D UAF on 14.20 (3/3 cold boots)» | `ЗАЯВЛЕНО` (третья сторона, артефактов в репо нет) |
| 2026-11-10 04:54 | `kevinisgoated24-spec/PS5-14.20-Jailbreak-Research` создан (0★, порт canvas UAF на 14.20) | `gh api repos/…` → `created=2026-11-10T04:54:48Z`, `pushed=2026-11-10T05:32:17Z` |
| — | X/форумы/внешние write-up'ы | `НЕ ПРОВЕРЕНО`: первичных ссылок с датами не нашёл; даты ниже — только GitHub |

Даты фаз pp (по коммитам master): **V573** — коммит `05c33ac7` 2026-10-23 05:34 («v569-v599»);
**V630** — коммит `15fc5328` 2026-10-23 06:40 («V600-V643 … full R/W confirmed»).
Артефакта **V674** в pp master нет (в commit-логе pp он не встречается; zz фиксирует
«pastawithpesto V674 not reproducible», `results/phase13_webkit/v674_canvas_api_info_leak_20261029.txt`,
дата файла 2026-10-29). То есть вся canvas-цепочка pp опубликована **2026-10-23**, за 4 дня
до метки образа 14.22.

### 0.2. Ответ по датам

1. `ФАКТ`: **входной баг, отработанный на 14.10, — это CVE-2026-43720 / WebKit bug 313175
   (реентерабельный `HTMLCanvasElement::getContext()`, canvas UAF).** Он публично опубликован
   с кодом и заявлением «full R/W confirmed» **2026-10-23**, а JS-оракул — **2026-10-22**.
   Для 14.10 образ `2026_0928` (Sony Last-Modified 2026-10-14, `recon/1422-exists.md:15,217`).
2. `ФАКТ`: демонстрация **на 14.20** появилась **после** метки образа 14.22 `2026_1027`:
   репозиторий `kevinisgoated24-spec` создан **2026-11-10**, независимое репро 14.20 упомянуто
   в issue-ответах **2026-11-09**. Реактивно (по факту публикации) Sony закрыть это в 14.22
   не могла.
3. `ФАКТ`, важный для логики: 14.20-репозиторий — **не новый баг, а порт того же** canvas UAF:
   его README дословно: «Porting and extending [pastawithpesto's PS5 14.10 WebKit research] to
   firmware 14.20» (`recon/_src/kg/README.md:3`). Поэтому дата 2026-11-10 не создаёт нового
   кандидата: кандидат был публичен с 2026-10-23, т.е. **до** `2026_1027`.
4. `ОЦЕНКА` по правилу дат: поскольку демонстрация входного бага была **ДО** `2026_1027`
   (23 окт < 27 окт; LS-дата образа 30 окт 02:30 GMT — `recon/1422-exists.md:242`), **нельзя
   утверждать «в 14.22 закрыть не могли»**. Наоборот: у Sony было ~4 дня до метки образа
   (и 10 дней до релиза 2 ноя) + официальная строка «some security fixes» в 14.22.
   По правилу лида этот кандидат считается **потенциально закрытым**, а не «живым».
5. `ОЦЕНКА`, почему «потенциально», а не «закрыт»: 4 дня — крайне мало для бэкпорта WebKit;
   публичных следов бэкпорта, дизасма WebKit 14.22 или теста на 14.22 **нет ни у кого**
   (`recon/1422-status.md:107-118`: «Бинарный дифф 14.20 → 14.22 по WebKit-модулю — нет;
   Тест на живой 14.22 — нет»). 14.20-образ `2026_1014` старше публикации (23 окт), поэтому
   14.20 реактивно не патчилась — это согласуется с заявлениями о работающем репро на 14.20.
6. Итог: **14.20-специфичного «живого на 14.22» кандидата по датам нет**, потому что это тот же
   баг, опубликованный раньше. Единственная 14.22-специфичная проверяемая без ядра гипотеза —
   «Sony всё-таки влила бэкпорт 313175 в 14.22 между 23 и 27 октября» — проверяется только
   пробой на консоли 14.22 (bundle §5) или дизасмом WebKit 14.22 vs 14.20. См. §3 и §5.

---

## 1. Какая ревизия WebKit в прошивках PS5 14.x

### 1.1. Что известно точно (ФАКТ)

1. **Порт PlayStation живёт в апстриме WebKit**, а не в отдельном публичном форке:
   `Source/cmake/OptionsPlayStation.cmake` (480 строк) содержит `set(PORT PlayStation)`,
   `WTF_PLATFORM_PLAYSTATION`, `-sce-stdlib=v2`; JIT выключен строками 176–178:
   ```
   176: WEBKIT_OPTION_DEFAULT_PORT_VALUE(ENABLE_JIT PRIVATE OFF)
   177: WEBKIT_OPTION_DEFAULT_PORT_VALUE(ENABLE_FTL_JIT PRIVATE OFF)
   178: WEBKIT_OPTION_DEFAULT_PORT_VALUE(ENABLE_DFG_JIT PRIVATE OFF)
   181: WEBKIT_OPTION_DEFAULT_PORT_VALUE(USE_ISO_MALLOC PRIVATE OFF)
   ```
   Проверено: `curl https://raw.githubusercontent.com/WebKit/WebKit/main/Source/cmake/OptionsPlayStation.cmake` → HTTP 200, 480 строк; `grep -n ENABLE_JIT`.
   Файл активно правится: последние коммиты по нему —
   `2026-11-09 0c34d35e8a [PlayStation] Fix linux build`,
   `2026-08-28 0c7b760ec6 Pass correct linker prefix on PlayStation platform`,
   `2026-08-26 82220a2f11 [CMake] Stop rewriting arguments in swiftc-wrapper`
   (`gh api 'repos/WebKit/WebKit/commits?path=Source/cmake/OptionsPlayStation.cmake'`).
   Вывод: Sony поддерживает порт в публичном дереве; отдельного публичного «Sony WebKit» нет.
2. **User-Agent версию движка не выдаёт** — он зашит в исходнике:
   `Source/WebCore/platform/playstation/UserAgentPlayStation.cpp`: `versionForUAString()` →
   `"605.1.15"`, UA собирается как `"… AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"`,
   а версия системы берётся из env `SYSTEM_SOFTWARE_VERSION` (на консоли подставляется `14.x`).
   Токен `Version/17.0` обновлялся коммитом `2023-10-03 39412fc4c8 [PlayStation] Update Safari Version in User Agent`.
   Команда: `curl …/main/Source/WebCore/platform/playstation/UserAgentPlayStation.cpp` → HTTP 200;
   `gh api '…/commits?path=Source/WebCore/platform/playstation/UserAgentPlayStation.cpp'`.
   Вывод: `Version/17.0 Safari/605.1.15` в UA — **не доказательство** ревизии (замороженный токен,
   задокументированный в коде). Утверждения «движок = Safari 17.0 по UA» из pp/kg — `НЕ ПОДТВЕРЖДЕНО`.
3. **Единственный публичный след реальной ревизии — device-фингерпринт JS-поверхности**:
   `ZigZagBoi1/PS5-14.10-Research`, пробник `probes/phase13_webkit/p162-engine-fingerprint.js`
   (32 API с тегом версии Safari), прогон на **PS5 14.10** через User's Guide DNS-redirect.
   Цитата `docs/CHANGELOG.md` (запись 2026-10-19, строка 1624):
   > «…it returns every 17.0 feature present (`Set.prototype.union`, RegExp `v`) and every 17.4
   > feature absent (`Object.groupBy`, `Promise.withResolvers`, `ArrayBuffer.prototype.transfer`),
   > with the 18.x set absent too. The JS surface is the Safari 17.0-17.3 band;
   > `navigator.hardwareConcurrency` is 4 and `deviceMemory` is absent.»
   Статус: `ЗАЯВЛЕНО` (публичный репозиторий, device-run, логи приложены), но это **единственные
   публичные данные о движке PS5 14.x**, и они согласуются с собственным кодом Sony-порта
   (UA-заморозка, JIT OFF).
4. **Точная ревизия не определяется.** Публичных build-строк/номера SVN из 14.x нет; образы
   зашифрованы (`recon/pup-decrypt-feasibility.md`, task-10: без ключа не читается); публичного
   дампа `libWebKit/WebContent` 14.x нет; UA заморожен (п. 1.2); pp-метки «WebKit-1400»,
   «WebKit-1200» — `НЕ ПОДТВЕРЖДЕНО` (в WebKit таких тегов/веток нет: `git ls-remote --tags`
   по `WebKit/WebKit` даёт 0 совпадений; автор pp сам называет «WebKit-1200 snapshot
   (December 2023)» — `recon/_src/pp-full` README).

### 1.2. Диапазон, которым ограничен ответ (ОЦЕНКА)

| Граница | Значение | Чем ограничена |
|---|---|---|
| Нижняя | ветка WebKit **7617** (Safari 17.x, окт. 2023): тег `WebKit-7617.1.10` = коммит `ac708f98`, дата **2023-10-06**; рядом `WebKit-7617.1.17` = `8e5aa612`, **2023-11-08** | `git ls-remote --tags` + `gh api repos/WebKit/WebKit/commits/{sha}` |
| Верхняя | **до Safari 17.4** (март 2024; release notes `developer.apple.com/documentation/safari-release-notes/safari-17_4-release-notes` — HTTP 200): `Object.groupBy`/`Promise.withResolvers`/`ArrayBuffer.prototype.transfer` отсутствуют на 14.10 | zz `p162` (пометки «17.4» в самом пробнике, см. п. 1.1.3) |
| Т.е. | база PS5 14.x = **Safari 17.0–17.3 band, ~окт 2023 – нач. 2024** | обе границы выше |

`ОЦЕНКА`: 2026-год прошивки (14.10 образ `2026_0928`, 14.20 `2026_1014`, 14.22 `2026_1027`)
**не означает** 2026-год WebKit. Sony держит движок на ветке ~7617 и не ребейзит его.
Для 14.20/14.22 публичного device-фингерпринта нет (GitHub code search `"PlayStation 5/14.20"`
и `"PlayStation 5/14.22"` → 0 результатов, проверено `gh api search/code`), поэтому диапазон
2023-го года экстраполируется с 14.10 и помечен как `ОЦЕНКА`, а не факт для 14.22.
Единственный способ закрыть вопрос по 14.22 без дизасма — bundle §5.

---

## 2. Фикс бага-кандидата в апстриме и его даты

### 2.1. Коммит и версии (ФАКТ)

| Поле | Значение | Проверка |
|---|---|---|
| Коммит (canonical) | `040ef6e21ffac03b6d6098e0e12354bdb5469ad1`, `316107@main` | `gh api repos/WebKit/WebKit/commits/040ef6e2…` |
| Заголовок | `Crash in CanvasRenderingContext::deref after reentrant getContext()` | там же |
| Автор/ревью | David Kilzer, `Reviewed by Said Abou-Hallawa` | `.patch` (`curl …/commit/040ef6e2….patch`) |
| Дата (author/committer UTC) | **2026-06-30 04:41:43Z** | `gh api` |
| Багзилла | **313175**, `rdar://175164594` | сообщение коммита |
| Исходная посадка | `305413.763@safari-7624-branch` (`40941e46f2d4`) | сообщение коммита |
| Тест | `LayoutTests/fast/canvas/canvas-getContext-reentrant.html` (+ `-expected.txt`) | список файлов коммита |
| Файлы | `Source/WebCore/html/HTMLCanvasElement.cpp`, `OffscreenCanvas.cpp` | список файлов |
| Safari-релиз | iOS/iPadOS/macOS **26.5.2 — Released June 29, 2026** | Apple advisory <https://support.apple.com/en-us/127594> (HTTP 200, 207 412 Б): раздел «**WebKit Canvas**», «WebKit Bugzilla: 313175, CVE-2026-43720: Gia Bui (@yabeow) from Calif.io, Josef Korbel» |
| NVD | `CVE-2026-43720`, published **2026-06-29T20:17:36Z**, CWE-416, CVSS 3.1 6.5 `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` | `recon/_src/nvd-43720.json` (task-9) |
| WebKitGTK | **исправлено в 2.52.5**: WSA-2026-0004 («Date Reported: July 10, 2026») — «CVE-2026-43720 … Versions affected: WebKitGTK and WPE WebKit **before 2.52.5** … WebKit Bugzilla: **313175**»; тег `webkitgtk-2.52.5` = коммит `476095dbd1`, **2026-07-09** | `curl https://webkitgtk.org/security/WSA-2026-0004.html` (HTTP 200, 22 830 Б); `git ls-remote --tags`; `gh api …/commits/476095dbd1` |

Дополнительно: NVD-описание по-прежнему не содержит слов canvas/WebKit/PS5 (проверено грепом
в task-9, 0 вхождений) — **привязка CVE к canvas теперь подтверждена не NVD, а Apple
(раздел «WebKit Canvas») и WebKitGTK (bug 313175)**. Это уточняет вывод task-9: атрибуция
pastawithpesto «43720 = canvas getContext» — `ПОДТВЕРЖДЕНО` первичными источниками по bug-id.

### 2.2. Что именно исправлено (ФАКТ, дифф)

До фикса (проверено по исходнику ветки-базы PS5, тег `WebKit-7617.1.10` = `ac708f98`,
2023-10-06, `Source/WebCore/html/HTMLCanvasElement.cpp:223`):
```cpp
ExceptionOr<std::optional<RenderingContext>> HTMLCanvasElement::getContext(…)
{
    if (m_context) { … return existing … }        // <- единственная проверка, ДО конвертации

    if (is2dType(contextId)) {
        auto settings = convert<IDLDictionary<CanvasRenderingContext2DSettings>>(state, …);
        // <- здесь выполняется JS-геттер; реентерабельный вызов ставит m_context
        auto context = createContext2d(contextId, WTFMove(settings));  // <- перезапись m_context
```
После фикса (`main`, коммит 040ef6e2) в каждой ветке добавлено:
```cpp
        // Dictionary conversion may run script, which may have set m_context via a re-entrant getContext().
        if (m_context) [[unlikely]]
            return getExistingContext();
```
(`curl …/main/Source/WebCore/html/HTMLCanvasElement.cpp | sed -n '/getContext(/,/^}/p'`;
`curl …/commit/040ef6e2….patch` — 17 059 Б, хунки по обоим файлам).

Вывод: в ветке, на которой стоит PS5 (~7617), **уязвимая форма кода присутствует**; фикса
там нет ни в какой форме — он появился в ветке 7624 (Safari 26.5.2) через 2.5+ года после
точки ветвления PS5. Попадание в 14.22 возможно **только бэкпортом**.

### 2.3. Сопоставление дат с образами 14.20/14.22

Даты (ФАКТ, из `recon/1422-exists.md` и `recon/1422-status.md`):

| Событие | Дата |
|---|---|
| фикс в апстриме (canonical) | 2026-06-30 |
| Safari 26.5.2 / CVE-2026-43720 | 2026-06-29 |
| WebKitGTK 2.52.5 | 2026-07-09 |
| образ 14.20 (`2026_1014`) | метка 2026-10-14; Sony `Last-Modified` 2026-10-30 02:30 GMT для `2026_1027` |
| **образ 14.22 (`2026_1027`)** | метка 2026-10-27; `Last-Modified` 2026-10-30 02:30 GMT; релиз 2026-11-02 |

`ОЦЕНКА`:
- **По календарю** фикс старше обоих образов на 3.5–4 месяца → формально «мог попасть» в 14.22.
- **По происхождению кода** — нет: база PS5 = ветка 7617 (2023), фикс из 7624 (2026); нужен бэкпорт.
- Публичных следов бэкпорта нет: Sony в 14.22 написала только «some security fixes»
  (`recon/1422-status.md:64`), конкретики нет; дизасма 14.22/14.20 по WebKit нет ни у кого
  (там же, §3.5: «Бинарный дифф … нет», «Тест на живой 14.22 … нет»).
- Единственное публичное утверждение «14.22 патчит re-entrant getContext» —
  `kevinisgoated24-spec/PS5-14.20-Jailbreak-Research` (0★, создан 2026-11-10, через 8 дней
  после релиза, без артефактов) → `ЗАЯВЛЕНО`, не факт.
- Наблюдение на 14.10 (образ `2026_0928`, т.е. **позже** фикса): zz `p635` (2026-11-05)
  заявляет VULNERABLE; pp V573/V630 — то же. То есть Sony не бэкпортила фикс даже в 14.10,
  вышедшую через 3 месяца после фикса. Это понижает (но не отменяет) вероятность бэкпорта в 14.22.

**Ответ на шаг 2:** по датам фикс **не входит** в 14.22 через базовую ветку; вхождение возможно
только бэкпортом, следов которого нет. По календарю «попадает» — по коду «не попадает».
Итоговый вердикт — §5 (нужна проба на консоли; она же — единственная проверка гипотезы
«Sony успела влить бэкпорт между 23 и 27 октября», см. §0).

---

## 3. Локальная проверка: что удалось и что нет

### 3.1. Сборка апстримного JSC на этой машине невозможна (ФАКТ, проверено заново)

```
$ for c in clang clang++ cmake ninja ruby gperf; do printf '%-8s ' "$c"; command -v $c || echo MISSING; done
clang    MISSING
clang++  MISSING
cmake    MISSING
ninja    MISSING
ruby     MISSING
gperf    MISSING
$ ls /usr/lib64/llvm22/bin
lldb  lldb-argdumper  lldb-dap  lldb-instr  lldb-mcp  lldb-server      # компилятора clang нет
$ python3 -m pip --version
pip 26.0.1 from /usr/lib/python3.14/site-packages/pip (python 3.14)
```

Причины: (1) WebKit собирается clang'ом, GCC-путь не поддерживается; в системе только
`gcc 16.2` и `lldb` без clang; (2) JSC требует Ruby для `offlineasm` (генерация LLInt/JIT
ассемблера), Ruby нет; (3) root нет — `sudo` требует пароль, `pip` даёт только cmake/ninja,
но не компилятор/ruby. Это независимо подтверждает `recon/webkit-vector.md` §6.

Вывод: **собрать JSC «близкой ревизии» (ветка 7617, 2023) на этой машине нельзя.** Кроме
того, целевой баг — не JSC-баг: `HTMLCanvasElement::getContext` живёт в WebCore, поэтому
чистый JSC-шелл его не воспроизводит в принципе (в шелле нет DOM/Canvas; см. 3.3).

### 3.2. Что использовано вместо сборки (ФАКТ)

На машине стоят настоящие бинарники WebKit:

```
$ rpm -q javascriptcoregtk4.1 webkit2gtk4.1
javascriptcoregtk4.1-2.52.5-1.fc44.x86_64
webkit2gtk4.1-2.52.5-1.fc44.x86_64
```

Это WebKitGTK **2.52.5** — тег `webkitgtk-2.52.5` = коммит `476095dbd1`, дата **2026-07-09**
(`gh api repos/WebKit/WebKit/commits/476095dbd1`). По WSA-2026-0004 (см. §2.1) фикс 313175
входит в 2.52.5, то есть локальная сборка — **пост-фиксная**, и это ожидаемо видно в пробах.
Это ближайшая к апстриму *запускаемая* ревизия на машине; PS5-ветку 7617 запустить нечем.

### 3.3. JSC-уровень: `tools/jsc-lab/jsc` + `tools/jsc-lab/probe-entry-1422.js` (ФАКТ)

```
$ ./tools/jsc-lab/jsc tools/jsc-lab/probe-entry-1422.js
JSC-FP flatMap=1,BigInt=1,matchAll=1,optChain=1,nullish=1,replaceAll=1,WeakRef=1,FinReg=1,
Segmenter=1,hasOwn=1,arrayAt=1,structuredClone=0,regExpD=1,atomicsWaitAsync=0,toSorted=1,
isWellFormed=1,setUnion=1,regExpV=1,objGroupBy=1,withResolvers=1,abTransfer=1,float16=1,
promiseTry=1,iterHelpers=1,u8base64=1,regExpEscape=1,offscreenCanvas=0
JSC-BAND >=18.x
```

Полный вывод: `tools/probe/logs/entry-1422-local-jsc.txt`.
`structuredClone=0` и `offscreenCanvas=0` — потому что это Web API, а не JSC: шелл не
содержит WebCore. **Паттерн canvas-реентерабельности в JSC не воспроизводится** — ни на
какой ревизии, потому что его нет в JSC. JSC здесь даёт только датировку поверхности:
локальный движок = `>=18.x`, PS5 14.10 (публичный p162) = `17.0..17.3`.

### 3.4. WebCore-уровень: прогон bundle-проб в локальном WebKitGTK (ФАКТ)

Команды и вывод (полные JSON — `tools/probe/logs/entry-1422-local-p{1,2,3}.txt`):

```
$ python3 tools/probe/bundles/entry-1422/run_local.py p1-canvas-reentry.html
LOCAL_PAGE_TITLE p1 FIXED
LOCAL_PAGE_JSON {"verdict":"FIXED", "cases":{
  "same_type_2d":{"verdict":"FIXED","fired":2,"firedKeys":"desynchronized+willReadFrequently",
                  "inner":"CanvasRenderingContext2D","outer":"CanvasRenderingContext2D","outerIsInner":true},
  "cross_bitmaprenderer_2d":{"verdict":"FIXED","outer":"null"},
  "cross_2d_bitmaprenderer":{"verdict":"FIXED","outer":"null"},
  "same_type_bitmaprenderer":{"verdict":"FIXED","outerIsInner":true},
  "offscreen_same_type_2d":{"verdict":"FIXED","outerIsInner":true}}, "control":{"verdict":"PASS"}}

$ python3 tools/probe/bundles/entry-1422/run_local.py p2-engine-fingerprint.html
LOCAL_PAGE_TITLE p2 >=18.x
LOCAL_PAGE_JSON {"band":">=18.x","hardwareConcurrency":8,"deviceMemory":0, ... 32 checks all 1 ...}

$ python3 tools/probe/bundles/entry-1422/run_local.py p3-crash-oracle.html '?armed=1'
LOCAL_PAGE_TITLE p3 SURVIVED
```

Интерпретация: на пост-фиксной сборке оракул даёт **FIXED** (`outer === inner` для 2d→2d;
`outer === null` для cross-type) — то есть проба реально различает состояния, а не «всегда
что-то». `p3` на пост-фиксной сборке не падает (SURVIVED), как и должно быть.

### 3.5. Важная находка при локальной проверке (ФАКТ)

В словаре `CanvasRenderingContext2DSettings` член `alpha` **закомментирован** в IDL:
`Source/WebCore/html/canvas/CanvasRenderingContext2DSettings.idl` (и в 7617, и в main):
```
    // FIXME: Add support for 'alpha'.
    // boolean alpha = true;
    boolean desynchronized = false;
```
Проверено диагностической страницей `tools/probe/bundles/entry-1422/diag-dictionary-getters.html` на 2.52.5: для `getContext('2d', opts)` геттер `alpha`
**не вызывается** (`fired=0`), а `desynchronized` — вызывается (`fired=1`); для
`bitmaprenderer`/`webgl` `alpha` вызывается. Поэтому в `p1` опции содержат геттеры на
`alpha+desynchronized+willReadFrequently+colorSpace`, а в отчёте пишется `firedKeys`.
Это же объясняет, почему в цепочках pp/kg для 2d-триггера важен не `alpha`: для same-type
2d→2d реентерабельность идёт через `desynchronized`.

### 3.6. Ответ на вопрос шага 3

**Паттерн локально не воспроизводится потому, что запускаемая локальная сборка — пост-фиксная
(WebKitGTK 2.52.5), а собрать уязвимую ветку 7617 на машине нельзя (нет clang/ruby/root).**
Вместо этого: (а) уязвимая форма кода подтверждена в исходнике ветки-базы PS5 (7617, §2.2);
(б) оракул `p1` проверен на реальном WebKit и различает FIXED/VULNERABLE; (в) на консоли
он даст однозначный ответ. Ограничение зафиксировано, а не замазано.

---

## 4. Bundle для консоли: `tools/probe/bundles/entry-1422/`

Состав (все файлы созданы в этой сессии):

| Файл | Назначение |
|---|---|
| `index.html` | хаб + проверка, что стенд живой (шлёт `HUB-OPEN`) |
| `p1-canvas-reentry.html` | главный оракул: `FIXED / VULNERABLE / UNKNOWN`; same-type 2d→2d + cross-type bitmaprenderer + OffscreenCanvas; геттеры на 4 членах словаря, `firedKeys` в отчёте |
| `p2-engine-fingerprint.html` | 32 API (1:1 с публичным p162) → полоса Safari `17.0..17.3` / `17.4..17.x` / `>=18.x`; UA, hardwareConcurrency, deviceMemory |
| `p3-crash-oracle.html` | crash-oracle: триггер N раз, затем чтение `lineWidth` у freed-контекста; только `?armed=1`; beacons `P3-BEFORE-DEREF`/`P3-AFTER-DEREF`/`P3-SURVIVED` |
| `run.sh` | `python3 tools/probe/serve.py --root <bundle> --port 8443` (HTTPS, самоподписанный серт, `/beacon` в JSONL) |
| `run_local.py` | прогон страницы в локальном WebKitGTK для проверки стенда на ПК |
| `README.md` | «что смотреть в логе»: таблица тегов→вывод, команды, ограничения, точки расширения |

Самопроверка стенда (ФАКТ, в этой сессии, `PORT=8943 ./run.sh`):

```
health=200   index=200   p1=200
POST /beacon {"tag":"SELFTEST"} -> {"ok": true, "seq": 1, ...}   beacon=200
tools/probe/logs/requests.jsonl: GET /p1-canvas-reentry.html 200, TLSv1.3
tools/probe/logs/beacons.jsonl:  {"probe":"raw","payload":{"tag":"SELFTEST"},"seq":1}
```

Точки расширения помечены `// EXT` в p1/p2/p3 (удержание обёрток и GC, новые API, спрей).
Запуск на консоли: `cd ps5jb/tools/probe/bundles/entry-1422 && ./run.sh`, затем на PS5 открыть
`https://<IP>:8443/` → p1 → p2 → (если p1=VULNERABLE) p3`?armed=1`. Подробности и таблица
«что смотреть в логе» — в `README.md` бандла.

---

## 5. Итоговый вердикт

### 5.1. Закрыт ли вектор в 14.22 (по датам и по коду)

| Проверка | Результат | Статус |
|---|---|---|
| Фикс 313175 существует и датирован | commit `040ef6e2…`, **2026-06-30**; Apple Safari/iOS **26.5.2 — 2026-06-29**; WebKitGTK 2.52.5 — 2026-07-09 | `ФАКТ` (§2.1) |
| 14.20 образ / 14.22 образ | `2026_1014` / `2026_1027` (релиз 14.22 — 2026-11-02) | `ФАКТ` (§2.3) |
| Календарное попадание фикса в 14.22 | фикс на 3.5–4 мес. старше образов → формально мог попасть | `ФАКТ` по датам |
| Попадание по происхождению кода | база PS5 = ветка **7617** (Safari 17.0–17.3, ~2023) → фикса в ней нет; нужен бэкпорт | `ФАКТ` (source + device-fingerprint 14.10) |
| Публичные следы бэкпорта в 14.22 | нет: Sony — только «some security fixes»; дизасма/теста 14.22 нет ни у кого; kevinisgoated24 (2026-11-10, 0★) — без артефактов | `ФАКТ` об отсутствии следов; само утверждение — `ЗАЯВЛЕНО` |
| Наблюдение на более поздней, чем фикс, прошивке | 14.10 (образ `2026_0928`, Sony `Last-Modified` 2026-10-14) — публичные прогоны pp/zz дают **VULNERABLE** (2026-10-23…11-05) | `ЗАЯВЛЕНО` (логи в репо; независимо не повторено) |
| Дата публикации входного бага vs метка образа 14.22 | баг публичен **2026-10-23** → **до** `2026_1027` | `ФАКТ` (§0) |

**Вывод по датам:** фикс существует раньше 14.22, но **не входит в базовую ветку PS5**.
Значит 14.22 «закрыта по датам» только в календарном смысле — при условии, что Sony сделала
бэкпорт. Публичных следов бэкпорта нет, а на 14.10 (вышедшей уже после фикса) вектор
публично работает. Поэтому:

- **ОЦЕНКА (итог): вход через реентерабельный Canvas2D `getContext()` в 14.22, скорее всего,
  НЕ закрыт.** Основания: (1) фикс не в базовой ветке; (2) нет ни одного публичного
  подтверждения бэкпорта/теста 14.22; (3) на 14.10 фикс не влит, хотя 14.10 новее фикса;
  (4) 14.20/14.22 — мелкие и быстрые релизы (13 дней между образами), ребейз движка
  маловероятен, а JS-поверхность 14.10 всё ещё Safari 17.0–17.3.
- **Контраргумент (честно):** входной баг был публичен 2026-10-23, за 4 дня до метки образа
  14.22 (и за 10 дней до релиза), а 14.22 официально заявила «some security fixes» — значит
  чисто реактивный бэкпорт **не исключён**. По правилу дат лида кандидат в этом смысле
  «потенциально закрыт». Это единственная оставшаяся неопределённость, и она снимается
  только пробой на консоли 14.22 (bundle §4) либо дизасмом WebKit 14.22 vs 14.20.

### 5.2. Готовность к выстрелу

Вектор доведён до состояния «готов к выстрелу»: есть самодостаточный bundle, который
поднимается одной командой (`./run.sh`), прошёл локальный self-test (HTTP 200 + `/beacon` 200),
и содержит ровно тот оракул, который различает фикс по поведению (same-type reentry
`outer === inner`), а не по строкам в бинарнике. Результат определяется одной строкой лога:
`P1-RESULT verdict=VULNERABLE|FIXED`; `p2` объясняет причину (`band`), `p3` подтверждает UAF
падением.

### 5.3. Что осталось непроверяемым без консоли

- Точная ревизия WebKit в 14.20/14.22 (нет публичных build-строк; PUP зашифрован; дизасм
  WebKit 14.22 vs 14.20 не сделан).
- Наличие бэкпорта 313175 в 14.22 (нет ни бинарника, ни теста).
- Дамп/адреса WebContent 14.22 (для R/W-стадии) — вне этой задачи.
- X/форумы как источник дат: `НЕ ПРОВЕРЕНО` (в отчёте только проверяемые GitHub-даты).

### 5.4. Исправления к чужим отчётам (для честности)

- `ZigZagBoi1/…/p635_cve_2026_43720_canvas_reentry_20261105.txt` ссылается на
  «WebKit fix: commit `2693828e8d73` (2026-06-29)». Проверено: `2693828e8d73` — это
  `[YARR] Fix incorrect offset …` от **2026-02-18**, не canvas-фикс. Настоящий фикс —
  `040ef6e2…`/`316107@main` (2026-06-30). Ссылку в чужом отчёте считать ошибочной.
- `recon/cve-and-notes.md` (task-9) делал вывод «привязка 43720 к canvas — только авторская».
  Уточнение: NVD действительно не называет функцию, но Apple (`support.apple.com/en-us/127594`,
  раздел «WebKit Canvas», bug 313175) и WebKitGTK (`WSA-2026-0004`, bug 313175) привязку
  подтверждают → **статус меняется на «подтверждено первичными источниками по bug-id»**.
- Метки «WebKit-1400/WebKit-1200» из pp/kg — не существуют в апстриме (0 совпадений в тегах),
  это внутренние ярлыки авторов; для датировки движка использовать `p2`/p162, не эти метки.
---

## 6. ОБНОВЛЕНИЕ (task-22, 2026-11-11): публичные артефакты с 14.22

Вопрос §5.1 («скорее всего не закрыт; нужна проба на консоли») закрыт **публичными
артефактами с консоли 14.22** (набор TFujiwara, ветка `research/tfujiwara-v919-v929-campaign`
форка `ZigZagBoi1/PS5-14.10-Research`; подробный разбор — `recon/artifacts-1422.md` §2):

- `results/phase13_webkit/v900_fw1422_recon_20261105.txt`, сырой лог
  `tools/browser_runner/beacon_logs/beacons_20261105_172139.log`: UA
  `… PlayStation 5/14.22 …`, затем `[A-OK] stale!=live (UAF present on 14.22)` и
  `[ALIAS] lw=811 idx=11`. Прогон **2026-11-05**, т.е. на уже выпущенной 14.22
  (релиз 2026-11-02, образ `2026_1027`).
- `results/phase13_webkit/p553_write_confirm_14.22_20261105.txt`, сырой лог
  `beacons_20261105_175742.log`: `P553-REVERSE-OK: FULL BIDIRECTIONAL R/W CONFIRMED`
  (12 Canvas2D API, save/restore, getTransform) — на 14.22.
- `beacons_20261105_203251.log`: `V904-UAF inner=OK outer=OK same=false` ×17 циклов.

**Итог: вектор входа (реентерабельный `getContext`, CVE-2026-43720 / bug 313175) в 14.22
НЕ закрыт — подтверждено файлом, а не пересказом.** Утверждение kevinisgoated24-spec
(«14.22 добавила context-change guard») — без артефактов и опровергнуто этими логами.
Ограничения те же: нет нативных стеков/дампов, лик/адрес не добыты; наша проба `entry-1422`
на 14.22 не запускалась (публичных `P1-RESULT` нет), её эквиваленты — v900/v904/p553.
