# Вектор входа: браузер PS5 (WebKit/JSC) и его состояние на 14.22

Дата сборки документа: 2026-11-11. Все проверки выполнены в этой сессии, команды и ответы
приведены дословно там, где это важно.

## 0. Легенда достоверности

| Метка | Значение |
|---|---|
| `ПОДТВЕРЖДЕНО` | есть первичный источник, проверенный в этой сессии (NVD/MITRE/Apple/WebKit git/Wikipedia/локальный бинарник) |
| `ЗАЯВЛЕНО АВТОРОМ` | так написано в репозитории, независимого подтверждения нет |
| `НЕ ПОДТВЕРЖДЕНО` | источник не найден |
| `ОПРОВЕРГНУТО` | найдено прямое противоречие с проверяемым фактом |

## 1. Источники

Скачано в `recon/_src/` (для воспроизводимости), полный клон — `recon/_src/pp-full`:

| Файл | Что это |
|---|---|
| `_src/pp/README.md` | pastawithpesto/PS5-14.10-Jailbreak-Research, ветка `master` |
| `_src/pp/CHANGELOG.md`, `_src/pp/VERSION` | `0.1.1` |
| `_src/kg/README.md` | kevinisgoated24-spec/PS5-14.20-Jailbreak-Research, ветка `main` |
| `_src/kg/exploit/canvas_uaf.js` | v6, 301 строка — основной эксплойт |
| `_src/kg/notes/memory_layout.md` | заметки по адресному пространству WebContent |
| `_src/kg/exploit/canvas_serve.html` | страница доставки |

Метаданные репозиториев (GitHub API): pp — создан 2026-10-18, последний push 2026-11-05,
19 звёзд, MIT, 3280 КБ. kg — создан 2026-11-10, push 2026-11-10, 0 звёзд, без лицензии, 23 КБ.

> Контекст: README pp в разделе «Models Used» перечисляет девять LLM как авторов работы
> («Claude Opus 4.6 … DeepSeek v4.1-Flash …»). Это не делает данные ложными, но означает,
> что тексты репозитория — не рецензированный источник; проверять надо каждый факт.

## 2. CVE-2026-43720 — что реально известно

`ПОДТВЕРЖДЕНО` CVE существует и опубликован:

- MITRE CVE Services API (`https://cveawg.mitre.org/api/cve/CVE-2026-43720`):
  `state: PUBLISHED`, assigner `apple`, `dateReserved 2026-05-01`, `datePublished 2026-06-29`,
  `dateUpdated 2026-08-17`.
- NVD (`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-43720`): опубликован
  2026-06-29, `vulnStatus Modified`, CWE-416 (Use After Free).
- Описание (одинаковое в MITRE и NVD): «A use-after-free issue was addressed with improved
  memory management… Processing maliciously crafted web content may lead to an unexpected
  Safari crash».
- Затронуто: Safari < 26.5.2, iOS/iPadOS < 18.7.10 и < 26.5.2, macOS Tahoe < 26.5.2,
  tvOS/visionOS/watchOS < 26.6.
- CVSS 3.1: `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` = **6.5 MEDIUM**. CISA ADP (SSVC):
  `Exploitation: none`, `Automatable: no`, `Technical Impact: partial`.

`ОПРОВЕРГНУТО` атрибуция «техника CVE-2026-43720 — авторства pastawithpesto».
Apple security advisory для iOS 26.5.2 / iPadOS 26.5.2 (Released **June 29, 2026**),
раздел WebKit: «WebKit Bugzilla: 313175, CVE-2026-43720: **Gia Bui (@yabeow) from Calif.io,
Josef Korbel**» (<https://support.apple.com/en-us/127594>). Ни pastawithpesto, ни
kevinisgoated24-spec в кредитах нет. Формулировка kg README «technique originally documented
by pastawithpesto» — это `ЗАЯВЛЕНО АВТОРОМ` и противоречит официальному кредиту Apple.

`НЕ ПОДТВЕРЖДЕНО` что CVE-2026-43720 — именно про canvas/`getContext`. В тексте CVE и NVD
слов `canvas`, `getContext`, `context` **нет** (проверено грепом по JSON: 0 вхождений).
Связь «CVE ↔ canvas getContext» устанавливается только двумя способами, и оба сходятся:

1. Коммит WebKit с тем же номером багзиллы 313175 и заголовком
   «Crash in `CanvasRenderingContext::deref` after reentrant `getContext()`».
2. Дата: CVE опубликован 2026-06-29, коммит — 2026-06-30 (исходная посадка в ветку
   `safari-7624-branch`).

То есть идентификация бага как canvas-reentrancy **верна**, но она не из CVE-описания, а из
коммита. Авторство техники эксплуатации при этом не подтверждено.

## 3. Стадии цепочки: что означает каждая

Источник: kg README §«Exploit Chain», pp README §«Planned Exploitation Path»,
`exploit/canvas_uaf.js`, `notes/memory_layout.md`.

Корневая причина по kg README: `getContext(type, options)` читает словарь `options` через
JS-геттеры **до** того, как зафиксировать новый тип контекста; реентерабельный геттер успевает
создать 2d-контекст, а внешний вызов затем заменяет его на `bitmaprenderer`, освобождая
768-байтный `CanvasRenderingContext2D`, тогда как JS-обёртка (`innerCtx`) остаётся живой.

| Стадия | Смысл | Статус в репозитории |
|---|---|---|
| **V573** | Same-type reclaim: спрей 5× `getContext('2d')` на canvas 1×1 без DOM; один из них попадает в освобождённый 768-байтный слот. Детект алиаса — sentinel `57005.0` (`0xDEAD`) в `innerCtx.lineWidth`, затем чтение `lineWidth` у всех контекстов спрея. Результат сессии: `slot=2`. | ✅ `ЗАЯВЛЕНО АВТОРОМ` |
| **V630** | Bidirectional R/W через алиас: `lineWidth`, `globalAlpha`, `miterLimit` пишутся в одну сторону и читаются в другую. Даёт «все 12 Canvas2D API» через устаревшую обёртку. | ✅ `ЗАЯВЛЕНО АВТОРОМ` |
| **V674** | AB(768) forge crash-scan: второй UAF, спрей 200× `ArrayBuffer(768)`, в каждый AB пишутся `m_stateStack.m_buffer` (смещения +112/+116 = lo/hi32), `m_capacity=1` (+120), `m_size=1` (+124); затем `innerCtx2.lineWidth` читает `*(TARGET+48)`. Невалидный адрес → SIGSEGV → диалог PS5 «not enough system memory» → перезагрузка → счётчик в `localStorage` двигается дальше. | 🔄 «running» |
| **V701** | Forge `Vector<double> m_lineDash` (смещение +168) внутри AB: `{data*, size, capacity}`; `setLineDash`/`getLineDash` через алиас дают произвольное чтение/запись. | ⏳ |
| **V744** | Произвольная запись 8 байт по любому отображённому адресу через подделанный lineDash. | ⏳ |
| **V788** | Type confusion: подделка заголовка `JSObject`/vtable в записываемой области. | ⏳ |
| **V821** | vtable hijack + ROP до `system()` либо до входа в kernel-эксплойт. | ⏳ |

Технические предпосылки, на которые опирается цепочка (`ЗАЯВЛЕНО АВТОРОМ`, kg README):
IsoHeap OFF (`WTF_MAKE_ISO_ALLOCATED` → FastMalloc под `PLATFORM(PLAYSTATION)`), Gigacage OFF
(бэкенды ArrayBuffer в той же куче libpas), JIT выключен (только LLInt), «JSC Config
unfrozen» (`startOfStructureHeap` остаётся записываемым после инициализации).

### 3.1. Где цепочка расходится с проверяемыми фактами

- `ОПРОВЕРГНУТО` **«DAZ: чтение float64 указателеподобных битов возвращает 0.0»** (pp README,
  kg README, `memory_layout.md`). DAZ (MXCSR, бит 6) и FTZ (бит 15) влияют на *арифметические*
  операции SSE, а не на загрузку/сохранение `double` и не на сравнения. Обычное чтение поля
  `double` через геттер вернёт те же биты; чтобы денормаль «схлопнулся», значение должно пройти
  через арифметику. На этом допущении построена вся интерпретация V674 («ZERO-HIT»), значит
  выводы сканера как минимум нуждаются в перепроверке.
- `НЕ ПОДТВЕРЖДЕНО` «libpas: свободные блоки остаются отображёнными, учёт внеполосный, in-band
  указателей свободного списка нет». Это утверждение о конкретной конфигурации аллокатора;
  в апстриме libpas часть аллокаторов действительно битмапная (bitfit), но часть — segregated
  с внутриблочными связями. Проверять надо на конкретной сборке.
- `НЕ ПОДТВЕРЖДЕНО` размер 768 байт для `sizeof(CanvasRenderingContext2D)` — зависит от
  компилятора, флагов и версии; в репозитории не приведён расчёт/дамп.
- `НЕ ПОДТВЕРЖДЕНО` «14.22 патчит цепочку» (kg README, блок Firmware Warning). Публичных
  подтверждений нет; см. §5.
- Официальная оценка impact — **только crash** (`C:N/I:N/A:H`), тогда как цепочка заявляет
  произвольное чтение/запись и исполнение кода. Это не опровержение, но сильное расхождение:
  вендор и CISA считают баг DoS-класса.

## 4. Фикс в апстриме WebKit

`ПОДТВЕРЖДЕНО` фикс существует, найден в `WebKit/WebKit`:

| Поле | Значение |
|---|---|
| Коммит | `040ef6e21ffac03b6d6098e0e12354bdb5469ad1` |
| Заголовок | `Crash in CanvasRenderingContext::deref after reentrant getContext()` |
| Автор | David Kilzer, `Reviewed by Said Abou-Hallawa` |
| Дата | 2026-06-30 (author/committer), bugzilla **313175**, `rdar://175164594` |
| Исходная посадка | `305413.763@safari-7624-branch` (`40941e46f2d4`), canonical `316107@main` |
| Релиз | Safari 26.5.2 / iOS 26.5.2 / macOS Tahoe 26.5.2 — **29 июня 2026** |
| Тест | `LayoutTests/fast/canvas/canvas-getContext-reentrant.html` (+ `-expected.txt`) |

Ссылки: <https://github.com/WebKit/WebKit/commit/040ef6e21ffac03b6d6098e0e12354bdb5469ad1>,
<https://bugs.webkit.org/show_bug.cgi?id=313175> (баг закрыт для внешнего доступа:
`<bug error="NotPermitted">` — это security-баг, что нормально).

### 4.1. Что именно исправлено (из сообщения коммита и диффа)

Дифф правит `Source/WebCore/html/HTMLCanvasElement.cpp` и `OffscreenCanvas.cpp`. Реальная
сигнатура — `getContext(JSC::JSGlobalObject&, const String& contextId,
FixedVector<JSC::Strong<JSC::Unknown>>&& arguments)`, то есть конверсия словаря идёт **внутри**
C++-метода (поэтому реентерабельность и возможна).

Ключевая фраза коммита, объясняющая, почему это настоящий UAF, а не «висячая ссылка»:

> «`CanvasRenderingContext` forwards `ref()`/`deref()` to its owning `CanvasBase`, so the
> wrapper's ref does not keep the context alive; on GC sweep the wrapper's `deref()` reads
> `m_canvas` from a freed `this`.»

Фикс: после конверсии словаря повторно проверяется `m_context`; если реентерабельный вызов его
установил — возвращается существующий контекст при совпадении типа и `null` при несовпадении.
Плюс `ASSERT(!m_context)` → `ASSERT_WITH_SECURITY_IMPLICATION(!m_context)` в четырёх
`createContext*()`.

### 4.2. Контракт после фикса (из `-expected.txt`, дословно)

```
getContext("bitmaprenderer") with reentrant getContext("2d"): outer=null inner=CanvasRenderingContext2D
getContext("2d")            with reentrant getContext("2d"): outer=CanvasRenderingContext2D inner=CanvasRenderingContext2D
getContext("webgl")         with reentrant getContext("2d"): outer=null inner=CanvasRenderingContext2D
+ те же 16 комбинаций для OffscreenCanvas
PASS if no crash.
```

### 4.3. Как определить наличие фикса — практический оракул (главный результат)

Бинарный поиск по строкам бесполезен: фикс не добавляет ни строк, ни новых символов, а
`AppleWebKit/605.1.15` — замороженный токен (в локальной библиотеке WebKitGTK он лежит прямо
в `.rodata` шаблоном `") AppleWebKit/605.1.15 (KHTML, like Gecko) "`). Рабочий способ —
**поведенческий оракул на JS**, ровно по контракту §4.2:

```js
var c = document.createElement('canvas'), inner = null, o = {};
Object.defineProperty(o, 'alpha', { get: function () { inner = c.getContext('2d'); return true; } });
var outer = c.getContext('bitmaprenderer', o);
// outer === null                -> ФИКС ЕСТЬ
// outer instanceof ImageBitmapRenderingContext -> УЯЗВИМО (внутренний 2d уже освобождён)
```

Оракул реализован и **проверен на реальной сборке**:

- `tools/probe/canvas_oracle.html` — сама страница (плюс матрица из 4 кейсов и фичи-фингерпринт);
- `tools/probe/canvas_oracle_runner.py` — прогон в локальном WebKitGTK через `python3-gi`.

Фактический вывод на локальном WebKitGTK 2.52.5 (пост-фикс):

```
ORACLE_JSON={"verdict":"FIXED","ua":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15
(KHTML, like Gecko) Version/60.5 Safari/605.1.15","trigger":{"surface":"html",
"outerType":"bitmaprenderer","innerType":"2d","outer":"null","inner":"CanvasRenderingContext2D",
"err":null},"innerStillUsable":7.5, ...}
```

То есть на фиксированной сборке `outer=null`, а внутренний контекст остаётся рабочим
(`lineWidth=7.5` читается обратно). На уязвимой сборке `outer` будет живым
`ImageBitmapRenderingContext` — это и есть дискриминатор. Дополнительный признак уязвимости:
падение web-процесса при GC после триггера (именно так устроен апстримный тест: `gc(); PASS if
no crash`).

Для PS5 это значит: один HTML-файл, отданный через локальный сервер, даёт однозначный ответ
«есть фикс / нет фикса» **без разбора бинарника**, и результат уходит беконом.

### 4.4. Если всё-таки разбирать бинарник PS5

Метод (проверяемая последовательность, не «магия»):

1. Найти в WebContent/`libWebKit` строки `"bitmaprenderer"`, `"webgl2"`, `"InvalidStateError"` —
   рядом лежит `HTMLCanvasElement::getContext`.
2. Восстановить функцию по xref на эти литералы (в `.sprx` символов нет, но строки и таблица
   исключений есть).
3. Признак фикса: **две** проверки поля `m_context` — на входе в функцию и повторно после
   каждого вызова конвертера словаря (`convert<IDLDictionary<...>>`), с ветвлением на общий
   блок «вернуть существующий контекст». До фикса проверка ровно одна, на входе.
4. Косвенно: наличие `ASSERT_WITH_SECURITY_IMPLICATION` не поможет — в релизе ассерты вырезаны.

Практически шаг 3 дороже оракула и даёт тот же ответ, поэтому приоритет — §4.3.

## 5. Версии WebKit/JSC в прошивках PS5 14.x

`ПОДТВЕРЖДЕНО` (Wikipedia, «PlayStation 5 system software»): 13.00 — 24 марта 2026,
**14.00 — 16 сентября 2026** (<https://en.wikipedia.org/wiki/PlayStation_5_system_software>).
То есть линейка 14.x существует и она новее фикса из §4 (июнь 2026).

`НЕ ПОДТВЕРЖДЕНО`:
- существование прошивок **14.10 / 14.20 / 14.22** — публичных релиз-нот или трекеров не найдено;
- версия WebKit/JSC в любой прошивке 14.x.

`ОПРОВЕРГНУТО` идентификатор «**WebKit-1400**» (pp README «Source tree WebKit-1400», kg README
«WebKit build WebKit-1400»). В апстриме такой ветки/тега нет: `git ls-remote --tags` по
`WebKit/WebKit` даёт 0 совпадений с `WebKit-1400`; реальные теги — `WebKit-7623.1.14.10.x`,
`WebKit-7625.2.8.x`, ветки — `safari-7620-branch`, `safari-7624-branch` и т.п. Нумерация
«1400» не соответствует ничему в WebKit. (Отдельно забавно, что в тегах встречается
`7623.1.14.10.*` — совпадение с «14.10», но это версия WebKit, а не прошивки.)

`НЕ НАДЁЖНО` как индикатор версии: UA. В репозитории pp найдены 17 захваченных UA вида
`Mozilla/5.0 (PlayStation; PlayStation 5/14.10) AppleWebKit/605.1.15 (KHTML, like Gecko)
Version/17.0 Safari/605.1.15`. Токен `605.1.15` заморожен и одинаков для всех современных
WebKit, а `Version/17.0` — это Safari-токен, который Sony может не обновлять. Локальный
WebKitGTK 2.52.5 (2026 год) отдаёт `Version/60.5` с тем же `605.1.15` — наглядно, что токены
не отражают ветку.

Как определять версию правильно (план, без бинарника):

1. **Фичи-фингерпринт.** Каждый релиз WebKit добавляет методы; набор `typeof` по десятку
   свежих API (в оракуле уже есть `Float16Array`, `Promise.withResolvers`, `Object.groupBy`,
   `Set.prototype.union`, `RegExp.escape`, `Iterator`, `Temporal`) сужает ветку до окна в
   несколько месяцев. Локальная сборка 2.52.5 даёт базу сравнения: `Float16Array` = function,
   `Temporal` = undefined.
2. **Оракул из §4.3** — прямой ответ на вопрос «есть ли фикс», важнее номера версии.
3. Бинарно: искать в `.sprx` не номер, а *поведение* (см. §4.4), либо строки релизных
   ресурсов WebKit (`Version/…`, `Safari/…`) в `libWebKit`/`WebContent`.

Вывод по 14.22: `НЕ ПОДТВЕРЖДЕНО`, что 14.22 «патчит цепочку». Логика «14.00 вышла после
фикса ⇒ фикс внутри» верна только при условии, что Sony ребейзит WebKit; публично это
не подтверждено, а исторически консольные форки отстают. Единственный надёжный ответ даёт
оракул, запущенный на самой консоли.

## 6. Практика: можно ли собрать JavaScriptCore локально

Замеры на этой машине (Fedora 44, 12 ядер, 15 ГБ RAM, 197 ГБ свободно на `/home`):

| Проверка | Результат |
|---|---|
| `cmake`, `ninja`, `clang`, `ruby`, `gperf`, `ccache` | **отсутствуют** |
| `gcc/g++` | 16.2.1 (есть), `bison` 3.8.2, `flex` 2.6.4, `python3` 3.14.7, `perl`, `pkg-config` 2.5.1 |
| dev-заголовки ICU/libxml2 | `/usr/include/unicode/utypes.h` и `/usr/include/libxml2` — **нет** |
| `sudo` | требует пароль → установить пакеты нельзя |
| `pip` | 26.0.1, ставит `cmake` (проверено: скачался `cmake-4.4.4-...whl`) и `ninja` без root |
| Клон WebKit `--depth 1 --filter=blob:none --no-checkout` | **15 МБ**, ~20 с |
| + `sparse-checkout` `Source/{JavaScriptCore,WTF,bmalloc}` | **239 МБ** (`JavaScriptCore` 75 МБ, `WTF` 25 МБ, `bmalloc` 13 МБ) |

Итог по сборке: **технически возможно, но не нужно и небыстро.**

- Блокеры: нет `clang` (WebKit собирается clang'ом; GCC-путь не поддерживается), нет `ruby`
  (offlineasm для JSC), нет `gperf`. Без root поставить их нельзя; `pip` даёт только
  cmake/ninja.
- Оценка времени при наличии clang: конфигурация ~2–5 мин, сборка `jsc` на 12 ядрах ~20–40 мин,
  плюс ~1.5–2 ГБ артефактов. Скачивание полного дерева (не sparse) — единицы гигабайт.

**Готовый обход, который уже работает:** на машине стоят `javascriptcoregtk4.1-2.52.5-1.fc44`
и `webkit2gtk4.1-2.52.5-1.fc44` (установлены 2026-08-28), то есть настоящий JSC и настоящий
web-процесс WebKit — без сборки. Есть даже `tools/jsc-lab/jsc` (шелл на public JSC C API,
собранный ранее). Полноценный браузерный тест канвас-бага идёт через `python3-gi` +
`WebKit2 4.1` (см. §4.3) — это ровно тот уровень (WebCore), которого нет в чистом `jsc`.

План, если всё же нужен свой JSC:

1. `python3 -m pip install --user cmake ninja` (проверено, что колёса доступны).
2. Достать clang: единственный путь без root — статическая сборка LLVM (долго) или
   `pip install clang` (даёт только Python-биндинги, **не** компилятор) → фактически нужен root.
3. `git clone --depth 1 --filter=blob:none --no-checkout https://github.com/WebKit/WebKit.git`,
   затем `git sparse-checkout set Source/JavaScriptCore Source/WTF Source/bmalloc Tools/Scripts`,
   `git checkout`.
4. `cmake -S Source/JavaScriptCore -B build -G Ninja -DPORT=JSCOnly -DCMAKE_BUILD_TYPE=Release
   -DENABLE_INTL=OFF` (Intl выключаем, потому что нет ICU-заголовков).
5. `ninja -C build jsc`.
6. Валидация: `build/bin/jsc -e 'print(1+1)'`, затем прогон регрессий
   `Tools/Scripts/run-jsc-stress-tests`.

Приоритет: шаги 2–5 сейчас заблокированы отсутствием root; для задачи «понять состояние
вектора на 14.22» они не нужны — оракул из §4.3 даёт ответ дешевле.

## 7. Что делать дальше (по убыванию ценности)

1. Отдать `canvas_oracle.html` на консоль (локальный HTTPS-сервер из kg `server/https_server.py`
   или любой другой) и снять `verdict` с 14.22. Это единственный способ закрыть вопрос
   «пропатчено или нет» — и он не требует ни бинарника, ни сборки JSC.
2. Если `verdict=VULNERABLE` — прогнать тот же файл на 14.20/14.10 для калибровки и только
   потом тратить время на V573/V630 (спрей, sentinel) — они проверяются тем же способом.
3. Не доверять числам из `memory_layout.md` (адреса, «DAZ», 768 Б) без собственного замера:
   минимум два утверждения из §3.1 противоречат семантике SSE/апстриму.
4. Перед любыми заявками на «jailbreak 14.22» помнить: официальный impact CVE — crash
   (CVSS 6.5, C/I = NONE), публичного эксплойта с произвольной записью нет.