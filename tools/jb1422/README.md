# jb1422 — пакет цепочки PS5 14.22 (userland R/W → kernel R/W)

Один каталог, который **сам себя проверяет на ПК** и одной командой поднимает стенд для
консоли. Внутри — Canvas WebKit-цепочка (userland) и kernel-модуль, который на моках
проходит все стадии, а на консоли честно показывает точку блокера.

> **Честный статус.** Полного джейлбрейка 14.22 этот пакет пока не выполняет.
> Подтверждено публично и воспроизводимо: **userland alias R/W на 14.22 живой**
> (Canvas `getContext()` reentrancy, CVE-2026-43720 / WebKit bug 313175 — beacon-логи
> TFujiwara, 2026-11-05: `v900 A-OK stale!=live`, `p553 FULL BIDIRECTIONAL R/W CONFIRMED`).
> **Kernel-часть упирается в два отсутствующих публичных данных:** (а) утечка адреса
> (leak) на публичной поверхности и (б) oid-офсеты 14.22. До них `STAGE 9–11` = `BLOCKED`.
> Пакет не делает вид, что работает: каждая стадия печатает `OK|FAIL|DEGRADED|BLOCKED`
> с причиной. Это инструмент для консольного прогона и для поиска этих двух данных.

Связанные отчёты: [recon/jb1422-design.md](../../recon/jb1422-design.md),
[recon/fresh-dumps-2026.md](../../recon/fresh-dumps-2026.md),
[recon/module-era-decoding.md](../../recon/module-era-decoding.md).

---

## 1. Состав пакета

| Путь | Что это |
|---|---|
| `index.html` | экран пакета: кнопки **Run full chain / Harness self-test / Kernel candidates**, лог `STAGE n: OK\|FAIL\|BLOCKED`, `?autorun=1` — автостарт |
| `js/util.js` | логирование, `JBUtil.stage/log/env`, определение движка/FW |
| `js/primitive.js` | Canvas-примитив: UAF-триггер, same-type reclaim, alias, self-test, forge |
| `js/stages.js` | 12 userland-стадий + harness (STAGE 0,1,H,2…12) |
| `js/kernel-candidates.js` | матрица кандидатов userland→kernel (12 шт.) |
| `js/kernel-bridge.js` | мост `p`/`chain` — ровно тот интерфейс, что ждёт kernel-модуль |
| `js/kernel-hook.js` | стадия 11: передача в `kernel/relapse1422.js` |
| `kernel/relapse1422.js` | kernel-модуль: 11 стадий (KASLR → … → shellcode), CLI `--dry-run*` |
| `kernel/offsets/1422.js` | Tier-1 оффсеты 14.22 (`window.KRW`), неподтверждённые = `null` |
| `probes/` | 40+ HTML/JS-проб проекта (`v900…v931`, `p550…p559`) — для отдельного прогона |
| `tests/rw-sim.js` | unit-симуляция R/W-логики на настоящем `document.createElement('canvas')` |
| `tests/kernel-integration.mjs` | проверка моста `p/chain` ↔ kernel-модуль на моках |
| `tests/run_local_webkit.py` | прогон `index.html` в локальном WebKitGTK (если установлен) |
| `payloads/` | `elfldr-ps5-v0.27.elf`, `kstuff-lite-1.2-dr-test2.elf` + `MANIFEST.sha256` |
| `run.sh` | поднять стенд (HTTP + POST `/beacon`), напечатать IP:порт для консоли |
| `selftest.sh` | всё проверяемое без консоли одной командой: **exit 0 = PASS** |
| `verify.sh` | сверка sha256 пакета с `MANIFEST.sha256` |
| `logs/` | `beacon.jsonl`, `requests.log`, `selftest-*.log`, `run-smoke.log` |

---

## 2. Быстрый старт на ПК

```bash
cd ps5jb/tools/jb1422

./selftest.sh        # 1) проверка пакета без консоли (exit 0 = PASS)
./verify.sh          # 2) целостность (sha256 по манифесту)
./run.sh             # 3) стенд: http://<IP>:8080/index.html
```

Что делает `selftest.sh`: `node --check` по всем 22 js, три dry-run режима kernel-модуля
(`--dry-run`, `--dry-run-kaslr-fail`, `--dry-run-no-oid`), `tests/rw-sim.js`,
`tests/kernel-integration.mjs`, проверку `index.html` и всех `<script src>`, sha256 payload'ов,
`verify.sh` и smoke-тест `run.sh` (реально поднимает сервер, `GET /index.html` = 200,
`POST /beacon` = 200). Отчёт: `logs/selftest-<дата>.log`, сводная таблица PASS/FAIL в консоли.

`./selftest.sh --fast` — без smoke-теста сервера.

### Локальный прогон в WebKitGTK (опционально)

```bash
./run.sh 8080 &
# затем в браузере ПК:
#   http://127.0.0.1:8080/index.html        → кнопка ▶ Run full chain
#   http://127.0.0.1:8080/index.html?autorun=1
python3 tests/run_local_webkit.py --help    # если установлен WebKitGTK + PyGObject
```
На ПК **STAGE 2 ожидаемо FAIL**: локальный WebKitGTK 2.52.5 уже содержит фикс, UAF не
воспроизводится. Это норма: harness (STAGE H) при этом PASS 12/12, а всё, что относится к
логике R/W, проверяет `tests/rw-sim.js` на легальном canvas-контексте.

---

## 3. Запуск на консоли PS5 14.22

1. ПК и PS5 — в одной сети. На ПК: `./run.sh` (по умолчанию порт 8080).
2. Скрипт печатает адреса вида `http://192.168.x.x:8080/index.html` — откройте этот адрес
   на консоли (User's Guide/браузер тем же способом, что и остальные пробы проекта;
   методика — `tools/probe/`, HTTPS-вариант стенда — `python3 tools/probe/serve.py --root ../jb1422`).
3. В логе на экране смотрите строки `STAGE n: STATUS — detail` (они же уходят в
   `logs/requests.log`; при использовании кнопок beacon-части — в `logs/beacon.jsonl`).
4. Автопрогон: `http://<IP>:8080/index.html?autorun=1` (стартует через 300 мс).
5. Кнопки: **▶ Run full chain**, **🧪 Harness self-test** (не требует уязвимости),
   **☰ Kernel candidates**, **Copy log**.

Ожидаемая картина на 14.22 (сверху вниз):

| STAGE | Что делает | Ожидание на 14.22 | На ПК | Если не так |
|---|---|---|---|---|
| 0 | окружение: UA, фичи, FW | OK | OK | не тот браузер/страница; откройте `index.html` ещё раз |
| 1 | контроли canvas/bitmaprenderer | OK | OK | WebKit без 2d-canvas (маловероятно) |
| H | harness self-test (12/12) | OK | OK | ошибка в js/primitive.js — пакет битый, `./verify.sh` |
| 2 | **UAF-триггер** `getContext()` reentrancy | **OK** | **FAIL (норма)** | FAIL на консоли = движок с фиксом; проверьте FW (STAGE 0) |
| 3 | same-type reclaim (спрей) | OK + alias idx | SKIP/FAIL | `zero-at-free`/иная раскладка → DEGRADED, см. STAGE 3 detail |
| 4 | поиск alias-контекста | OK | — | повторить Run; см. `probes/p553` |
| 5 | self-test R/W на известном объекте | OK | — | FAIL = alias не bidirectional, смотрите `p553/p554d` |
| 6 | инвентарь каналов (104 Б) | OK | OK | — |
| 7 | state stack (save/restore) | OK | OK | — |
| 8 | Tier-1 оффсеты 14.22 (печать) | OK | OK | оффсеты `null` — это ожидаемо, не ошибка |
| 9 | forge raw-канал (lineDash Vector) | **BLOCKED** (нет leak) | BLOCKED | появление leak = прогресс, зафиксируйте лог |
| 10 | мост `p`/`chain` | BLOCKED | BLOCKED | `p.ready=false` — нужен leak (STAGE 9) |
| 11 | handoff в `kernel/relapse1422.js` | BLOCKED | BLOCKED | нужен kernel R/W: нет oid-офсетов 14.22 |
| 12 | матрица kernel-кандидатов (12) | BLOCKED | BLOCKED | все ждут leak/code-exec |

Если лог обрывается **до** STAGE 2 — это не «сломался эксплойт», а окружение (не тот
браузер/страница, JS-ошибка). Проверьте `logs/requests.log` и консоль браузера.

---

## 4. Kernel-модуль отдельно (dry-run без консоли)

```bash
node kernel/relapse1422.js --dry-run              # полная мок-цепочка, exit 0, done=true
node kernel/relapse1422.js --dry-run-kaslr-fail   # имитация провала KASLR: FAIL стадии 4, exit 0
node kernel/relapse1422.js --dry-run-no-oid       # нет oid: fallback по DEGRADED, done=true
```
Режимы с ожидаемым провалом (`--dry-run-kaslr-fail`) специально возвращают exit 0 — это
заложено в модуле; `selftest.sh` проверяет именно ожидаемые маркеры (`ИТОГ:`,
`РЕЗУЛЬТАТ:`, `FAIL`), а не только код возврата.

Таблица стадий kernel-модуля (моки): 1 KASLR candidates → 2 pin to single core →
3 arm kernel R/W (waiter+oid/external) → 4 verify kbase → 5 discover gadgets/stubs →
6 find curproc → 7 locate pipes → 8 cross pipes → 9 defuse aio groups →
10 escalate (ucred+security_flags) → 11 launch shellcode. На моках: `OK=9, DEGRADED=2,
done=true`; `DEGRADED` — это fallback-путь, а не ошибка.

---

## 5. Что делать при FAIL / DEGRADED / BLOCKED

- **FAIL на STAGE 2 на консоли** — движок не уязвим (обновлён/другой); сверьте FW в
  STAGE 0, повторите на чистой вкладке, откройте `index.html` без кэша (`?v=2`).
- **DEGRADED на STAGE 3/5** — reclaim не сложился (иная раскладка heap). Это данные, а не
  баг: сохраните лог, попробуйте `probes/p553`/`p554d` и повторите прогон 2–3 раза.
- **BLOCKED на STAGE 9** — ожидаемое состояние 14.22: нет утечки адреса. Любой leak —
  ценный результат, зафиксируйте `detail` и `logs/`.
- **BLOCKED на STAGE 11** — kernel-модулю не хватает kernel R/W/oid-офсетов 14.22. Смотрите
  `kernel/offsets/1422.js`: поля со `null` — это и есть список неизвестного; их ищут
  оффлайн-сканом и на консоли.
- **Всё PASS, но консоль молчит** — проверьте, что открыт именно `http://<IP>:<PORT>/index.html`
  (а не локальный файл), и что сервер видит запросы в `logs/requests.log`.

---

## 6. Payload'ы (самодостаточность)

`payloads/` содержит два готовых payload-ELF, которые пакет может доставить на консоль
внешними средствами (elfldr) — они не нужны для самого прогона цепочки:

| Файл | Размер | Назначение |
|---|---|---|
| `elfldr-ps5-v0.27.elf` | 394 568 | loader ELF по TCP (приём payload'ов на консоли) |
| `kstuff-lite-1.2-dr-test2.elf` | 1 558 040 | `kstuff-lite` — kernel-патчи/debug (для 13.x; на 14.22 не проверялся) |

Проверка: `cd payloads && sha256sum -c MANIFEST.sha256`. Доставка на консоль — по методике
`ps5jb/recon/relapse-anatomy.md` §5 (порты 9020/9021, elfldr) и `payloads/MANIFEST.sha256`
для сверки после передачи.

---

## 7. Логи и диагностика

| Файл | Что пишется |
|---|---|
| `logs/beacon.jsonl` | POST `/beacon` с консоли/ПК (JSON + IP + время) |
| `logs/requests.log` | все запросы стенда (`run.sh`) |
| `logs/selftest-<дата>.log` | полный вывод `selftest.sh` (включая dry-run и sim) |
| `logs/run-smoke.log` | вывод сервера при smoke-тесте из `selftest.sh` |
| экран `index.html` | тот же лог, что и на экране; кнопка **Copy log** копирует целиком |

Диагностика ПК: `./selftest.sh` (exit 0 обязателен), `./verify.sh` (целостность),
`node --check <файл>` для точечной проверки синтаксиса.

---

## 8. Ограничения (чтобы не было иллюзий)

1. Пакет **не** выполняет полный джейлбрейк 14.22: kernel R/W не достигнут ни на одной
   публичной консоли; в цепочке это `STAGE 9–11 = BLOCKED` с указанием причины.
2. Kernel-модуль проверен только на моках (`--dry-run*`, `tests/kernel-integration.mjs`).
   Реальный R/W доказывается исключительно на консоли 14.22.
3. Оффсеты `kernel/offsets/1422.js` — Tier-1 (деривация от 13.60 + upstream SDK-офсеты);
   поля, помеченные как неподтверждённые, равны `null` и добываются рантайм-сканом.
4. `kstuff-lite` в `payloads/` рассчитан на 13.x; на 14.22 не проверялся — не считать
   «готовым обходом».
5. Стенд `run.sh` — HTTP/1.1 без TLS; для консольных методик с HTTPS используйте
   `tools/probe/serve.py` (тот же каталог в `--root`).