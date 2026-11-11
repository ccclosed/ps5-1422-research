# jb1422 — карта цепочки userland R/W → kernel R/W (PS5 14.22)

Дата: 2026-11-11. Код: `tools/jb1422/` (userland — webkit-1422: `index.html`, `js/**`,
`probes/**`; kernel — recon-fw-exists: `kernel/**`). Этот файл — карта и честный статус.

## 0. TL;DR

- **Userland-вход на 14.22 жив** (публичные артефакты TFujiwara, 2026-11-05): `v900 A-OK
  stale!=live`, `p553 FULL BIDIRECTIONAL R/W CONFIRMED`, `v904 same=false` ×17 → пакет
  доходит до alias R/W и self-test на консоли.
- **Kernel-часть кодом готова** (`kernel/relapse1422.js`, 12 стадий), на моках проходит
  `done:true`; на консоли упирается в **нет userland address leak** (STAGE 9) →
  нет `p.read1..8/malloc` по VA и `chain.syscall` (ROP) → kernel R/W не поднимается.
- **Пакет не делает джейлбрейк 14.22 end-to-end.** Он доводит до userland R/W и показывает
  точную точку обрыва. Это зафиксировано в логах стадий.

## 1. Архитектура (поток данных)

```
[браузер PS5] index.html
   └─ js/stages.js  (оркестратор, лог STAGE n: OK/FAIL/BLOCKED + hint)
        ├─ js/primitive.js:  trigger UAF (desynchronized / bitmaprenderer+alpha)
        │     → same-type reclaim (spray 1x1 canvas, ladder 80/160/300)
        │     → alias stale↔spray  → typed R/W (7 props*8B + matrix 6*8B = 104 B)
        │     → self-test на известном объекте (identity/matrix/props/save-restore)
        │     → RawMemory (forge lineDash Vector = произвольное чтение/запись по адресу)
        ├─ js/kernel-bridge.js: p (read1..8/write1..8/malloc/leakval/ready + read64/write64/
        │     read32/write32/add + readDouble/writeDouble/readMatrix/writeMatrix)
        │     и chain (async syscall/rtmsg2/ROP-queue) — то, что ждёт kernel-модуль
        ├─ js/kernel-hook.js: грузит kernel/offsets/1422.js + kernel/relapse1422.js (ESM),
        │     вызывает runKernelExploit(p, chain, log)
        └─ js/kernel-candidates.js: 12 кандидатов userland→kernel (prepare/trigger/detect)
```

## 2. Стадии и статус

| STAGE | Что | Код | ПК (WebKitGTK 2.52.5) | Консоль 14.22 |
|---|---|---|---|---|
| 0/1 | env, контроли canvas | stages.js | OK | OK |
| H | harness self-test (не эксплойт) | primitive.js | OK 12/12 | OK |
| 2 | реентерабельный `getContext` UAF | primitive.js | FAIL (движок с фиксом) | **OK** (v900) |
| 3 | reclaim + ladder spray | primitive.js | BLOCKED | OK при живом UAF; FAIL → hint (увеличить spray/cold boot/zero-at-free) |
| 4 | alias binding | primitive.js | BLOCKED | OK |
| 5 | self-test stale↔alias | primitive.js | BLOCKED | OK (p553-уровень) |
| 6/7 | каналы 104 Б; state stack save/restore | stages.js | OK / BLOCKED | OK |
| 8 | Tier-1 оффсеты 14.22 (печать) | stages.js | OK | OK |
| 9 | raw-канал: forge lineDash Vector | primitive.js RawMemory | BLOCKED | **BLOCKED без leak** |
| 10 | мост p/chain + сверка контракта | kernel-bridge.js | BLOCKED (contract OK) | BLOCKED до STAGE 9 |
| 11 | handoff в kernel/relapse1422.js | kernel-hook.js | BLOCKED (честно, stage 0) | зависит от leak + kernel R/W |
| 12 | 12 kernel-кандидатов | kernel-candidates.js | BLOCKED | BLOCKED (нужен code-exec) |

## 3. Что проверено на ПК (числа)

`node --check js/*.js` — OK. `node tools/jb1422/tests/rw-sim.js` — PASS (harness 12/12,
I64/адресная арифметика, forge-гейты). `node tools/jb1422/tests/kernel-integration.mjs` —
PASS: мост `p/chain` совпал с контрактом kernel-модуля, мок-цепочка `done:true`, без
accessor'а модуль честно `{done:false, stage:0, status:'BLOCKED'}`.
`node kernel/relapse1422.js --dry-run` — done=true (12 стадий, OK=10/DEGRADED=2/FAIL=0).
`python3 tools/jb1422/tests/run_local_webkit.py` — браузерный smoke: STAGE H OK, STAGE 2 FAIL
(локальный движок пост-фикс), 11/12 BLOCKED с подсказками. Логи — `tools/jb1422/logs/`.

## 4. Что требует консоли

1. **STAGE 2/3/4/5/7** — реальный UAF/alias/self-test. На ПК не проверить (движок исправлен);
   на 14.22 подтверждено публично (v900/p553/v904), нашим кодом — ожидает прогона.
2. **Leak/addrof** (между 8 и 9) — без него `RawMemory`/forge не активируются. Публичные
   лик-лейны 14.22 закрыты: zero-at-free (v909 6/6), v911 grid `SURV=0`, p691 NOLEAK,
   CE-108262-9 history без адресов. Это первый блокер всей цепочки.
3. **Kernel R/W**: нужен `oid.*`/`nodeMutex`/`gadgetmap`/`syscall_map` 14.22 (публичного
   дампа нет) либо внешний `attachKernelRw/attachKernelPipe`. Без этого kernel-модуль
   честно `DEGRADED` и STAGE 4 (verify kbase) не проходит.
4. **Shellcode/ELF 14.22** — стадия launchShellcode без payload только `DEGRADED`.

## 5. Оффсеты 14.22 (Tier-1; внутри образа, KASLR slide неизвестен)

| Константа | RVA | Источник |
|---|---|---|
| kernelData | `0x00CE0000` | SDK kernel.c case 0x14220000 |
| allproc | `0x035B9EA0` | SDK (exact-unverified) |
| security_flags | `0x01A84064` | SDK |
| rootvnode | `0x03E3B510` | SDK (exact-unverified) |
| retStatic predict | `0x00B06869` (low16 0x6869) | 14.22 окно |
| retStatic окно | `0x00AFEAF1…0x00B14191` | 14.22 окно |
| oid/nodeMutex/rodataProbe/gadgetmap/syscall_map | — | **нет** (нужен дамп 14.22) |

## 6. Контракт p/chain (сверен с `kernel/relapse1422.js` grep'ом)

- `p`: read1/2/4/8, write1/2/4/8, malloc(size,align)→I64(add32), leakval, ready()/reason(),
  плюс (контракт лида) read64/write64/read32/write32/add и typed readDouble/writeDouble/
  readMatrix/writeMatrix; опционально pipeRead/pipeWrite/attachKernelPipe.
- `chain`: syscall(nr,...)→Promise<{low,hi}>, rtmsg2()→Promise<Uint8Array|null>,
  add_syscall/add_syscall_ret, push/push_write8/launch; backend подключается
  `attachSyscallBackend` (ROP/code-exec).
- Стадия 10 сверяет ВСЕ поля и печатает `contract OK/MISSING …` в лог.

## 7. Следующие шаги (по приоритету)

1. **Address leak/addrof** на 14.22 (zero-at-free-эра): искать иные источники, чем p553 —
   аллокаторные residue- каналы, FontFace p640 status, APNG (закрыт), JSC 17.0 N-day под
   LLInt. Без этого стадии 9+ не запустятся.
2. **Oid-оффсеты 14.22**: нужен расшифрованный образ/дамп; сейчас kernel-модуль работает
   только waiter-вектором без oid → STAGE 4 BLOCKED.
3. **ROP/code-exec backend** для `chain.syscall` (оригинальный main.js: worker-ROP через
   `pop rsp`; нужны gadgetmap/syscall_map libkernel 14.22 — тоже нет).
4. Console-прогон текущего пакета: зафиксировать STAGE 2-7 на 14.22 (ожидаемо OK) и точный
   лог обрыва на 9 — это единственный способ валидировать userland-часть на железе.

## 8. Файлы

`tools/jb1422/{index.html, js/{util,primitive,kernel-bridge,kernel-hook,syscalls,
kernel-candidates,stages}.js, probes/ (43 пробы + ANALYSIS.md + MANIFEST.sha256),
kernel/ (recon-fw-exists), tests/ (recon-1422-status), logs/}`.