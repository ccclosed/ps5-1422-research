# Контракт userland-примитива `p` ↔ `kernel/relapse1422.js`

Дата проверки: 2026-11-11. Ревизия kernel-модуля на момент сверки:
`kernel/relapse1422.js`, **81 365 байт**, sha256 (16) **b94794f7ddfacd65** (mtime
2026-11-11 18:49:59); файл активно правится recon-fw-exists, поэтому строки в таблице —
снимок этой ревизии, для повтора используйте команды в §1–§2.

Владелец контракта: `js/primitive.js` (`JBPrimitive.createKernelP(...)`), метод
`CanvasAliasPrimitive.prototype.toKernelP(rawMem)`. `js/kernel-bridge.js` даёт ту же форму
(используется тестом `tests/kernel-integration.mjs`).

## 1. Что использует kernel-модуль (grep)

Команда:
```bash
cd ps5jb/tools/jb1422
for f in malloc read1 read2 read4 read8 write1 write2 write4 write8 ready reason \
         attachKernelPipe pipeRead pipeWrite leakval; do
  printf '%s: ' "$f"; grep -n "this\.p\.$f\|[^A-Za-z]p\.$f" kernel/relapse1422.js | cut -d: -f1 | tr '\n' ',' ; echo
done
for f in syscall rtmsg2 add_syscall add_syscall_ret launch push push_write8; do
  printf 'chain.%s: ' "$f"; grep -n "chain\.$f" kernel/relapse1422.js | cut -d: -f1 | tr '\n' ','
done
```

Снимок (номера строк на ревизии выше):

| Поле | Где в kernel (строки) | Есть в `primitive.createKernelP` | Есть в `bridge.createPrimitive` | Примечание |
|---|---|---|---|---|
| `p.malloc(size, align)` | 152, 184, 1012, 1182, 1199 | **да** | **да** | возвращает KBAddr/I64 с `.add32()`; требует userland-accessor (VA) — до leak бросает `JbNotReady` |
| `p.read1(addr)` | 153 | **да** | **да** | через accessor/RawMemory; до leak — `JbNotReady` |
| `p.read2(addr)` | — (не используется) | да (совместимость) | да | оставлен для симметрии/будущих версий |
| `p.read4(addr)` | 154, 1345 | **да** | **да** | — |
| `p.read8(addr)` | 155, 276, 277, 527, 528 | **да** | **да** | возвращает 64-битный I64-совместимый объект (`{low,hi}`) |
| `p.write1(addr, v)` | 156 | **да** | **да** | — |
| `p.write2(addr, v)` | — (не используется) | да (совместимость) | да | — |
| `p.write4(addr, v)` | 152, 157, 1349, 1354 | **да** | **да** | — |
| `p.write8(addr, v)` | 158 | **да** | **да** | принимает I64/`{low,hi}`/number |
| `p.ready()` | 210, 212 | **да** | **да** | `true` только после leak/accessor; на ПК — `false` (ожидаемо) |
| `p.reason()` | 213 | **да** | **да** | точная причина: `no userland accessor (needs leak/addrof): STAGE 9 blocked` |
| `p.attachKernelPipe(kx)` | 859 | **да** | **да** | внешний kernel R/W: возвращает `{read,write}` или `null` (тогда модуль идёт внутренним AIO-путём и честно деградирует) |
| `p.pipeRead(addr, len, out)` | 1005, 1013 | условно (появляется после `providePipe`/`attachKernelPipe`) | так же | kernel проверяет `typeof … === "function"`; если отсутствует — STAGE «cross pipes» = DEGRADED, не FAIL |
| `p.pipeWrite(addr, v, len)` | 1005, 1025 | условно | так же | — |
| `p.leakval(obj)` | — (grep=0 в этой ревизии) | **да** | **да** | контракт моста; kernel напрямую не вызывает (читает ответ routing socket через malloc/writeU8), но поле оставлено для совместимости |
| `p.read64/write64/read32/write32/add` | — (kernel использует read8/read4+I64) | **да** | **да** | добавлены по контракту атакующего скелета/лида; не мешают kernel |
| `p.readDouble/writeDouble/readMatrix/writeMatrix` | — | **да** | **да** | typed Canvas2D-канал (после STAGE 4 alias); kernel не использует |
| `p.I64` / KBAddr `.add32/.sub/.eq/.toString` | 152, 276–277 | **да** | **да** | kernel оборачивает `read8` в свой `I64.of`, поддерживаются `{low,hi}` |

`chain` (не поля `p`, но kernel использует — реализовано в `js/kernel-bridge.js`
`createChain` + `js/syscalls.js`):

| Поле chain | Где в kernel | Есть | Примечание |
|---|---|---|---|
| `chain.syscall(nr, ...)` | 151, 1188–1220 | да | async → `{low,hi}`; нужен syscall-backend (ROP) — до него `JbNotReady` |
| `chain.rtmsg2()` | 286, 374–380, 537, 625–631 | да | async → `Uint8Array|null` (KASLR-ответ routing socket) |
| `chain.add_syscall(...)` | 1264–1266 | да | ROP-очередь |
| `chain.add_syscall_ret(slot, ...)` | 1266 | да | ROP-очередь с записью ret |
| `chain.launch()` | 1128, 1222–1223 | да (в bridge: `launch`, push, push_write8, stack_entry_point) | `push/push_write8` kernel в этой ревизии не вызывает |

## 2. Проверка «каждое поле есть» (машинно)

```bash
node --input-type=module - <<'EOF'
import fs from 'node:fs'; import vm from 'node:vm';
globalThis.window = globalThis;
globalThis.document = { createElement: () => ({ getContext: () => ({}) }), body: { appendChild() {} }, head: { appendChild() {} } };
globalThis.location = { protocol: 'http:', href: 'http://x/' };
vm.runInThisContext(fs.readFileSync('js/util.js', 'utf8'));
vm.runInThisContext(fs.readFileSync('js/primitive.js', 'utf8'));
const p = globalThis.JBPrimitive.createKernelP({ describe: () => ({}), alias: null }, null, () => {});
const required = ['malloc','read1','read2','read4','read8','write1','write2','write4','write8',
  'ready','reason','attachKernelPipe','read64','write64','read32','write32','add',
  'readDouble','writeDouble','readMatrix','writeMatrix','leakval'];
const missing = required.filter(k => typeof p[k] !== 'function');
console.log('required=' + required.length + ' missing=' + JSON.stringify(missing));
console.log('ready=' + p.ready() + ' reason=' + p.reason());
console.log(missing.length === 0 ? 'CONTRACT PASS' : 'CONTRACT FAIL');
EOF
```
Результат на этой машине: `required=22 missing=[]`, `ready=false`,
`CONTRACT PASS`.

## 3. Результаты обязательных прогонов

```
$ node tools/jb1422/tests/rw-sim.js
SIM_RESULT: PASS (unit simulation; exploit stages still need PS5 14.22)

$ node tools/jb1422/tests/kernel-integration.mjs
SIM_RESULT: PASS (интерфейс моста/модуля совпал; мок-цепочка done:true; ПК-путь BLOCKED)
```

Плюс `node --check` по всем `js/*.js` — без ошибок; браузерный smoke
(`tests/run_local_webkit.py`): STAGE H OK 12/12, STAGE 2 FAIL (локальный WebKitGTK 2.52.5
с фиксом — ожидаемо), остальные стадии BLOCKED с подсказками; `STAGE 10` печатает
`contract OK`.

## 4. Чего заведомо нет и почему это не ломает kernel

- `pipeRead/pipeWrite` по умолчанию отсутствуют (появятся только после реального kernel R/W
  через `providePipe`/`attachKernelPipe`) — kernel корректно проверяет `typeof` и уходит в
  DEGRADED (STAGE «cross pipes»), не падая.
- `malloc/read*/write*/leakval` до leak бросают `JbNotReady` с причиной — kernel на это
  отвечает `{done:false, stage:0, status:'BLOCKED'}` (ветка precondition), а не мусором.
- `p.ready()===false` на ПК — ожидаемый и единственный честный путь: на консоли 14.22
  стадии 2–7 дают alias R/W, но leak/адрес (STAGE 9) публично не добыт; kernel-стадия
  блокируется именно там, а не на несовпадении интерфейса.