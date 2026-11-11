# bundle-1422 — YARPE/LUA как примитив `p` для kernel-цепочки 14.22

Второй вход в userland: игровой save-эксплойт даёт **Python/Lua внутри процесса игры**, а значит —
произвольное чтение/запись памяти **без всякой возни с утечкой адреса** (на 14.22 canvas leak
мёртв: zero-at-free, p691 вернул нули). Этот каталог превращает такой вход в объект `p`, который
ждёт `tools/jb1422/kernel/relapse1422.js` (`runKernelExploit(p, chain, log)`).

## Интерфейс `p` (совпадает с tools/jb1422)

| Метод | Возврат | Реализация |
|---|---|---|
| `p.read1(addr)` / `read4` / `read8` | int | срез `sc.mem[addr-0x1000 : +n]` + `struct.unpack` |
| `p.write1/4/8(addr, value)` | — | запись в тот же срез `sc.mem` |
| `p.read(addr, n)` / `p.write(addr, bytes)` | bytes | сырые буферы |
| `p.read64(addr)` | `"0x..."` | hex-вариант контракта `js/primitive.js` |
| `p.write64(addr, val)` | — | принимает hex-строку или число |
| `p.read32(addr, off)` / `p.write32(addr, off, val)` | hex / — | как в `js/primitive.js` |
| `p.add(addr, off)` | `"0x..."` | арифметика адресов |
| `p.malloc(size, align=1)` | int-адрес | `utils.etc.alloc` + `addrof` |
| `p.ready()` | `True` | `sc.mem` получен |
| `p.reason()` | `"yarpe"` | — |
| `p.syscall(num, *args)` | int (rax) | `calls.Syscall(sc, num)(rdi..r9)` |

Точные сигнатуры YARPE, на которые это опирается (проверено в `Helloyunho/yarpe`):
`utils/unsafe.py: readbuf(addr,n) -> mem[addr-0x1000:...]`, `writebuf(addr,data)`,
`readuint/writeuint`; `utils/etc.py: alloc(size) -> bytearray`, `addrof(obj) -> int`;
`calls.py: Syscall(sc, num).__call__(rdi,rsi,rdx,rcx,r8,r9) -> rax`,
`Function(sc, addr).__call__(...) -> rax`; `sc.py: is_jailbroken = getuid()==0 and is_in_sandbox()==0`.

## Файлы

| Файл | Что делает | Проверено на ПК |
|---|---|---|
| `primitive.py` | класс `P` (консоль: `sc.mem`; ПК: `MockBackend`) + 23-проверочный selftest | **PASS** |
| `kernel-runner.py` | бинарный TCP-сервер «1 байт cmd + 8 addr + 8 len/data», режимы `--mock`, `--in-game`, `--relay`, `--selftest` | **PASS** (20 операций) |
| `yarpe_agent.py` | агент **внутри YARPE** (py2.7, `utils.tcp`), слушает :9139 | синтаксис + протокол (через MockBackend) |
| `agent_lua.lua` | пассивный агент в Lua-loader (9026), fd из `signal.fd_addr` | Lua 5.1 compile **OK** |
| `bridge_server.py` | HTTP JSON + line-протокол (CORS), `--lua-host` сам подключается к 9026 | **PASS** (12 проверок) |
| `mock_agent.py` | ПК-заглушка агента (словарь адресов) | используется в тестах |
| `probe_14xx_entry.lua`, `send_lua.py`, `selftest.py` | проба входа + отправщик 9026 | **PASS** |
| `run.sh` | все проверки одной командой | **7/7 PASS** |
| `manifest.json` | метаданные + sha256 | — |

## Запуск на ПК

```bash
cd ps5jb/tools/lua-lab/bundle-1422
./run.sh                    # 7 шагов, итог ALL PASS
python3 primitive.py        # только примитив (23 проверки)
python3 kernel-runner.py --selftest   # только бинарный протокол (20 операций)
python3 bridge_server.py --self-test  # только мост HTTP/line
```

## Запуск на консоли 14.22 (YARPE — основной путь)

1. **Требования:** PSN-активированный профиль; игра Ren'Py из списка YARPE
   (`A YEAR OF SPRINGS` CUSA30428-31 или `Arcade Spirits: The New Challengers` CUSA32096/97 —
   PS4-издания, импортируются на не-jb консоль); сейв из `save.zip` v3.3.0
   (`https://github.com/Helloyunho/yarpe/releases/tag/v3.3.0`), вставленный через JB-PS4 + Apollo
   (или Save Wizard для PS4-сейва).
2. Запустить игру и загрузить сейв → в логе `Listening on port 9025 for stage 2 payload...`.
3. Отправить агента (сырой текст Python, без длины):
   ```bash
   python3 - <<'PY'
   import socket
   src = open("yarpe_agent.py", "rb").read()
   s = socket.create_connection(("<PS5_IP>", 9025), timeout=10)
   s.sendall(src)
   print(s.recv(65536).decode("utf-8", "replace"))
   PY
   ```
   В игре появится `[agent] yarpe binary agent on 9139`.
4. Подключение kernel-части:
   - JS на ПК/в Node — напрямую к `http://<PS5_IP>:9139` (бинарный протокол, см. ниже);
   - JS в браузере консоли + ПК-релей: `python3 kernel-runner.py --relay --agent-host <PS5_IP> --agent-port 9139 --port 9140`,
     тогда JS ходит на ПК:9140.
5. Ожидаемый лог: `ready -> true`, `reason -> yarpe`, чтение/запись по адресам процесса игры.

### Бинарный протокол (для JS-цепочки)

```
0x01 READ    [addr u64][len u64]               -> [0][data:len]
0x02 WRITE   [addr u64][len u64][data:len]     -> [0]
0x03 MALLOC  [size u64][align u64]             -> [0][addr u64]
0x04 SYSCALL [num u64][argc u8][args u64*argc] -> [0][ret i64]
0x05 READY   -> [0][1]       0x06 REASON -> [0][ascii]
```
Node-клиент: `const s = require('net').connect(9139, '<PS5_IP>'); s.write(Buffer.from([1, ...addrLE, ...lenLE]))`.

## LUA-путь (9026, альтернатива)

Если игра Hamidashi Creative Demo (CUSA27390) уже настроена (`recon/lua-vector.md`), тот же `p`
доступен через загрузчик: `bridge_server.py --lua-host <PS5_IP>` сам подключится к 9026, включит
signal handler, отправит `agent_lua.lua` и поднимет HTTP-мост. `agent_lua.lua` на консоли **не
проверялся** (в сессии нет консоли) — проверена только компиляция Lua 5.1; протокол 1:1 совпадает
с проверенным `kernel-runner.py --selftest`.

## Чего это не даёт

- **Не ядро.** `sc.is_jailbroken = getuid()==0 and is_in_sandbox()==0`; на не-jb консоли — `False`.
  Kernel R/W по-прежнему должен поднять `tools/jb1422/kernel/relapse1422.js`; мы даём ему `p` и
  `syscall()`.
- **Не отменяет консольную проверку**: адреса/смещения YARPE (гейджеты, libc, exec) привязаны к
  конкретной игре и изданию; `sc.version` покажет прошивку (для 14.2x ждём `14.2x`).
- **Не публичный эксплойт прошивки**: YARPE — userland-вход, kernel-части для 14.2x нет
  (последний публичный KEX — 13.60; `lapse.py` покрывает 4.03–12.02).

## Full-chain: наша kernel-цепочка через НАШ примитив по TCP

```bash
python3 demo-fullchain.py        # одна команда: поднимает mock-kernel runner, гоняет node-цепочку
```

Что происходит: `kernel-runner.py --mock-kernel` (Python: mock YARPE + синтетическое ядро как в
dry-run-моках) слушает TCP; `run-relapse-over-tcp.mjs` импортирует
`tools/jb1422/kernel/relapse1422.js` (`runKernelExploitWith`) и подставляет `p`/`chain`/`rw`,
которые ходят по TCP. Сам `kernel/**` **не изменялся** — это отдельный runner.
Синхронные `p.read*/write*/malloc` обслуживает worker-поток (`pb-worker.mjs`) через
`SharedArrayBuffer + Atomics.wait`; `chain.syscall` и `rw.*` — отдельный async-сокет.

Результат (реальный прогон, лог `output/fullchain-over-tcp.log`):

```
ИТОГ: done=true, стадий=13, OK=13, DEGRADED=0, FAIL=0
```

Все 13 стадий зелёные — как `--dry-run-full` у владельца kernel-модуля; прогон ~3.3 с.

Что понадобилось: `p.readBytes/p.writeBytes` (bulk, 1 round-trip на чанк — из них crossPipes
берёт быстрый путь, стадия 8), `p.pipeRead/p.pipeWrite` (фолбэк), `options.triggerPayload` с
`t1_aio_wait_race.elf` для AIO sanity check (стадия 13) и префетч-кэш чтения.
Отдельно: владелец kernel-модуля (recon-fw-exists) по моему замеру 4604 мс/чанк исправил
`kreadBytes()` (теперь возвращает `Uint8Array` напрямую, 1 round-trip вместо 2×len) и перевёл
сканеры на чанки 0x10000 с перекрытием 8 байт — это зафиксировано в `recon/relapse-port-1422.md` §15.
Payload 394 568 Б и триггер 10 000 Б простеганы через TCP (write1-батчинг по 32 KiB).

### Контракт `chain.rtmsg2()` и разделение пространств памяти

Kernel-модуль вызывает `chain.rtmsg2()` и делает `copyIntoProcess(reply)` — то есть обязан получить
**байты**, а не объект. Мост отдаёт:

```js
chain.rtmsg2() -> Uint8Array(512)  // первые 8: 04 00 00 00 00 00 00 00
                       .ptr        // 0x... — адрес этого же буфера в памяти ПРОЦЕССА
                       .bytes      // он же (для кода, который ждёт {ptr, bytes})
```

**Финальный контракт (согласован с владельцем kernel-модуля):**

```js
chain.rtmsg2() -> { ptr, bytes }
//   ptr   — адрес буфера в памяти ПРОЦЕССА (0x...)
//   bytes — Uint8Array(512): первые 8 байт 04 00 00 00 00 00 00 00,
//           ret по смещению 184: 69 68 b0 00 ff ff ff ff
```

Kernel принимает его в `routingSocketReply()`:
`const bytes = toBytes(reply) || toBytes(reply && reply.bytes); if (bytes) return copyIntoProcess(bytes);`

`PB_RTMSG2=hybrid` — **legacy-опция** для старого kernel: `Uint8Array` с полями `.ptr`/`.bytes`
(старый путь звал `new Uint8Array(obj)` и получал 0 байт). Оба режима проверены на ПК: 13/13/0/0.

Кросс-проверка контракта со стороны kernel: `run.sh` шаг 8 гоняет
`node tools/jb1422/kernel/relapse1422.js --dry-run-objreply` (мок отдаёт чистый `{ptr,bytes}`)
и требует `13/13/0/0` — регрессия этого бага теперь ловится с обеих сторон.

Отладка: `PB_DEBUG=1` печатает режим, тип, длину, первые 8 байт и `ret@184`.
Регрессия: `demo-fullchain.py` возвращает !=0, если стадий < 13, OK < 13, есть DEGRADED/FAIL или
`done != true` (переопределяется `EXPECTED_STAGES`).
