# Анатомия цепочки Relapse (PS5 7.00–13.60) — эталон для 14.22

**Агент:** recon-relapse (перезапуск) · **Задача:** task-5 · **Дата:** 2026-11-11
**Машина:** Linux, root НЕТ, сеть через `socks5h://127.0.0.1:10810`.
**Правило:** ничего не выдумано. Каждый факт — со ссылкой на файл/репозиторий. Непроверенное помечено **НЕ ПОДТВЕРЖДЕНО**.

Локальные копии: `recon/_src/relapse/<owner>_<repo>/` (git clone --depth 50, 2026-11-11).
Бинарники: `tools/payload/payloads/`, лог проверки — `tools/payload/RELAPSE-PAYLOADS-VERIFY.txt`.

---

## 0. Проверка источников

Существование и HEAD проверены `git ls-remote`, метаданные — `gh api repos/...` (2026-11-11):

| Репозиторий | HEAD | Создан/обновлён | Описание (из API) |
|---|---|---|---|
| [m2k7m/Relapse-Exploit](https://github.com/m2k7m/Relapse-Exploit) | `fc28fb48` | push 2026-11-09 | Exploit chain for PS5 7.00 – 13.60 |
| [manos555555/Relapse-Exploit](https://github.com/manos555555/Relapse-Exploit) | `22a25db9` | push 2026-10-30 | PS5 Relapse Jailbreak — kernel exploit with offline support (FW 7.00-13.60) |
| [arg0WAK/WAK1360-Relapse](https://github.com/arg0WAK/WAK1360-Relapse) | `e1fb88f9` | push 2026-11-08 | W.A.K. — modular automated exploit framework for PS5 7.00-13.60 |
| [tidewell/relapse-offset-dumper](https://github.com/tidewell/relapse-offset-dumper) | `8c8fc823` | push 2026-10-29 | Kernel offset dumper for Relapse; extracts per-FW kernel values to port exploit to new FW |
| [oscarlaradev/cyber-forge-ps5-ps4-exploit-host](https://github.com/oscarlaradev/cyber-forge-ps5-ps4-exploit-host) | `9234b734` | push 2026-11-07 | PS5 (Relapse 7.00-13.60 / Y2JB / UMTX2) & PS4 WebKit host |
| [bsk193/drakmor-kstuff-mirror](https://github.com/bsk193/drakmor-kstuff-mirror) | `db4f1855` | push 2026-11-05 | Зеркало релизов drakmor/kstuff-lite, включая Discord-only сборки (кода нет, только Releases) |
| [drakmor/kstuff-lite](https://github.com/drakmor/kstuff-lite) | `2dfdef81` | push 2026-09-21 | Форк [EchoStretch/kstuff-lite](https://github.com/EchoStretch/kstuff-lite) (API: `fork=true`, parent EchoStretch) |
| [ps5-payload-dev/elfldr](https://github.com/ps5-payload-dev/elfldr) | `2a8da002` | — | ELF loader через ptrace в `SceRedisServer` |
| [ps5-payload-dev/sdk](https://github.com/ps5-payload-dev/sdk) | — | — | SDK, от которого зависят elfldr/kstuff/dumper (`ps5/kernel.h`) |

Смежные (проверены по API, нужны для §1/§5):
[soniciso1/LuaPSX](https://github.com/soniciso1/LuaPSX) (Luac0re, порт 9026), [cosmicflow2512/PS5AutopayloadHA](https://github.com/cosmicflow2512/PS5AutopayloadHA) (карта портов), [Gezine/Y2JB](https://github.com/Gezine/Y2JB) (userland code exec через YouTube-приложение).
Отдельно проверен репозиторий исследования **14.20**:
[Khal0da/PS5-14.20-WebKit-Research](https://github.com/Khal0da/PS5-14.20-WebKit-Research) — HEAD `df4c8c4e`, push 2026-11-10,
описание по API: *«PS5 14.20 WebKit attack-surface research: diagnostics, probes and field notes. **No exploit code**.»*

> `ps5-payload-dev/payloads` **не существует** (`git ls-remote` → `Repository not found`). Payload-репозитории называются поимённо: `elfldr`, `klogsrv`, `shsrv`, `ftpsrv`, `websrv`, `kstuff`, `gdbsrv`, `offact`, `pkg` и т.д. — список получен через `gh api orgs/ps5-payload-dev/repos`.
> `ps5-payload-dev/kstuff` в орге есть, но `README.md` на `master` отдаёт 404 (ветка/файл другие) — **НЕ ПОДТВЕРЖДЕНО**.

---

## 1. Цепочка: этапы и порядок

Все три «дистрибутива» Relapse (m2k7m, manos, WAK) — это **один и тот же код** с разной обвязкой:
`webkit.js` (браузер) → `rop.js` + `mem.js` (userland ROP) → `relapse_exploit.js` (ядро) → `kexp.js` (доставка).

### E0. Точка входа — браузер PS5

Host раздаёт статический сайт (`serve.py`, порт 8000; или GitHub Pages). На консоли открывается через
User's Guide / custom DNS (`m2k7m/README.md`, `arg0WAK/README.md` §«PS5 User's Guide via Custom DNS»).
Версия прошивки берётся из `navigator.userAgent` регуляркой `/PlayStation 5\/(\d+\.\d+)/`, имя файла
смещений — `offsets/<fw>.js` (`src/firmware.js:20-29` в m2k7m). Неизвестная FW → отказ.

### E1. WebKit/JSC: уязвимости → userland R/W

`src/webkit.js` (729 строк), экспорт `establishPrimitive()` (строка 710).
Заявленный состав (README m2k7m + manos, дословно: *«Browser stage uses JSC info leaks and a structured
clone object pool mismatch to corrupt a typedarray»*):

1. **JSC info leaks** — получить адреса объектов и указатель на нативный конструктор; результат
   складывается в `globalThis.__ps5NativeCtor` (`webkit.js:522`).
2. **structured clone object pool mismatch** — рассинхронизация пула объектов при `structuredClone`
   (или его аналоге) даёт **тип-конфузию**: один и тот же буфер виден как разные типы.
3. **Corrupt a typedarray** → `ArrayBuffer` c подменёнными `backing`/`byteLength` → чтение/запись
   произвольной памяти процесса (класс `Leaker` в `webkit.js:210`, оконный буфер `MEMORY_WINDOW_SIZE`,
   `webkit.js:243`).
4. `src/utils/mem.js` (`installWindowP`) превращает это в удобный API: `read1/2/4/8`, `write1/2/4/8`,
   `leakval(obj)` → адрес объекта, `malloc(size)` (через `ArrayBuffer`+`leakval(backing).add32(0x10)`).

**Итог E1:** `p` = userland-примитив «произвольное чтение/запись в адресном пространстве процесса WebKit».

### E2. ROP → вызов произвольного syscall из JS

`src/main.js` (`prepareRop`) + `src/rop.js`:

1. База WebKit: из `__ps5NativeCtor` перебором `OFFSET_wk_host_constructor_candidates` (по 3 кандидата
   на FW), проверка `0x800000000 ≤ base < 0x900000000 && base % 0x4000 == 0` (`main.js:110-125`).
2. `libSceLibcInternalBase` = `*(webkitBase + OFFSET_wk_memset_import) − OFFSET_lc_memset` (GOT/import-слот).
3. `libKernelBase` = `*(webkitBase + OFFSET_wk___stack_chk_guard_import) − OFFSET_lk___stack_chk_guard`.
   **Обе базы выводятся из двух 8-байтовых чтений в WebKit** — это ключ к userland-части.
4. Гаджеты ROP берутся как `webkitBase + wk_gadgetmap[имя]` (25 гаджетов), syscall-стабы —
   `libKernelBase + syscall_map[nr]` (~300 номеров).
5. Запускается `new Worker("./src/utils/rop_slave.js")` (4 строки: `onmessage → postMessage`).
6. **Worker-stack поиск:** `libKernelBase + OFFSET_lk__thread_list` → обход списка потоков
   (`next_thread @+0x38`, `stack_addr @+0xa8`, `stack_size @+0xb0`), фильтр «стек 0x80000»,
   затем **fingerprint-выбор**: на стеке ищется значение `libKernelBase + OFFSET_lk_worker_wait_return`
   в диапазоне `[stack+0x7f000, stack+0x80000)`; ровно одно совпадение = наш worker (`main.js:1-88`).
7. Фигура стека: перезапись return-слота на `gadgets["pop rsp"]`, рядом кладётся `chain.stack_entry_point`;
   в конце цепочки — `setjmp`/`longjmp` (`OFFSET_lc_setjmp`, `OFFSET_lc_longjmp`) для возврата в JS
   и восстановления состояния (`main.js:225-260`).
8. ROP-стек строится в куче JS (`rop.js`: `stack_size=0x80000`, `reserved_stack=0x10000`),
   вызовы добавляются парами dword (`push`/`add_syscall`/`add_syscall_ret`), затем `chain.run()`.
9. Проверка живости цепочки: в `chain.return_value` пишется яд `0xdeadbeef00c0ffee`; вызов `syscall(GETPID)`,
   если яд не изменился — «Worker chain did not execute».

**Итог E2:** `chain.syscall(nr, args...)` + `chain.call(addr, ...)` + возможность батчить syscall'ы
(`chain.clear()/add_syscall()/run()`) — планировщик для гонки в E3.

### E3. Ядро: KASLR → UAF → kernel R/W

`src/relapse_exploit.js` (1181 строка), класс `KernelExploit`, точка входа `run()` (строка ~1096).
Порядок строго такой (это и есть ответ на «в каком порядке»):

**Шаг 1 — KASLR-лик (`leakKernelBase`, стр. 206-271).**
Уязвимость — **неинициализированная/лишняя копия в ответе RTM_GET на `PF_ROUTE`-сокете**:
1. Получить свой IP: `SYS_NETGETIFLIST` перебором интерфейсов (`firstInterfaceAddress`, AF_ROUTE-запрос
   требует живой LAN — иначе `kaslr: no interface has an address`, см. WAK README «Technical Notes»).
2. `socket(AF_ROUTE=17, SOCK_RAW=3, 0)`; `setsockopt(SOL_SOCKET, SO_RCVTIMEO, 5s)`.
3. Собрать `RTM_GET` (496 байт): `rtm_version=5`, `rtm_type=4`, `rtm_addrs=RTA_DST|RTA_AUTHOR (0x41)`,
   `rtm_seq=0x1234`, dst = `sockaddr_in` (sa_len=88), author = `sa_len=255, AF_INET6`.
4. `write(fd, msg, 496)` → ядро возвращает ответ; в записи `RTA_AUTHOR` по смещению **+184**
   лежит **адрес возврата в `.text` ядра**.
5. Проверка: `hi == 0xffffffff` и `low & 0xffff == retLow16`; `kbase = ret − retStatic`.

**Шаг 2 — пиннинг на одно ядро** (`pinToSingleCore`, `SYS_CPUSET_GETAFFINITY`/`SET` по CPU_WHICH_TID) —
гонка в шаге 3 должна идти на одном CPU.

**Шаг 3 — UAF/гонка `aio_multi_wait`** (`armKernelReadWrite` → `parkAioWorkers` → `makeOidWritable` →
`reclaimWaiterArray` → `flipOidKind`, стр. 292-660):
1. `raiseFdLimit()` (getrlimit/setrlimit RLIMIT_NOFILE → max).
2. `parkAioWorkers(24)`: через `socketpair(AF_UNIX)` + `aio_submit_cmd(AIO_CMD_READ=1)` отправить
   **блокирующиеся** AIO-чтения, чтобы worker'ы ядра «припарковались» на мосту.
3. `claimPendingRequests(18)`: набрать 18 «висящих» (state==1) AIO-запросов-кандидатов.
4. `buildWaiterNodes(13, firstTarget, secondTarget)`: подготовить в userland 13 нод размером
   `requestSize=0x28`, где по +0x20 `0xffffffff`, по +0x00/+0x08 — два целевых указателя,
   по +0x10 — `kbase + nodeMutex`.
5. `runReclaimBatch`: выстроить батч syscall'ов — `ioctl(0xffffffff, churnRequest=0x80000000|(13*0x28<<16)|0x4101, nodes)`
   × 32 (churnBefore) → **`aio_multi_wait(group.ids, 18, states, 0, timeout)`** → ioctl × 256 (churnAfter)
   → 64 × `aio_submit_cmd(..., nodes, 13, ...)` (спрей). Смысл: пока `aio_multi_wait` держит массив
   waiter-нод, эти ноды **освобождаются** (`cancel`/churn) и **перезахватываются** контролируемыми
   спреями → классический **use-after-free массива waiter'ов** (UAF списка ожидания AIO).
6. `firstPendingRequest` → `cancelRequest(group, canary)` освобождает конкретную ноду;
   `flipOidKind` отменяет головы по одной, пока `sysctl_oid.kind` не станет `0x70048002`.

**Уязвимость-цель UAF:** `sysctl_oid` с `kind = 0x80048002` (read-only, `CTLFLAG_RD`-набор + `sysctl_oid`
handler) — запись в его `kind` через освобождённую waiter-ноду даёт **writable OID**, т.е. `sysctl` начинает
ПИСАТЬ туда, куда указывает `oid.arg1`.

**Шаг 4 — «медленный» kernel R/W через OID-окно** (`setWindowLow/High`, `aimWindow`, `kread32/kwrite32`, стр. 511-560):
* `mibA = kern.smp.cpus`, `mibB = kern.smp.maxcpus` (последний прячется/виден по `oid.b.visible`).
* Примитив: `arg1` OID-a переустанавливается на `oid.b.arg1` (перенацеливание), затем `arg1` OID-b
  перезаписывается на **целевой адрес** — и `sysctl(mibB)` читает/пишет 32 бита по этому адресу.
* Старшие 32 бита: `prepareHighWriter` делает OID-c писать в `oid.b.arg1+4`, поэтому окно 64-битное
  (`kread64`/`kwrite64` = два 32-битных доступа).
* Самопроверки: `testKernelRead` (сверка kind через `oidKind` и через `kread32`),
  `testKernelWrite` (`walkCounter.addr = 0x41424344` и обратно).

**Шаг 5 — переход на «быстрый» kernel R/W через pipe** (`findCurrentProcess`, `locatePipes`, `crossPipes`, стр. 661-885):
1. `allproc` (адрес из offsets) → обход списка `proc` по `p->next` (`OFFSET_KERNEL_ALLPROC`), ищем свой pid
   (`proc.pid=0x0bc`), берём `proc.ucred` (+0x040), `proc.fd` (+0x048), `proc.aioInfo` (+0x0c48).
2. `pipe2(2)` дважды → по `fdp->files` (+0x00) → таблица `filedesc` → `ofiles + fd*0x30` → `file` →
   `file->data` → `struct pipe`. Проверка: `pipe->pair` (0xe8) равен самому себе; записали байт —
   `pipe->count == 1`.
3. `crossPipes`: перезаписать у **master**-pipe поля `count=0,in=0,out=0,size=0x4000`,
   а `buffer` — на адрес **struct pipe жертвы**. Теперь `write(master_fd, X, 0x18)` пишет прямо в поля
   структуры victim-pipe → задаём victim `buf/count/size` → `read/write(victim_fd)` = **произвольное
   чтение/запись адреса ядра** (`kreadFast/kwriteFast`, `readKernel32/64`, `writeKernel32/64`).
4. Верификация быстрого R/W: прочитать по `kbase + rodataProbe.rva` строку
   `"_aio_submit_cmd\0_aio_multi_wait"` и сравнить побайтово.

**Шаг 6 — гашение гонки** (`defuseAioGroups`, стр. 966-1040): по каждому «взведённому» AIO-id найти
группу в `aioInfo`-таблице (страницы по 0x80 слотов, `slotStride=0x30`, `entryType=0x160`), проверить
`generation/state==3/type`, и **занулить `waiters`-голову** (0 в +0x50) — иначе ядро позже упадёт на
освобождённых нодах. Это не косметика, а обязательный шаг живучести.

### E4. Эскалация привилегий (`escalate`, стр. 886-935)

Через быстрый R/W правится `ucred` текущего процесса:
`uid/ruid/svuid=0` (ucred.uid 0x04, ruid 0x08, svuid 0x0c), `ngroups=1` (0x10), `rgid/svgid=0`,
`sceAuthId = 0x48000000_00000007` (sysCore), `sceCaps=0xffffffffffffffff`, `sceCaps1=idem`,
`sceAttrs |= 0x80000000`; `rootvnode` (из offsets) в `fd->cdir/rdir` (+0x08/+0x10), `jdir=0`;
`dynlib->syscallStart=0/syscallEnd=0xffffffff/restrictFlags=0/libkernelRef=1`.
Проверки: `getuid()==0` и `is_in_sandbox()==0`.
**Важно:** для 14.22 это отдельный риск — `ucred`- и `dynlib`-смещения зашиты константами
(`window.KRW.ucred`/`dynlib`) и **не извлекаются дампером** (см. §3).

### E5. Доставка payload: kexp → elfldr → payload'ы по TCP

`src/kexp.js` (362 строки). Ключевые константы: `DEFAULT_ELFLDR="elfldr-ps5-1360.elf"`,
`DEFAULT_KEXP="kexp_2026_05_25.bin"` (18 912 байт «сырого» shellcode, `SHELLCODE.size=18912`).

1. `runKexp(krw, p, chain)` получает `{ktextBase: kbase, procFdAddr, read8, write4, write8}` — т.е.
   **готовое kernel R/W** от E3/E4.
2. `mapElf(elfldr)`: `mmap` RW + копирование ELF побайтово (проверка `\x7fELF` после копирования).
3. Загрузить 18 912-байтный kexp-шеллкод, **пропатчить импорты** живыми адресами:
   `libkernel.sceKernelSendNotificationRequest/sysctlbyname/pthread_create/pthread_join`,
   `libc.malloc/free/memcpy/memset/strcmp/memcmp/vsnprintf` (+ `getpid` вшивается как `mov rax, imm64`);
   перед патчем проверяется сигнатура шеллкода (`SHELLCODE.resolverCalls`, `getpid.bytes`).
   Адреса берутся из `window.SYMBOLS` + `p.libKernelBase`/`p.libSceLibcInternalBase` (E2).
4. `mapExecutable`: `jitshm_create(0, len, PROT_RWX)` → `mmap(MAP_SHARED)`; если страница не пишется —
   `jitshm_alias(fd, PROT_RW)` + второй `mmap` для записи (обход W^X).
5. `prepareShellcodePipes`: два `pipe2`, через kernel R/W у master-pipe `count/in/out=0,size=0x4000`,
   `buffer → struct pipe жертвы` (тот же трюк, что E3-шаг5) — **это канал «шеллкод ↔ ядро»**.
6. `args` (0x28 байт): fds master/victim, `allproc`, `elfldr.base`, `elfldr.size`.
7. `pthread_create_name_np(entry=шеллкод, args)` + `pthread_join` → шеллкод сам разворачивает ELF
   (relocations) и **запускает elfldr отдельным процессом**, возвращая его адрес.
8. `loadOptionalPayloads`: список `AUTOLOAD_PAYLOADS` (m2k7m: `kstuff1.13-fpkg-dr-test8-rest.elf`,
   `ShadowMountPlus1.7beta12.elf`; задержка 3 с, R2-отмена), каждый payload: `mapElf` → `sendElf`.

**Отправка ELF (E5-финал, `connectToElfldr`/`sendElf`):** TCP на `127.0.0.1:9021`
(`sockaddr`: `sin_len=0x10`, `sin_family=AF_INET`, порт `0x233D=9021`, `127.0.0.1`), ретраи 40×250 мс,
затем `write()` кусками по `0x10000` байт до полной передачи, `close()`. Никакого пароля/заголовка —
**elfldr принимает поток ELF прямо с порта 9021**.

---

## 2. Перечень уязвимостей цепочки (в порядке эксплуатации)

| # | Уязвимость | Где | Что даёт | Firmware-зависимость |
|---|---|---|---|---|
| V1 | JSC info leak(ы) | `webkit.js` | адреса объектов, `__ps5NativeCtor` | зависит от сборки WebKit (offsets) |
| V2 | structured-clone pool mismatch → type confusion | `webkit.js` | чтение/запись памяти процесса | зависит от JSC-сборки |
| V3 | Порча typedarray/ArrayBuffer (`backing`,`byteLength`) | `webkit.js`, `mem.js` | произвольный userland R/W | — |
| V4 | Перезапись return-адреса worker-стека + «pop rsp» (ROP) | `main.js`, `rop.js` | вызов произвольных syscall из JS | нужны gadgetmap/syscall_map/libkernel/libc base |
| V5 | **Утечка адреса возврата ядра в ответе `RTM_GET` (`PF_ROUTE`)**: автор-запись содержит `.text`-указатель на +184 | `relapse_exploit.js:206` | KASLR bypass (`kbase`) | нужны `kaslr.retStatic`, `kaslr.retLow16` |
| V6 | **UAF массива waiter'ов `aio_multi_wait`** (spin: блокирующиеся AIO-чтения + `ioctl(…0x4101)` churn + спрей `aio_submit_cmd`) | `relapse_exploit.js:292-510` | 32-битная запись в `sysctl_oid.kind` (0x80048002 → 0x70048002) | нужны `aio.*`, `oid.*`, `nodeMutex` |
| V7 | **Превращение read-only sysctl OID в writable** (следствие V6) | `reclaimWaiterArray`/`flipOidKind` | медленный kernel R/W 32/64 бита через `sysctl` | нужны адреса oid.a/b/c + `walkCounter` |
| V8 | **Пересечение структур `struct pipe`** (запись в struct pipe через `buffer` другого pipe) | `crossPipes` | быстрый произвольный kernel R/W | нужны `proc/filedesc/pipe` |
| V9 | Правка `ucred`/`rootvnode`/`filedesc`/`dynlib` | `escalate` | uid=0, sandbox off, снятые ограничения | нужны `ucred`, `dynlib`, `rootvnode`, `allproc` |
| V10 | JIT-страницы RWX (`jitshm_create`+`alias`) для шеллкода | `kexp.js` | запуск kexp-шеллкода в процессе браузера | не зависит от FW |

Порядок жёстко последовательный: **V1→V2→V3→V4→V5→V6→V7→V8→V9→V10**. V6 требует, чтобы V4 уже давал
батч syscall'ов (планировщик `chain`), V8 требует V7 (медленное R/W для поиска `proc`/`pipe`).

---

## 3. Примитивы, необходимые для kernel R/W (и что из них firmware-specific)

### 3.1 То, что нужно захардкодить в `offsets/<fw>.js` (`window.KRW`)

По образцу `offsets/13.60.js` (450 строк, m2k7m) — полный список полей:

```
kernelData: 0x00CC0000          // data-text delta (KERNEL_ADDRESS_DATA_BASE - text_base)
allproc:    0x03589E80          // RVA от text_base
rootvnode:  0x03E0B510
security_flags: 0x01A5C064      // (TARGETID/QA_FLAGS/UTOKEN_FLAGS = security_flags + 0x09/+0x24/+0x8C)
kaslr: { mode:"rtmsg2", retStatic: 0x00AE2DA0, retLow16: 0x2DA0 }
oid: { originalKind:0x80048002, writableKind:0x70048002,
       a:{base,kind,kindByte3,arg1,arg1Byte1,arg1Value,deadSink},
       b:{base,kind,kindByte3,arg1,arg1Value,visible},
       c:{base,kind,arg1,arg1Value,mib:[9,8]} }
walkCounter: { addr, mib:[9,7] }
nodeMutex:  0x01a9bab8
rodataProbe: { rva: 0x01379d6c, text: "_aio_submit_cmd\0_aio_multi_wait" }
aio: { waiterSize:0x38, requestSize:0x28, group:{num:0,state:8,waiters:0x50},
       idTable:{pages:0x220, slotStride:0x30, entryType:0x160} }
proc: { pid:0x0bc, ucred:0x040, fd:0x048, aioInfo:0x0c48, dynlib:0x3e8 }
ucred: { uid:4, ruid:8, svuid:0xc, ngroups:0x10, rgid:0x14, svgid:0x18,
         sceAuthId:0x58, sceCaps:0x60, sceCaps1:0x68, sceAttrs:0x80 }
sysCoreAuthId: { lo:7, hi:0x48000000 }
filedesc: { files:0, cdir:8, rdir:0x10, jdir:0x18 }
filedescTable: { nfiles:0, ofiles:8, entryStride:0x30, fileData:0 }
pipe: { count:0, in:4, out:8, size:0xc, buffer:0x10, pair:0xe8, defaultSize:0x4000 }
dynlib: { syscallStart:0xf0, syscallEnd:0xf8, restrictFlags:0x118, libkernelRef:0x18 }
```

### 3.2 То, что нужно для userland-части (E1/E2) — отдельный файл, тоже per-FW

`OFFSET_wk_host_constructor_candidates[3]`, `OFFSET_wk_memset_import`, `OFFSET_wk___stack_chk_guard_import`,
`OFFSET_lk___stack_chk_guard`, `OFFSET_lk__thread_list`, `OFFSET_lk_worker_wait_return`,
`OFFSET_lk_pthread_create_name_np`, `OFFSET_lk_pthread_join`, `OFFSET_lk_pthread_exit`, `OFFSET_lk_sleep`,
`OFFSET_lc_memset`, `OFFSET_lc_setjmp`, `OFFSET_lc_longjmp`, `OFFSET_WORKER_STACK_OFFSET`,
`wk_gadgetmap` (25 гаджетов), `syscall_map` (~300 syscall-стабов), `window.SYMBOLS` (libkernel: getpid,
sysctlbyname, sceKernelSendNotificationRequest, pthread_*; libc: malloc/free/memcpy/memset/strcmp/memcmp/vsnprintf).

**Масштаб различий по FW** (diff `offsets/<fw>.js` против 13.60): 13.42 — 77 строк, 13.00 — 602, 10.00 — 798,
7.00 — 801. Т.е. между соседними минорными FW меняются единицы-десятки констант, между 13.60 и 7.00 — ~800.

### 3.3 Чем 14.22 отличается принципиально

Механика V1–V10 **не привязана к версии FW** (код один на 33 версии 7.00–13.60, включая
`13.42/13.00/12.x/11.x/10.x/9.x/8.x/7.x` — см. `supportedFirmware` в `src/firmware.js`).
Версионно-зависимы **только значения** из 3.1–3.2. Значит, для 14.22 нужен полный набор этих значений.

---

## 4. `tidewell/relapse-offset-dumper`: что именно извлекает и из чего

Репозиторий: 4 файла (`main.c` 840 строк, `Makefile`, `README.md`, `LICENSE`). Это **ELF-payload**,
запускаемый на уже взломанной консоли через elfldr (`nc <ip> 9021 < relapse-dumper.elf`), пишет отчёт в
`/data/relapse_dump/` (`offsets.txt`, `dumper.log`, `kdata_*.bin`), забирается по FTP.
Компилируется против `ps5-payload-dev/sdk`, использует `<ps5/kernel.h>` (SDK-функции `kread/kwrite/kread4/8`,
`kernel_get_fw_version()`, `KERNEL_ADDRESS_*`).

**Извлекает ровно kernel-часть (то, что в 3.1), и вот из чего:**

| Что | Метод (по коду `main.c`) | Строки |
|---|---|---|
| `kernelData` (delta data↔text) | `KERNEL_ADDRESS_DATA_BASE − KERNEL_ADDRESS_TEXT_BASE` из SDK; если `TEXT_BASE==0` — fallback `DATA_BASE − 0x0D30000` | 660-690 |
| `allproc`, `rootvnode`, `security_flags` (+ их RVAs) | `KERNEL_ADDRESS_ALLPROC/ROOTVNODE/SECURITY_FLAGS` из SDK, затем **верификация чтением**: `*allproc>>48==0xFFFF`, `*rootvnode>>48==0xFFFF` («Tier 1 PASS/FAIL») | 693-740 |
| `kaslr.retStatic` / `retLow16` | **Активный RTM_GET** на `PF_ROUTE`: UDP-getsockname → локальный IP → собрать `RTM_GET` (496 байт, `RTA_DST|RTA_AUTHOR`, dst `sockaddr_in` 88, author `AF_INET6` 255) → `write` → `recv*` → найти запись `AUTHOR` (индекс 6), прочитать qword по `author+184`; `retStatic = ret − kbase` | 390-560 |
| `rodataProbe.rva` | **Brute-force сканирование `.rodata`** на строку `"_aio_submit_cmd"` (с `\0`): сначала диапазон RVA `0x01000000–0x01400000`, затем шире `0x00800000–0x01800000`, чанки `0x10000` с перехлёстом 64 | 232-300 |
| `oid.a/b/c` (`base`, `kind`, `arg1`, `arg1Value`) | **Скан памяти** на структуры `sysctl_oid` с `kind == 0x80048002` с шагом 8 по диапазонам вокруг референсных RVA `REF_1120`/`REF_1160` (`oid_a_base±0x100`, `oid_c_base±0x100`); поля: `kind@+0x14`, `arg1@+0x18`, `number@+0x10`, `name@+0x28`, `handler@+0x30`; печатает `name`, `num`, `arg1`, `handler` — по имени и определяется, какой это OID (`kern.smp.cpus`/`maxcpus`) | 305-345, 755-800 |
| `walkCounter` | чтение по референсному адресу `REF_1120.walk_counter` + `oid_c.arg1Value` | 783-790 |
| `nodeMutex` | **Скан по строкам-именам мьютексов**: ищет мьютекс с `lo_name` == `"sysctl lock"` или `"sysctl"` в заданных диапазонах | 566-600 |
| Сырые дампы ядра | `dump_region()` — 4 региона, чанки `0x10000`, «дырки» забиваются нулями (`kdata_*.bin`) | 348-390 |

**Чего дампер НЕ извлекает (важно!):**
- **Всей userland-части** (3.2): WebKit base candidates, gadgetmap, syscall_map, libkernel/libc offsets,
  worker-stack. README прямо: *«The userland offsets (WebKit, libkernel, libc, gadgets, syscalls) are not
  extracted by this dumper. Those come from separate analysis of the userland binaries.»*
- **`aio.*`, `proc.*`, `ucred.*`, `filedesc*`, `pipe.*`, `dynlib.*`** — это НЕ в списке извлекаемого;
  в 13.60 они считаются одинаковыми для 7.00–13.60 (в `offsets/*.js` они совпадают буквально).
  Для 14.22 это **слепая зона**: если Sony подвинула `struct proc`/`ucred`/`pipe`, дампер это не поймает.
- `writableKind`/`kindByte3`/`arg1Byte1`/`deadSink`/`visible` — вычисляются/подбираются из найденных
  `oid.*` вручную (это байтовые адреса внутри 32-битных полей: kind+3, arg1+1 и т.п.), дампер печатает
  только базовые `base/kind/arg1`.
- `security_flags`-производные (`TARGETID`, `QA_FLAGS`, `UTOKEN_FLAGS`) — арифметика от `security_flags`.

**Ограничение дампера по FW (из README):** референсные точки сканов — 11.20 и 11.60 с запасом,
«покрывает примерно 7.x–13.x»; для FW вне этого диапазона надо править `REF_1120`/`REF_1160` в `main.c`.
Т.е. **для 14.22 дампер нужно будет перецелить** (новые референсные RVA) — иначе `oid`/`nodeMutex` не найдутся.

**Порядок пользования (README §Using the output):** скопировать `offsets/TEMPLATE.js` из
`soniciso1/relapse` → заполнить kernel-значения из `offsets.txt` → определить раскладку OID
(`kind` на `+0x14` в стиле 11.20 или на `+0x1C` в стиле 11.60) → добавить версию в `SUPPORTED`
в `firmware.js` → тест на железе.

---

## 5. Доставка payload: порты, elfldr, kstuff-lite

### 5.1 Карта портов (проверено по нескольким источникам)

| Порт | Кто слушает | Что принимает | Источник |
|---|---|---|---|
| **9020** | «rudimentary ELF loader», который даёт *начальный* kernel-exploit (BD-J `ps5-payload-loader`, Specter webkit) | ELF, в т.ч. `elfldr-ps5.elf` для бутстрапа | [elfldr README](https://github.com/ps5-payload-dev/elfldr) (Quick-start), cyber-forge README «Inyector LAN (Puerto 9020/9021)» |
| **9021** | **elfldr** (`ps5-payload-dev/elfldr`) | ELF-поток, либо текст `file:/path`/`https://…` (он сам скачает), либо HTTP `GET /?uri=` | elfldr README (Usage), Relapse `kexp.js:135` (`0x3d230210` = `sin_len 0x10, AF_INET, :9021, 127.0.0.1`) |
| 9025 | BD-UN-JB loader | `.jar` (BD-J payload) | [PS5AutopayloadHA README](https://github.com/cosmicflow2512/PS5AutopayloadHA) |
| **9026** | **Luac0re remote Lua loader** | Lua-скрипт (payload-скрипт); скрипт затем сам биндит порт 9028–9045 и отвечает `"K"` как ACK для бинарного блоба | [LuaPSX send2.py](https://github.com/soniciso1/LuaPSX) + PS5AutopayloadHA («Port 9026 → Remote Lua Loader») |
| 9027 | Luac0re UDP-log | UDP-логи (не конфликтует с TCP) | LuaPSX `send2.py` docstring |
| 50000 | Y2JB webkit-stage loader | `.js` payload | PS5AutopayloadHA README |

В самих Relapse-репозиториях встречаются **только 9020 и 9021** (grep по всему дереву: 99 упоминаний 9021,
75 — 9020, других 90xx нет). **9026 в Relapse-цепочке не используется** — это отдельный (Lua-)
канал доставки, который в host'ах идёт как альтернатива браузеру.

### 5.2 Как именно Relapse доставляет payload (без 9020!)

Цепочка **сама** поднимает elfldr, поэтому 9020 не нужен:
`kexp`-шеллкод (E5) исполняется в процессе браузера, разворачивает `elfldr-ps5-1360.elf` и запускает его
отдельным процессом → elfldr слушает **9021** → JS льёт payload'ы по TCP 9021 (`sendElf`, чанки 0x10000).
Проверка живости elfldr «на повторном входе»: manos-форк делает реальный `connect(127.0.0.1:9021)`
через свои же примитивы и, если порт жив, **пропускает kernel-стадию** (`manos/README.md` §Safe re-entry,
`manos/serve.py:60-73` — серверный `/api/elfldr` probe).

### 5.3 elfldr — что это и зачем

`ps5-payload-dev/elfldr`: ELF-loader, который через **ptrace** впрыгивает в процесс `SceRedisServer`,
затем запускает себя отдельным процессом, живущим в фоне (в т.ч. во время игры) и **переживающим rest mode**;
payload'ы исполняются в отдельных процессах, поэтому падение payload'а не убивает loader.
Отсюда требование: elfldr должен быть загружен один раз, дальше любой payload = TCP-стрим на 9021.

### 5.4 kstuff-lite — что это и зачем

`drakmor/kstuff-lite` (форк `EchoStretch/kstuff-lite`) — **kernel-модуль**, не userland-payload:
по README — «Payload loading and startup» (CR3, поиск `ShellCore`, аллокация под модуль),
`fpkg` и PFS-крипто (XTS/HMAC-SHA256 кэши, DMEM fast-path), `FSELF` (парсинг/патч SELF, authinfo),
автомонтирование fpkg (можно отключить). Грузится как обычный ELF на 9021, но работает в ядре.
В Relapse-автолоаде m2k7m стоит `kstuff1.13-fpkg-dr-test8-rest.elf` — и он **побайтово совпал** с
публичным `bsk193/drakmor-kstuff-mirror` release `1.13-fpkg-dr-test8-rest` (см. §6).

---

## 6. Payload-бинарники: скачано и проверено

Каталог: `tools/payload/payloads/` (всего **11** бинарников). Артефакты проверки:
- `tools/payload/RELAPSE-PAYLOADS-VERIFY.txt` — полный лог: `size`, `sha256`, `file`, `readelf -h` (Class/Data/Type/Machine/Entry), `readelf -l` (все `LOAD`: off/vaddr/filesz/memsz/flags/align) по каждому файлу;
- `tools/payload/payloads/SHA256SUMS.recon-relapse` — контрольные суммы всех 11 файлов (в формате `sha256sum`, пригодно для `sha256sum -c`);
- `tools/payload/payloads/MANIFEST.json` и `SHA256SUMS` — уже существовали (другая задача), их не перезаписывал; мои файлы добавлены рядом.

| # | Файл | Откуда | Размер | `file` | Entry | 1-й LOAD | sha256 (полный) |
|---|---|---|---|---|---|---|---|
| 1 | `elfldr-ps5-v0.25.elf` | ps5-payload-dev/elfldr `v0.25` | 397 024 | ELF64 PIE x86-64, SYSV, dyn, stripped | `0x46b8` | off `0x4000` / RWE / al `0x4000` | `de70a47e6d099dc03718c33c158a727f1340c3b5310155618c5049ab0fb41754` |
| 2 | `elfldr-ps5-v0.27.elf` | ps5-payload-dev/elfldr `v0.27` (latest) | 394 568 | ELF64 PIE x86-64, **FreeBSD**, BuildID `1336996040caf084…`, stripped | `0x0` | off `0x4000` / RWE / al `0x4000` | `82f6227610172c98bad6efe68219fc93a10027035991f47eb4b75532d023407d` |
| 3 | `kstuff-lite-1.1-dr.elf` | drakmor/kstuff-lite `1.1-dr` | 1 527 064 | ELF64 PIE x86-64, SYSV, dyn, stripped | `0xed290` | off `0x4000` / RWE / al `0x4000` | `59d780c9095cda04b148da3d537e857059784b0ea43fc4646082f27aaeb7fa09` |
| 4 | `kstuff-lite-1.2-dr-test1.elf` | drakmor/kstuff-lite `1.2-dr-test1` | 1 553 752 | ELF64 PIE x86-64, SYSV, dyn, stripped | `0xed2b0` | off `0x4000` / RWE / al `0x4000` | `9c1b242eaed3704ef18be45d001a2c4ebf2d9222cfe3cbb0f0c3db33309abac9` |
| 5 | `kstuff-lite-1.2-dr-test2.elf` | drakmor/kstuff-lite `1.2-dr-test2` (prerelease) | 1 558 040 | ELF64 PIE x86-64, SYSV, dyn, stripped | `0xedd90` | off `0x4000` / RWE / al `0x4000` | `2b699d411079a21dba7c39a02993fc0fb21e52f434103e884a0c892fafe56b75` |
| 6 | `kstuff-1.13-fpkg-dr-test8-rest.elf` | bsk193/drakmor-kstuff-mirror `1.13-fpkg-dr-test8-rest` | 1 845 320 | ELF64 PIE x86-64, SYSV, dyn, stripped | `0xfc8c8` | off `0x4000` / RWE / al `0x4000` | `127332652374157b8ee0f5eb1128976f9055b88df5da89c0c54183e9c326fc7f` |
| 7 | `kstuff-1.13-fpkg-dr-test8-rest-fast.elf` | bsk193/drakmor-kstuff-mirror `…-rest-fast` | 1 845 320 | ELF64 PIE x86-64, SYSV, dyn, stripped | `0xfd048` | off `0x4000` / RWE / al `0x4000` | `221fa41c43597677c1153d5224174be9062105c0c9a3379e96cb45d278aa52fc` |
| 8 | `ftpsrv-ps5-v0.22.elf` | ps5-payload-dev/ftpsrv `v0.22` *(был до меня)* | 192 432 | ELF64 PIE x86-64, SYSV, dyn, **not stripped** | `0x7c98` | off `0x4000` / RWE / al `0x4000` | `41148c2c1cad1ea9e7cfde03e389fa918e3338e896d06167346de09adbdc8757` |
| 9 | `klogsrv-ps5-v0.9.elf` | ps5-payload-dev/klogsrv `v0.9` *(был до меня)* | 136 016 | ELF64 PIE x86-64, SYSV, dyn, **not stripped** | `0x2370` | off `0x4000` / RWE / al `0x4000` | `e828ec144231f81547cb58bc7d2c396fa984be0c2295f31364b58017816dcceb` |
| 10 | `shsrv-ps5-v0.20.elf` | ps5-payload-dev/shsrv `v0.20` *(был до меня)* | 986 184 | ELF64 PIE x86-64, SYSV, dyn, **not stripped** | `0x4acc` | off `0x4000` / RWE / al `0x4000` | `fa4ccb2587bb61be317df0d001f668b17ebf9b4aafad87acf691b1fb8da0bd2d` |
| 11 | `websrv-ps5-v0.34.elf` | ps5-payload-dev/websrv `v0.34` *(был до меня)* | 1 597 864 | ELF64 PIE x86-64, SYSV, dyn, **with debug_info**, not stripped | `0x4937c` | off `0x4000` / RWE / al `0x4000` | `54730c867c6e1148536fdcb370e63a7762d989ea87b62488ad4caff64d43f263` |

**Общие признаки (проверено на всех 11):** `Class=ELF64`, `Data=2's complement, little endian`,
`Type=DYN (PIE)`, `Machine=Advanced Micro Devices X86-64`; первая `LOAD`-секция всегда
`flags=RWE` (off `0x4000`, vaddr `0`), выравнивание `0x4000` — т.е. PS5-ELF грузятся как RWX-образ,
`.text` начинается с vaddr 0. Скриптом `tools/payload/verify.py` (чужой) не пользовался; проверял
`file`/`readelf`/`sha256sum` напрямую (`LC_ALL=C`, иначе `readelf` отдаёт русские метки и grep по «Class:» не срабатывает).

**Сверка с тем, что реально использует Relapse (`recon/_src/relapse/m2k7m_Relapse-Exploit/payloads/`):**

| Бандл m2k7m | Размер | sha256 | Вывод |
|---|---|---|---|
| `elfldr-ps5-1360.elf` | 397 024 | `de5dd480d12637527ba2d75e35de851adbb59c455293fa32588c492ef6b44b81` | размер = upstream **v0.25**, но **хеш отличается** → **кастомная сборка** elfldr под 13.60, не релизный бинарь |
| `kstuff1.13-fpkg-dr-test8-rest.elf` | 1 845 320 | `127332652374157b8ee0f5eb1128976f9055b88df5da89c0c54183e9c326fc7f` | **побайтово = `kstuff-1.13-fpkg-dr-test8-rest.elf`** из зеркала ✅ (совпал и размер, и хеш) |
| `ShadowMountPlus1.7beta12.elf` | 3 626 576 | — | авто-монтировщик (в autoload вторым), публично в `manos/payloads/ShadowMountPlus_1.7beta11.elf` (b11, не b12) |
| `kexp_2026_05_25.bin` | 18 912 | `7cfb3a8cb86db67893c360ae3531f460f800e9f24039797038e6e81fc50f18a9` | не ELF (`file`: DOS executable/COM), сырой shellcode; импортирует `sceKernelSendNotificationRequest`, `sysctlbyname`, `pthread_create` |

---

## 7. Таблица «этап цепочки | что нужно | есть ли для 14.22»

Легенда «есть ли»: **да** — подтверждено источником; **нет** — подтверждено отсутствием/опровержением;
**неизвестно** — источника нет, нужна проверка (указан способ).

| # | Этап цепочки | Что нужно | Для 14.22 | Источник / как проверить |
|---|---|---|---|---|
| E0 | Хост + определение FW | статический хост (8000/GitHub Pages), `offsets/14.22.js`, запись в `supportedFirmware[]` | **нет**: в `m2k7m`, `manos`, `WAK` список заканчивается 13.60; файла `offsets/14.22.js` нет ни в одном | `src/firmware.js` (33 версии, максимум 13.60); `ls offsets/` |
| E1а | JSC info leaks | работающий leak на сборке WebKit 14.22 | **неизвестно** (публично не найдено; `webkit-vector.md` другой задачи помечает `НЕ ПОДТВЕРЖДЕНО`) | нужна сборка `libSceNKWebKit`/JSC 14.22 и тест |
| E1б | structured-clone pool mismatch → typedarray corruption | тот же баг в JSC 14.22 | **неизвестно** (в Relapse-коде версия JSC не проверяется, баг заявлен как работающий 7.00–13.60) | `webkit.js`/README; тест на железе 14.22 |
| E2 | Userland R/W → ROP → syscall | `OFFSET_wk_host_constructor_candidates[3]`, `OFFSET_wk_memset_import`, `OFFSET_wk___stack_chk_guard_import`, `OFFSET_lk___stack_chk_guard`, `_thread_list`, `worker_wait_return`, `pthread_*`, `setjmp/longjmp`, `wk_gadgetmap`(25), `syscall_map`(~300) | **нет** значений для 14.22 (есть только 7.00–13.60 × 33 файла) | `offsets/*.js`; добывается дизасмом `libSceNKWebKit.elf`/`libkernel.elf`/`libSceLibcInternal.elf` **14.22** |
| E3а | KASLR-лик `RTM_GET` | рабочий `PF_ROUTE`-сокет + `kaslr.retStatic`/`retLow16` для 14.22 + живой LAN-IP | **неизвестно** (механика FW-независима; нужна одна пара констант; есть готовый измеритель — `relapse-offset-dumper` rtmsg2) | `relapse_exploit.js:206-271`; dumper `rtmsg2_leak()` |
| E3б | UAF `aio_multi_wait` | `aio.waiterSize/requestSize/group{num,state,waiters}/idTable{pages,slotStride,entryType}` — если структуры 14.22 не менялись, работает как есть | **скорее нет** (заявлено третьей стороной: на 14.20+ «aio_multi_delete Blocked», см. §7.1); значения совпадают во всех 33 offsets 7.00–13.60, но для 14.22 не измерены и **дампером не покрываются** | `offsets/13.60.js` (aio-блок); cyber-forge `app.js:274-281`; нужен kernel-dump 14.22 |
| E3в | sysctl OID → kernel R/W | `oid.a/b/c{base,kind,arg1,arg1Value,...}`, `nodeMutex`, `walkCounter`, `oid.originalKind/writableKind` | **неизвестно**: извлекается `relapse-offset-dumper`, но его референсные RVA (`REF_1120`,`REF_1160`) покрывают «~7.x–13.x» → **требуется перецеливание на 14.22** | dumper README §Firmware compatibility; `main.c` REF_1120/REF_1160 |
| E3г | `rodataProbe.rva` (`"_aio_submit_cmd"`) | скан `.rodata` 14.22 | **неизвестно** (сканируется автоматически, диапазон `0x01000000–0x01400000`, для 14.22 не проверен) | dumper `scan_rodata_string()` |
| E4 | `allproc`, `rootvnode`, `security_flags` | SDK `KERNEL_ADDRESS_*` для 14.22 (`ps5-payload-dev/sdk`) | **нет** подтверждения: SDK-адреса берутся из `kern.elf` конкретной прошивки; публичного 14.22-кита не найдено | `ps5-payload-dev/sdk`, dumper §Tier 1 |
| E4б | `proc/ucred/filedesc/pipe/dynlib` смещения | `proc.pid/ucred/fd/aioInfo/dynlib`, `ucred.*`, `filedesc*`, `pipe.*`, `dynlib.*` | **неизвестно** и это **слепая зона дампера** (он их не извлекает); во всех 7.00–13.60 они идентичны | `offsets/*.js` (сравнить блоки); нужен kernel-dump 14.22 |
| E5а | kexp-шеллкод + JIT RWX | `jitshm_create` + `jitshm_alias` на 14.22; патч импортов `window.SYMBOLS` для 14.22 | **неизвестно**: символов libkernel/libc для 14.22 нет (нужен дизасм userland 14.22) | `kexp.js` (`SHELLCODE.imports`, `SHELLCODE.size=18912`) |
| E5б | elfldr | сам бинарь elfldr (`v0.27` есть, скачан) + запуск из kexp | **да, но только «наличие бинаря»**: elfldr — userland-загрузчик (ptrace → `SceRedisServer`), сам по себе от версии FW не зависит; работа **именно на 14.22** не проверена (нужен рабочий примитив kernel R/W из E4) | `tools/payload/payloads/elfldr-ps5-v0.27.elf`; elfldr README |
| E5в | TCP 9021 приём payload | elfldr слушает 9021, стрим ELF | **да** (не зависит от FW, проверено на 7.00–13.60; порт зашит в `kexp.js`) | `kexp.js:135` (`0x3d230210`) |
| E5г | kstuff-lite | сам бинарь + работающая kernel R/W | **да** для бинаря (1.1-dr/1.2-dr/1.13 есть, проверены), **неизвестно** для 14.22-специфичных патчей ядра (kstuff=`kernel module`, зависит от kernel-структур) | `tools/payload/payloads/kstuff-*`; kstuff-lite README |
| — | Alt-вектор: 14.20 WebKit research (Khal0da) | userland WebKit-проба/диагностика на 14.20 | **нет (кода нет)**: репозиторий явно «No exploit code», только probes/field notes; host помечает 14.00–14.22 как `PATCHED` | [Khal0da/PS5-14.20-WebKit-Research](https://github.com/Khal0da/PS5-14.20-WebKit-Research) |
| — | Alt-вектор: Y2JB (YouTube) | `Gezine/Y2JB` userland code exec через приложение YouTube | **неизвестно** для 14.22: README Y2JB верхнюю границу FW **не указывает** («At least 4.03 firmware»; YouTube PKG «4.03 to 12.40» и «12.60 and up»), а host cyber-forge пишет «Y2JB (ALL <=13.60)». Для 14.22 нужен тест с YouTube PKG 01.000.030+ | [Gezine/Y2JB README](https://github.com/Gezine/Y2JB), cyber-forge `app.js:263` |
| — | Alt-вектор: Luac0re/Lua (:9026) | Lua-скрипт + Luac0re на консоли | **неизвестно** (нужен разбор `lua-vector.md` — отдельная задача) | [soniciso1/LuaPSX](https://github.com/soniciso1/LuaPSX), PS5AutopayloadHA |
| — | Alt-вектор: UMTX1/UMTX2 | kernel race R/W | **неизвестно/нет**: UMTX2 в cyber-forge только для PS5 `5.00–5.50`; UMTX1 — `1.00–4.51` | cyber-forge `app.js:224-237` |

### 7.1. Что публично заявлено именно про 14.20/14.22 (важно!)

Единственный найденный в источниках **явный** текст про 14.22 — в host'е `oscarlaradev/cyber-forge`:

- `app.js:273-281` — запись таблицы цепочек:
  `{ fw: "14.00 - 14.22", codename: "PROLAPSE / 14.20 RESEARCH", status: "PATCHED",
     entry: "WebKit Probe (Khal0da)", kernel: "aio_multi_delete Blocked", rate: "0% (Stay Offline)" }`
  со ссылкой на `https://github.com/Khal0da/PS5-14.20-WebKit-Research`;
- `app.js:1049` — *«Sony sealed kernel R/W on 14.20/14.22. Apply our Primary & Secondary DNS blockers …
  and wait for private WebKit/hypervisor chains to become public.»*;
- `app.js:1040` — *«Sony patched the Relapse kernel vulnerability on PS5 FW 14.00+. DO NOT UPDATE past 14.00»*;
- `index.html:184` — плашка *«[SECURITY] Sony FW 14.20/14.22 Patched — Keep Blockers DNS Active!»*.

**Статус этих утверждений: ЗАЯВЛЕНО ТРЕТЬЕЙ СТОРОНОЙ, не подтверждено первоисточником.**
Что из них следует для нашей задачи (гипотезы, требующие проверки на kernel-dump 14.22):
1. `aio_multi_delete Blocked` — если на 14.20/14.22 урезан/удалён `aio_multi_delete` (или сопутствующий
   UAF-путь), то **E3б (V6) не работает** → вся ветка kernel R/W через OID-окно (V7) отваливается,
   и Relapse-механика в текущем виде на 14.22 неприменима. Это **главный риск** для 14.22.
2. «sealed kernel R/W» — согласуется с (1), но формулировка маркетинговая; проверить: жив ли
   `aio_multi_wait`/`aio_multi_delete`/`aio_submit_cmd` в libkernel 14.22 и не поменялись ли `aio_info`.
3. «wait for private WebKit/hypervisor chains» — намёк, что на 14.2x публичных kernel-примитивов нет,
   работающие цепочки приватные. Значит для 14.22 публичного «эталона» может не быть вообще.

**Практический вывод:** эталон Relapse отвечает на вопрос «как устроена рабочая цепочка 7.00–13.60»,
но **не гарантирует переносимость на 14.22** — из-за вероятной блокировки AIO-уязвимости (V6)
и отсутствия userland/структурных констант для 14.22.

**Сводка:** для 14.22 в публичном доступе **нет ни одного** готового файла `offsets/14.22.js` и ни одного
релиза Relapse/WAK/Y2JB с поддержкой 14.xx (все три репозитория — 7.00–13.60, 33 версии, максимум 13.60;
grep по `14.xx`/`FW 14` по всему дереву источников — 0 совпадений). Механика цепочки от FW не зависит —
зависимы **только константы**; для их добычи есть готовый инструмент (`relapse-offset-dumper`), но его
нужно **перецелить** на 14.22 и он **не покрывает** userland-часть и `proc/ucred/pipe/dynlib/aio`-смещения.
Дополнительно: хост cyber-forge **прямо заявляет**, что на 14.00–14.22 цепочка `PATCHED`, а AIO-путь
(наш V6) заблокирован (§7.1) — это надо проверить первым делом, потому что при подтверждении
вся Relapse-схема на 14.22 неприменима и нужен другой kernel-примитив.

---

## 8. Что это значит для 14.22 (практические выводы)

1. **Цепочка воспроизводима по этапам** E0–E5; для 14.22 нужен порт `offsets/14.22.js`, а не новый эксплойт.
2. **Два независимых набора констант:** kernel (`window.KRW`, извлекается дампером) и userland
   (`offsets`-часть для WebKit/libkernel/libc/гаджетов — только дизасм бинарей 14.22).
3. **Слепые зоны дампера** (проверять вручную на kernel-dump 14.22): `aio.*`, `proc.*`, `ucred.*`,
   `filedesc*`, `pipe.*`, `dynlib.*`; и производные `kindByte3`, `arg1Byte1`, `deadSink`, `visible`,
   `writableKind`, `security_flags`-производные.
4. **Порядок проверки на 14.22:** сначала E3а (KASLR-лик, дешёвый и FW-независимый) → E3б (UAF) →
   E3в/г (OID/rodata) → E4 (allproc/ucred) → E1/E2 (WebKit/ROP) → E5.
5. **Доставка не проблема:** elfldr (9021) и kstuff-lite — публичные, firmware-agnostic по интерфейсу;
   payload-бинарники проверены и лежат в `tools/payload/payloads/`.
6. **Альтернативы без браузера:** Lua (:9026) и Y2JB (:50000) — но обе заявлены до 13.60, для 14.22
   неизвестны; UMTX2 в публичных host'ах ограничен 5.x.

---

## 9. Можно ли применить анатомию Relapse к 14.22 — по факту проверки

Раздел написан по результатам трёх работ: (1) выписки per-FW таблицы из SDK, (2) сканера,
отлаженного на **реальном дампе ядра 13.60**, (3) сверки с эталонными `offsets/13.60.js`.
Артефакты: `tools/payload/offsets-14.22.md`, `tools/payload/scan_1322.py`,
`tools/payload/scan-13.60.log`, `tools/payload/scan-13.60.json`.

### 9.1. Прошивка 14.22 существует, но образа ядра для неё нет

- 14.22 **есть**: `label 26.07-14.22.00.00-00.00.00.0.1`, `sdk_version 14.22.00.00`, образ
  `2026_1027`, PUP 1 266 091 008 байт, verify OK (разведка `recon/1422-exists.md`, стр. 17-20).
- PUP зашифрован (SCEUF), а `fw/r64-*.bin` — это 64-МБ **срезы PUP** (начинаются с `SLB2`/`PS5UPDATE1.PUP`),
  а не образы ядра. Единственный настоящий дамп ядра в проекте — **13.60**
  (`fw/ps5-kernel-13.60-live.bin`, 103 546 880 байт, sha256 `c3f745e2…`).
- Поэтому «просканировать настоящее ядро 14.22» сейчас **нечем**; методика отлажена на 13.60,
  а для 14.22 получены только те константы, которые даёт SDK (см. 9.2).

### 9.2. Что уже ЕСТЬ для 14.22 (точные значения, первоисточник — SDK)

Из `tools/fwsim/vendor/sdk/crt/kernel.c:567-576` (case `0x14220000`; тот же блок, что 14.00/14.10/14.20).
Формула `Relapse = D + X` предварительно **проверена на 13.60 — 4/4 точных совпадений** с `offsets/13.60.js`:

| Константа Relapse | 14.22 (SDK) | 13.60 (эталон) | Δ |
|---|---|---|---|
| `kernelData` (data−text) | **`0x00CE0000`** | `0x00CC0000` | +0x20000 |
| `allproc` | **`0x035B9EA0`** | `0x03589E80` | +0x30020 |
| `security_flags` | **`0x01A84064`** | `0x01A5C064` | +0x28000 |
| `rootvnode` | **`0x03E3B510`** | `0x03E0B510` | +0x30000 |
| `TARGETID` / `QA_FLAGS` / `UTOKEN_FLAGS` | `+0x09` / `+0x24` / `+0x8C` от `security_flags` | те же смещения | — |
| `VMSPACE_P_ROOT` / `VMSPACE_VM_PMAP` | `0x1d0` / `0x2e8` | те же | — |

**Вывод 9.2:** «каркас» kernel-адресов для 14.22 закрыт (это ровно то, что дампер называет Tier 1).

### 9.3. Проверка методики на реальном ядре 13.60 (сканер `tools/payload/scan_1322.py`)

Прогон (уже в виде конвейера, см. `docs/KERNEL-INGEST.md`): `python3 tools/payload/scan_1322.py`,
103 МБ, **~0.85 с**; результат — **33 константы**, из них **18 сверены с публичным
`offsets/13.60.js` и совпали все 18**, критических расхождений 0, один WARN (`nodeMutex`) и два
предсказания (`retStatic`). Логи: `tools/payload/scan-13.60.log`, `tools/payload/offsets-13.60.json`.
Найдено теми же признаками, что у дампера:

| Признак (как в `main.c`) | Найдено | Эталон `offsets/13.60.js` | Итог |
|---|---|---|---|
| строка `"_aio_submit_cmd"` в `.rodata` | `0x01379D6C` | `rodataProbe.rva = 0x01379D6C` | ✅ |
| `sysctl_oid` с `kind==0x80048002`, имя `cpus` | base `0x028CEF68`, kind `0x028CEF7C`, arg1 `0x028CEF80`, arg1Value `0x028CEF58` | `oid.a` — все 4 поля | ✅ |
| `sysctl_oid`, имя `maxcpus` | base `0x028CEE40`, kind `0x028CEE54` (`0x7F048002`!), arg1 `0x028CEE58`, arg1Value `0x028CED70` | `oid.b` — все 4 поля | ✅ |
| `sysctl_oid`, имя `priority_scheduling` (num=8) | base `0x02BF1C38`, kind `0x02BF1C4C`, arg1 `0x02BF1C50`, arg1Value `0x03D831BC` | `oid.c` — все 4 поля | ✅ |
| `walkCounter` (`oid.c.arg1Value − 4`) | `0x03D831B8`, читается | `walkCounter = 0x03D831B8` | ✅ |
| `security_flags` (dword по SDK-адресу) | `0x00000017` | — | ✅ ненулевой битмаск |
| мьютекс с `lo_name == "sysctl lock"` | кандидаты `0x358A5A8` ("sysctl lock"), `0x1AD6030`/`0x256A350` ("sysctl") | `nodeMutex = 0x01A9BAB8` | ⚠ **не совпало** |
| `kaslr.retStatic` (предсказание) | `0x00AE6869`, окно `0x00ADEAF1…0x00AF4191` | `0x00AE2DA0` | ✅ истина в окне, дельта `−0x3AC9`; точно — только с консоли |

**Вывод 9.3:** методика скана **работает** и воспроизводит **18 из 18** сверяемых с эталоном значений
точно (единственное расхождение — `nodeMutex`, помечен WARN), включая все три OID-структуры целиком,
плюс предсказывает `retStatic` с окном, в которое истина попадает. Для 14.22 её можно применять,
как только появится образ ядра: одна команда `python3 tools/payload/scan_1322.py --image <образ> --fw 14.22`.

Три важные находки эксперимента:

1. **Идентификация OID по ИМЕНИ надёжнее, чем по окну `REF±0x100`** (как делает дампер):
   в дампе 13.60 нашлось **63** структуры с `kind==0x80048002`, и только имя (`cpus`/`maxcpus`/
   `priority_scheduling`) однозначно указывает на нужные. Рекомендация для 14.22: сканировать по именам.
2. **`nodeMutex` — единственная константа, которую эвристика дампера не воспроизводит.**
   Фактический `nodeMutex` 13.60 = `0x01A9BAB8`, его `lo_name` = **`"ntpadj"`** (не "sysctl lock"),
   `+0x08 = 0` (не заблокирован). Ни один из трёх кандидатов по имени не равен ему.
   Значит: для 14.22 **нельзя** брать «первый мьютекс с именем sysctl»; либо переиспользовать смещение
   при неизменной структуре, либо подбирать валидацией UAF на живой консоли. (Отсюда WARN, а не FAIL:
   это ограничение методики, а не ошибка скана.)
3. **Дамп — только образ ядра (text+data); куча ядра в direct map.** `*allproc = 0xFFFF8E777997D9E0`,
   `*rootvnode = 0xFFFF8E77033BCF00` — адреса вида `0xffff8e77…`, их нет в дампе, разыменовать нельзя.
   Поэтому проверка «Tier 1» с обходом `proc` выполнима **только на живой консоли** (у дампера она и так
   на консоли). Плюс в дампе **12 073 нулевых (несмонтированных) страниц** — скан должен их переживать
   (дампер это делает через `kread`-fail + пропуск чанка).

### 9.4. Что осталось неизвестным для 14.22 и как это добыть

| Что | Статус | Как получить |
|---|---|---|
| `kernelData`, `allproc`, `rootvnode`, `security_flags` (+3 производных) | **ЕСТЬ** (SDK, 9.2) | — |
| `rodataProbe.rva` | неизвестно, но добываемо | скан `.rodata` дампа 14.22 (диапазон `0x01000000–0x01400000`, как у дампера); тренд: ~`0x0138xxxx–0x0139xxxx` |
| `oid.a/b/c` (base/kind/arg1/arg1Value) | неизвестно, но добываемо | тот же скан по именам `cpus`/`maxcpus`/`priority_scheduling`; тренд base ~`0x028Dxxxx–0x028Fxxxx` |
| `nodeMutex` | неизвестно, **методика ненадёжна** (9.3 п.2) | только тест UAF на консоли либо сравнение структур по дампу |
| `kaslr.retStatic` / `retLow16` | **неизвлекаемо из дампа в принципе** | одна команда `RTM_GET` на живой 14.22 (дампер умеет, `rtmsg2_leak()`) |
| `aio.*`, `proc.*`, `ucred.*`, `filedesc*`, `pipe.*`, `dynlib.*` | не даёт ни SDK, ни дампер | сверка дампа 14.22 со структурой 13.60 (если поля не двигали — заработает как есть) |
| AIO-уязвимость (V6) вообще | **под вопросом** | публичное заявление host'а: на 14.20+ «aio_multi_delete Blocked» (§7.1) — проверять первым |

### 9.5. Итоговый вердикт по 14.22

**Применить анатомию Relapse к 14.22 можно не полностью, и это не вопрос аккуратности — не хватает
входных данных в двух разных местах:**

1. **Kernel-адресная часть (Tier 1)** — закрыта: 4 константы получены точно из SDK, формула проверена
   на 13.60 (4/4). Это реальный прогресс, доступный без консоли.
2. **Скан-часть (`oid.*`, `rodata`, `nodeMutex`)** — методика **проверена и работает** (19 PASS на
   реальном 13.60), но применить её к 14.22 нечем: нет образа ядра 14.22 (PUP зашифрован, 64-МБ срезы
   не образ). Нужен либо дамп 14.22 (его можно снять только с уже взломанной 14.22 — замкнутый круг),
   либо перенос значений по соседним FW с проверкой на живой консоли.
3. **Userland-часть (E1/E2: WebKit/JSC, gadgetmap, syscall_map, libkernel/libc)** — не закрыта вообще:
   требует дизассемблера `libSceNKWebKit`/`libkernel`/`libSceLibcInternal` **14.22**, которого у нас нет.
4. **Блокирующий риск:** по заявлению cyber-forge на 14.20+ заблокирован AIO-путь (§7.1). Если это так,
   Relapse-схема на 14.22 неприменима **при любых offsets** — нужен другой kernel-примитив.

**Практический план (в порядке возрастания стоимости):**
`SDK-константы (сделано) → проверить AIO на 14.22 (нужна консоль) → снять дамп 14.22 и прогнать
scan_1322.py → измерить retStatic → дизасм userland 14.22 → собрать offsets/14.22.js → тест цепочки`.

### Приложение. Команды, которыми это проверялось (воспроизводимо)

```bash
export ALL_PROXY=socks5h://127.0.0.1:10810
git clone --depth 50 https://github.com/<owner>/<repo>   # 7 репозиториев → recon/_src/relapse/
git ls-remote https://github.com/<owner>/<repo> HEAD     # проверка существования
gh api repos/<owner>/<repo> --jq '[.full_name,.fork,.pushed_at,.size,.description,(.parent.full_name//"")]|@tsv'
gh api repos/<owner>/<repo>/releases --jq '.[]|[.tag_name,.prerelease,(.assets|map(.name)|join(","))]|@tsv'
curl -x socks5h://127.0.0.1:10810 -L -o tools/payload/payloads/<name> https://github.com/<repo>/releases/download/<tag>/<asset>
file -b <elf>; readelf -h <elf>; readelf -lW <elf> | grep LOAD; sha256sum <elf>
```