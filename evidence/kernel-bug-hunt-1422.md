# Охота за kernel-багом под PS5 14.22: карта поверхностей + триггеры (task-34)

**Агент:** recon-relapse · **Дата:** 2026-11-11 · **Консоли нет** — работа по дампу ядра 13.60
(`fw/ps5-kernel-13.60-live.bin`, sha256 `c3f745e2…`) и публичным исходникам FreeBSD 11.4.

> **Главное:** найдено 5 достижимых из userland кандидатов, для каждого написан и **собран** триггер
> (`tools/kexpl/*.elf`, 5 валидных ELF64). Два из них — свежие фиксы FreeBSD, которых заведомо не было
> в форке Sony: **UMTX UAF (SA-24:14, 2024)** и **IPV6_MSFILTER UAF (SA-26:29, 2026)**. Шесть
> «горячих» CVE-кандидатов из списка отброшены с обоснованием (§4): не тот код, не та сборка, не тот ABI.

---

## 1. Метод и что реально удалось/не удалось

1. **Дамп 13.60** → таблица sysent: `fw/sysent-13.60.json` (`sysent_native.entries_total = 735`,
   `implemented_entries = 496`, `nosys_entries = 239`; stride 48; vaddr `0xffffffff9f266e50`).
   Имена — из сверки с ZigZag (`recon/_src/t14/sysent-names-13.60-native.csv`, 735/735).
2. **Публичный FreeBSD 11.4** (`releng/11.4`) — проверка, есть ли в базовой ветке код/структуры,
   которых касаются известные фиксы: скачаны `sys/sys/umtx.h`, `sys/netinet6/in6.h`,
   `sys/kern/kern_umtx.c` (см. §6).
3. **Cross-check с Security Advisories FreeBSD** (индекс 737 записей, `freebsd.org/security/advisories/`):
   отобраны 45 SA, касающихся наших поверхностей; из них детально прочитаны 8 (§4).
4. **SDK собрать не удалось — и это ограничение зафиксировано:** `tools/fwsim/vendor/sdk` (v0.45)
   требует host `clang-18`/`lld-18` (`bin/prospero-clang` — шелл-обёртка над `clang` из LLVM_BINDIR),
   а в системе их нет; `apt`/`dpkg` отсутствуют, root нет, `pip install ziglang` не скачался через
   DPI-прокси. Поэтому триггеры собраны **freestanding**: `gcc -nostdlib -static -no-pie`, никакой libc
   и libkernel, все вызовы — raw `syscall`. Это **валидный PS5 payload**: elfldr поддерживает ET_EXEC
   (`tools/fwsim/vendor/elfldr/elfldr.c:172-178`: `ctx.base_addr = min_vaddr; flags |= MAP_FIXED`),
   интерпретатор и динамические секции не нужны.
   Makefile умеет и «правильный» путь: `make PS5=1` с `PS5_PAYLOAD_SDK` (нужен clang-18).

**Важная находка при порте (не из документации):** `elfldr` **не обнуляет `.bss`** — `data_load()`
делает только `memcpy` `p_filesz` байт в `malloc`-буфер, а не `calloc`
(`elfldr.c:99-110`). Все триггеры поэтому не полагаются на zero-init: массивы/структуры
инициализируются явно (`zero_mem`), RW-сегмент имеет файловый образ там, где это важно.

---

## 2. Карта userland→kernel поверхностей (по нашему дампу 13.60)

735 записей sysent (496 реализовано, 239 — `nosys`), каждая: `narg` + RVA хендлера.
Ниже — поверхности, которые принимают указатели/размеры/индексы и потому интересны для баг-хантинга.

| Поверхность | Syscall'ы (номер:narg) | Что принимает из userland | Кандидаты |
|---|---|---|---|
| **AIO Sony** | `aio_submit` 661:4, `aio_multi_delete` 662:3, `aio_multi_wait` 663:5, `aio_multi_poll` 664:3, `aio_get_data` 665:2, `aio_multi_cancel` 666:3, `aio_create` 668:2, `aio_submit_cmd` 669:5, `aio_init` 670:4 | массивы id, `struct aio_request` (0x28/0x40), буферы состояний | **да**: 662 закрыт в 14.20 (Prolapse), 663 — Relapse, 664/665 — не валидированы (проверяем) |
| AIO POSIX | `aio_read` 255, `aio_write` 256, `aio_suspend` 315, `aio_cancel` 316, `aio_error` 317, `aio_return` 314, `aio_waitcomplete` 359 | sigevent/aiocb | косвенно (общий `aio_aqueue`) |
| **UMTX** | `_umtx_op` 454:5 | obj/op/val/uaddr1/uaddr2 — произвольный userland-указатель + флаги | **да**: SA-24:14 (2024) |
| **IPv6** | `socket` 97, `setsockopt` 105:5, `getsockopt` 118:5, `sendmsg` 28, `recvmsg` 27 | буферы опций, списки source-фильтров | **да**: SA-26:29 (2026), SA-23:06 (DoS) |
| kqueue | `kqueue` 362, `kevent` 363:6 | kevent-массивы | **нет**: CPONFORK-баги 2026 относятся к FreeBSD 15.1, в 11.4 такого режима нет |
| pipe | `pipe`/`pipe2` (compat 42; нативный — через 42/…), `fstat` 189 | fd-таблицы | слабо |
| filedesc/SCM_RIGHTS | `sendmsg` 28, `recvmsg` 27, `open` 5, `dup` 41 | control-сообщения, fd-массивы | только compat32 (SA-20:23) — payload 64-битный, **N/A** |
| netgraph | `socket(AF_NETGRAPH=…)` через 97 + `ioctl` 54 | ioctl-структуры | не проверено (нет в наших данных о гейтинге) |
| Sony-ioctl | `ioctl` 54:3 — /dev/54, gc, dmem, mdbg | произвольные ioctl-структуры | **не тронуто намеренно**: нет описания ABI, слепой фаззинг = паника |
| nmount | 378:7 | iovec-массив | нужен root/гейт; не приоритет |
| ptrace/kld/ktrace | 26, 304-309, 45 | — | на PS5 обычно гейтится; не приоритет |
| jitshm | `jitshm_create` 533, `jitshm_alias` 534 | размеры/prot | не приоритет (используется Relapse как RWX, не баг) |
| pipe/jitshm/proc | `procctl` 689, `mmap` 477, `mprotect` 74 | — | не приоритет |

**Вывод по карте:** у PS5 наибольшая «плотность» свежих баг-фиксов FreeBSD — в **AIO** (Sony-расширения
поверх базовой `vfs_aio.c`), **UMTX** и **IPv6**. Именно они и взяты в топ.

---

## 3. Топ-5 кандидатов под 14.22 (с обоснованием приоритета)

Приоритет = «фикс FreeBSD вышел позже, чем Sony форкнул 11.x, И поверхность достижима из userland,
И статус на 14.00/14.10/14.20 неизвестен/не закрыт».

| # | Кандидат | База | Почему перспективен для 14.22 | Триггер |
|---|---|---|---|---|
| 1 | **UMTX UAF** `UMTX_OP_SHM/UMTX_SHM_DESTROY` (SA-24:14, 2024-09-04) | FreeBSD 11.4 **есть** `UMTX_OP_SHM=25` + флаги CREAT/LOOKUP/DESTROY/ALIVE (`sys/sys/umtx.h:99,111-115`), `kern_umtx.c:3962 __umtx_op_shm → umtx_shm(td, uaddr1, val)` | фикс 2024 г. — заведомо позже форка Sony; конкурентные DESTROY уменьшают refcount лишний раз → объект освобождается раньше времени (UAF/паника) | `t3_umtx_shm.elf` |
| 2 | **IPV6_MSFILTER UAF** (SA-26:29, 2026-06-09) | 11.4 **есть** `IPV6_MSFILTER=74` (`sys/netinet6/in6.h:504`, «struct __msfilterreq; set/get multicast source filter list») | фикс **2026 г.** — новее, чем 13.60 и 14.22; гонка «отпустили lock → copyin списка → взяли lock» против освобождения фильтра | `t4_ip6_msfilter.elf` |
| 3 | **AIO multi-wait UAF** (вектор Relapse, syscall 663) | PS5-специфично (нет в FreeBSD); наш дамп: хендлер RVA `0x3b01f0`, narg=5 | в 14.00 reportedly закрыт (не подтверждено), в 14.10/14.20/14.22 — **неизвестно**; это единственный публично известный рабочий путь kernel R/W | `t1_aio_wait_race.elf` |
| 4 | **AIO multi-delete** (вектор Prolapse, syscall 662) | PS5-специфично; narg=3 | **закрыт в 14.20** (LavX/Coixao), но 14.22 — контрольная точка: триггер покажет, закрыт ли он и там | `t2_aio_del_reuse.elf` |
| 5 | **Sony-AIO аргументная валидация** `664/665/663` | PS5-специфично; narg 3/2/5 | 664/665 — недокументированные соседи двух известных багов, принимают userland-указатели; проверяем, копирует ли ядро с проверкой | `t5_aio_poll_abuse.elf` |

### Отброшено (и почему)

| SA | Тема | Почему **не** кандидат для PS5 14.22 |
|---|---|---|
| SA-26:50.kqueue, SA-26:65.kqueue (2026) | UAF в copy-on-fork kqueue (`KQUEUE_CPONFORK`) | режим введён в FreeBSD 13/14; в 11.4 его **нет** → кода-цели на PS5 нет (`Affects: FreeBSD 15.1`) |
| SA-20:23.sendmsg | priv-esc в compat32 `sendmsg/recvmsg` | только 32-битный ABI; наш payload — 64-битный, нативные sysent 64-bit |
| SA-22:06.ioctl | heap OOB write в ioctl mpr/mps/mpt | это SCSI-драйверы с device-node; на PS5 таких драйверов/узлов нет |
| SA-23:06.ipv6 | integer overflow в IPv6 fragment reassembly | только **remote DoS** (паника), не LPE; как LPE не даёт kernel R/W, а паника — ровно то, чего избегаем |
| SA-22:10.aio | AIO credential reference leak (`aio_aqueue`, `lio_listio`) | утечка cred-refcount требует 2³² инкрементов — на практике недостижимо; нативный `lio_listio` в PS5 sysent отсутствует (есть только `compat6.lio_listio`), а Sony-`aio_submit` может идти через тот же `aio_aqueue` — оставлено как фон, не триггер |

---

## 4. Что именно делает каждый триггер, что «ломает» и как это увидеть

Все логи пишутся в **`/data/kexpl-<имя>.log`** (fallback `/tmp/…`); payload на консоли — root в sandbox,
`/data` доступен на запись (так делает и `relapse-offset-dumper`: `OUT_DIR "/data/relapse_dump"`).
Формат лога: `[tN] …`, в конце `RESULT: …`; код выхода payload — 0 (отрицательно) / 2 (положительно).

### t1 — `t1_aio_wait_race.elf` (syscall 661/663/666)
* **Что делает:** `socketpair(AF_UNIX,SOCK_STREAM)`; через `aio_submit_cmd`(669) отправляет 8
  **блокирующихся** AIO-чтений (структура запроса 0x40: `u32 +0x08 = 1`, `u64 +0x10 = sink`,
  `u32 +0x20 = rfd` — ровно как в Relapse `relapse_exploit.js:293-296`); затем один раз
  `aio_multi_wait`(663) с 16-байтным таймаутом; затем отменяет каждый id `aio_multi_cancel`(666)
  и **сразу пробует отменить его повторно**; 3 итерации.
* **Что «ломает»:** проверяет инвариант id-таблицы AIO — повторная отмена уже отменённого запроса
  не должна приниматься. Принятие = признак незащищённого состояния (двойное освобождение ноды —
  то, что эксплуатирует UAF `aio_multi_wait`).
* **Критерий детекта:** строка `DOUBLE-CANCEL-ACCEPTED id=0x…` и `RESULT: POSITIVE` (exit 2).
  Отсутствие = `RESULT: NEGATIVE` (errno-паттерн в логе).

### t2 — `t2_aio_del_reuse.elf` (syscall 662, вектор Prolapse)
* **Что делает:** 8 блокирующихся AIO-чтений → `aio_multi_delete`(662) по всему массиву **дважды**,
  затем точечно один id — дважды.
* **Что «ломает»:** идемпотентность delete. Второй вызов по тем же id должен вернуть ошибку; если
  возвращает 0 — путь не защищён (двойное удаление = двойное освобождение).
* **Критерий детекта:** `RESULT: POSITIVE` + `single delete rc1=… rc2=0`.
  **Дополнительная ценность:** дифференциальный маркер «закрыт ли 662 на 14.22» — на 13.60/14.10
  ожидается POSITIVE, на 14.20+ ожидается NEGATIVE (по публичным данным Prolapse закрыт в 14.20).

### t3 — `t3_umtx_shm.elf` (syscall 454, **SA-24:14**)
* **Что делает:** `_umtx_op(NULL, UMTX_OP_SHM=25, UMTX_SHM_CREAT=1, &id, NULL)`; `fork()`; **оба**
  процесса 64 раза вызывают `UMTX_SHM_DESTROY=4` по одному и тому же id; 16 раундов.
* **Что «ломает»:** refcount объекта umtx-shm. По SA-24:14 конкурентные DESTROY декрементируют
  счётчик лишний раз → объект освобождается при живых ссылках. На 14.22 ожидается уязвимость,
  если UMTX_OP_SHM вообще поддержан (если нет — триггер честно скажет `RESULT: SKIP`).
* **Критерий детекта:** `REFCOUNT-UNDERFLOW: успешных destroy в одном раунде=N (норма 1)` и
  `RESULT: POSITIVE`; либо паника/UAF в klog (тогда триггер сработал «в минус» — см. оговорку §5).

### t4 — `t4_ip6_msfilter.elf` (setsockopt 105, opt 74, **SA-26:29**)
* **Что делает:** определяет принятую раскладку `struct __msfilterreq` (две гипотезы:
  `group=sockaddr_storage` → len 148, либо `group=sockaddr_in6` → len 48; `srcs` — указатель;
  так же поступает и сам парсер ядра, копируя список из userland), логирует `LAYOUT-ACCEPTED`,
  затем из двух процессов (`fork`, fd унаследован → **один и тот же сокет**) 4000 раз дёргает
  `setsockopt(IPPROTO_IPV6, IPV6_MSFILTER)` с списком source-фильтров.
* **Что «ломает»:** гонку «lock отпущен → copyin → lock взят» против освобождения фильтра
  (SA-26:29 — ровно эта гонка).
* **Критерий детекта:** `LAYOUT-ACCEPTED` (поверхность достижима) + отсутствие паники на 4000
  итерациях. **Честно:** UAF без KASAN/DTRACE наблюдаемым не бывает — успех гонки проявится
  паникой или повреждением; поэтому триггер используется как (а) проверка достижимости опции на
  PS5, (б) нагружатель для последующего прогона с klog-мониторингом.

### t5 — `t5_aio_poll_abuse.elf` (syscalls 663/664/665)
* **Что делает:** поднимает блокирующиеся AIO-запросы, затем подаёт заведомо битые аргументы:
  `aio_multi_poll(ids, n, 0xdead0000)`, `aio_multi_poll(0xdead0000, n, states)`,
  `aio_get_data(0xdeadbeef, sink)`, `aio_get_data(valid_id, 0xdead0000)`,
  `aio_multi_wait(ids, n, 0xdead0000, 0, timeout)`.
* **Что «ломает»:** предполагает отсутствие проверки userland-указателя (ожидается EFAULT/EINVAL).
* **Критерий детекта:** любая строка `VALIDATION-GAP: … rc=0` (или rc, отличный от EFAULT/EINVAL)
  → `RESULT: POSITIVE`. Это самый «дешёвый» способ найти новый баг в недокументированных Sony-вызовах.

---

## 5. Ограничения (что НЕ проверено и почему)

1. **Без консоли нельзя утверждать, что баг есть.** Триггеры — это probes: они показывают
   *наблюдаемое* состояние (errno/счётчики/достижимость), а не доказывают UAF.
2. Некоторые сценарии могут **паниковать консоль** (UAF в t3/t4 при удачной гонке) — это ожидаемый
   исход для исследования, но требует перезагрузки; на общей консоли запускать только осознанно.
3. **Нет kernel-дампа 14.22** → нельзя сравнить хендлеры 662/663/664 с 13.60 по коду; сравнение
   возможно только косвенно (по поведению триггеров). Как появится дамп — `tools/payload/scan_1322.py`
   + дизасм хендлеров (`0x3b01f0` для 663 на 13.60) закроют это.
4. **SDK-сборка не проверена** (нет clang-18/lld-18 и прав на установку); freestanding-вариант
   эквивалентен по формату ELF (ELF64 ET_EXEC, elfldr поддерживает), но не линкуется с libkernel.
5. **Sony-ioctl (`/dev/54`, gc, dmem, mdbg) намеренно не фаззились** — нет описания ABI, слепой
   фаззинг почти гарантированно даёт панику без полезного результата.

---

## 6. Источники и проверки

| Утверждение | Источник | Как проверено |
|---|---|---|
| 735 sysent, 496 реализовано, 239 nosys, stride 48 | `fw/sysent-13.60.json` (`sysent_native`) | python-разбор JSON |
| Имена и narg 661-670, 454, 105, 97… | `fw/sysent-13.60.json` + `recon/_src/t14/sysent-names-13.60-native.csv` | join по номеру, вывод narg |
| ABI Sony-AIO (`aio_submit_cmd` 669: cmd,req,count,3,idout; `aio_multi_wait` 663: ids,count,states,mode,timeout) | `recon/_src/relapse/m2k7m_Relapse-Exploit/src/utils/syscalls.js:475-484`, `src/relapse_exploit.js:292-300,404-430` | чтение исходников |
| `UMTX_OP_SHM=25`, флаги 1/2/4/8 | FreeBSD `releng/11.4/sys/sys/umtx.h:99,111-115` | скачано, grep |
| `__umtx_op_shm(td, uap->uaddr1, uap->val)` | FreeBSD `releng/11.4/sys/kern/kern_umtx.c:3962-3966` | скачано, чтение |
| `IPV6_MSFILTER=74`, `struct __msfilterreq` | FreeBSD `releng/11.4/sys/netinet6/in6.h:504-506` | скачано, grep |
| SA-24:14.umtx — «umtx Kernel panic or Use-After-Free», concurrent `UMTX_SHM_DESTROY` | https://www.freebsd.org/security/advisories/FreeBSD-SA-24:14.umtx.asc | HTTP 200, текст прочитан |
| SA-26:29.ip6_multicast — UAF в `IPV6_MSFILTER`, lock-drop + copyin | https://www.freebsd.org/security/advisories/FreeBSD-SA-26:29.ip6_multicast.asc | HTTP 200, текст прочитан |
| SA-22:10.aio — cred refcount leak в `aio_aqueue` (`lio_listio`) | https://www.freebsd.org/security/advisories/FreeBSD-SA-22:10.aio.asc | HTTP 200 |
| SA-26:50/26:65.kqueue — CPONFORK, `Affects: FreeBSD 15.1` | https://www.freebsd.org/security/advisories/FreeBSD-SA-26:65.kqueue.asc | HTTP 200; в 11.4 режима нет |
| SA-20:23.sendmsg — compat32 | https://www.freebsd.org/security/advisories/FreeBSD-SA-20:23.sendmsg.asc | HTTP 200 |
| SA-22:06.ioctl — mpr/mps/mpt | https://www.freebsd.org/security/advisories/FreeBSD-SA-22:06.ioctl.asc | HTTP 200 |
| SA-23:06.ipv6 — remote DoS, integer overflow | https://www.freebsd.org/security/advisories/FreeBSD-SA-23:06.ipv6.asc | HTTP 200 |
| elfldr грузит ET_EXEC (MAP_FIXED по min_vaddr) | `tools/fwsim/vendor/elfldr/elfldr.c:172-178` | чтение кода |
| elfldr **не** обнуляет .bss (только memcpy p_filesz) | `tools/fwsim/vendor/elfldr/elfldr.c:99-110` | чтение кода |
| 662 закрыт в 14.20 | LavX, 2026-10-25 (`recon/_src/t14/lavx-prolapse-2026-10-25.txt`) | текст: «Prolapse works on 14.00/14.10 … Sony patched it in the 14.20 update» |

---

## 7. Сборка и запуск

```bash
# сборка (freestanding, gcc — как собрано здесь)
cd ps5jb/tools/kexpl && make clean && make all && make verify

# «правильная» сборка через SDK (если есть clang-18/lld-18)
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
make clean && make PS5=1

# запуск на джейлбрейкнутой консоли (elfldr на 9021)
nc <PS5_IP> 9021 < t3_umtx_shm.elf
# забрать лог:
#   ftpsrv (порт 1337) -> /data/kexpl-t3-umtx-shm.log
#   либо shsrv (telnet 2323) -> cat /data/kexpl-t3-umtx-shm.log
```

**Порядок прогона на 14.22 (рекомендация):** `t5` (самый безопасный) → `t2` (дифференциал по delete) →
`t1` (wait) → `t3` (umtx) → `t4` (ip6; самый рискованный для стабильности).

---

## 8. Артефакты

| Файл | Что |
|---|---|
| `tools/kexpl/kexpl.h` | freestanding-окружение: raw syscall-обёртки (r10/r8 для 4-5 аргументов, CF=errno), лог в `/data`, nanosleep, `_start` |
| `tools/kexpl/t1_aio_wait_race.c` … `t5_aio_poll_abuse.c` | 5 триггеров |
| `tools/kexpl/Makefile` | сборка gcc (по умолчанию) и `PS5=1` через SDK; цель `verify` |
| `tools/kexpl/*.elf` | собранные payload'ы (ELF64 EXEC, entry=`_start`, 3 LOAD, нет INTERP/динамики) |
| `tools/kexpl/relapse1422.js` | **не мой файл** (от параллельной задачи), не трогал |

Собранные ELF (sha256):

```
9a618b694f08a812c60eca3c50b793539939a6506c0282fc0aaa2b92ce4d4a38  t1_aio_wait_race.elf   10000 B
f37c7dd5f17b872cf959a92d0754f444c3a1f52d01757ee3e5c6911b9fb87d49  t2_aio_del_reuse.elf    9832 B
5de9374ddf3634e7f23aab5b383fc77640a664fca8ac74d28b785cbf7bc38c38  t3_umtx_shm.elf         9832 B
5f39baf63f8ca4f99e105bce714bcd7a226e06a2e370796730c73a76db9de25b  t4_ip6_msfilter.elf     9840 B
c1003b6e266f7753884b839ac8e417a40975b34eb3bdf817c52bffee93dd2095  t5_aio_poll_abuse.elf  14304 B
```

Проверка формата (`LC_ALL=C readelf`): `Class: ELF64`, `Type: EXEC`, `Machine: X86-64`, entry = `_start`,
3 × `LOAD`, `There is no dynamic section in this file`, `INTERP` отсутствует, undefined-символов нет.

---

## 9. Итог

1. Карта поверхностей построена из нашего дампа: 735 sysent, из них 496 реализовано; выделены AIO-семейство
   Sony (661-670), UMTX (454), IPv6 (105/97/27/28), kqueue/pipe/filedesc/netgraph/ioctl.
2. Сверка с FreeBSD 11.4 + 737 SA дала **5 обоснованных кандидатов** и **6 обоснованных отказов**
   (kqueue-CPONFORK, compat32-sendmsg, mpr/mps ioctl, remote-DoS ipv6, cred-leak aio — не тот код/эффект).
3. Приоритет для 14.22: **UMTX UAF (SA-24:14)** и **IPV6_MSFILTER UAF (SA-26:29)** — их фиксы новее, чем
   форк Sony; далее AIO wait (663) / delete (662) как дифференциальные маркеры, и валидация 664/665.
4. Все 5 триггеров написаны на C, **собраны в валидные ELF** и снабжены критериями детекта;
   запуск — elfldr на 9021, лог — `/data/kexpl-*.log`.
5. Проверка на 14.22 требует консоли; на 13.60 те же триггеры дают точку сравнения (и `t2` должен
   показать POSITIVE, подтверждая, что методика ловит закрытый в 14.20 баг).