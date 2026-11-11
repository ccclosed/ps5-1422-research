# 14.22: какие kernel-поверхности открыты и жив ли AIO-вектор

**Агент:** recon-kernel-dumps · **Задача:** task-14 · **Дата:** 2026-11-11
**Машина:** Linux, root НЕТ, сеть через `socks5h://127.0.0.1:10810`; `gh api` — авторизован.
**Правило:** каждое утверждение — с источником/командой; непроверенное помечено. Образ 14.22 публично **отсутствует** —
поэтому всё, что касается «что Sony изменила в 14.22», может быть только заявлением третьей стороны, не доказательством.
Сырьё сохранено в `recon/_src/t14/`.

## 0. TL;DR (для лида)

1. **«aio_multi_delete Blocked» из cyber-forge — не результат анализа, а строчка в статической маркетинговой матрице.**
   Это литерал `kernel: "aio_multi_delete Blocked"` в массиве `HARDWARE_MATRIX.ps5.firmwares` (`app.js`, карточка FW
   `14.00 - 14.22`, стр. **271–281**, `status: "PATCHED"`, `rate: "0% (Stay Offline)"`). Никакой код эти статусы не вычисляет
   (динамика в `app.js` есть только для GitHub-releases и «radar», не для статусов FW). Ссылка в карточке — на
   `Khal0da/PS5-14.20-WebKit-Research`, в котором **нет ни одного упоминания AIO** (`search/code` по репо = 0; в его docs
   слово «aio» отсутствует; слово «BLOCKED» у него означает «эксплуатация заблокирована secondary defense в WebKit»).
2. **Что стоит за фразой на самом деле:** публичный пресс-источник — LavX News (25.10.2026): «Prolapse functions on firmware
   14.00 and 14.10, though Sony patched it in the 14.20 update… targets a memory management flaw in the `aio_multi_delete`
   function… Coixao confirmed the update closed the vulnerability». Т.е. факт = **Sony закрыла конкретный баг Prolapse
   (TOCTOU/double-free в `aio_multi_delete`) в 14.20**, а не «вырезала AIO» и не «заблокировала syscall».
3. **Про «generation-id»:** механизм заявлен только автором Prolapse-кода (gist zecoxao, created 2026-10-26:
   «patched in 14.20 by the `*state != saved_generation_id` recheck») и его репликой (kuzibelit, 2026-10-27).
   Оба ссылаются на IDA-анализ **`kernel_1410.elf` (это образ 14.10, не 14.20)** → механизм не доказан.
   Сами авторы 14.10-исследования (ZigZag) в своём аудите пишут: «**HALF CONFIRMED** … The "generation-ID revalidation"
   mechanism is **our inference** … **not sourced** from any external document». Цепочка цитирования замыкается.
4. **Наш дамп 13.60 это подтверждает независимо:** проверка generation-id в lookup'е **уже существует** в 13.60
   (функция `0x39a2a0`: `and 0x1fff`, `mov 0x28(r13,rcx)`, `shl 0xd`, `cmp`), поэтому «14.20 добавила generation-id check»
   в таком виде — сомнительно; если патч есть, он в *пост-lock-drop revalidation* внутри delete-пути (см. §5.4), а это без
   образа 14.20/14.22 проверить нельзя.
5. **AIO-векторов два, это разные баги:** `aio_multi_delete` (662, Prolapse) и `aio_multi_wait` (663, Relapse).
   Публичная цепочка Relapse заканчивается на **13.60** (README ntfargo/Relapse-Exploit). Статус wait-вектора на 14.20/14.22
   **не доказан ни в одну сторону**; утверждение «14.00 закрыла wait-vs-submit race» в 14.10-репо помечено как unsourced.
6. **Публичных kernel R/W на 14.1x–14.2x нет** (три независимых авторских репозитория прямо это отрицают; см. teammate
   `recon/1422-status.md`). Официальные примечания 14.22 — «security fixes» без конкретики.
7. **Альтернативные поверхности** (таблица §7): UMTX (`_umtx_op`=454), kqueue/kevent (141/362/363), IPv6-UAF (netinet6),
   Sony-ioctl (`ioctl`=54; `gc_ioctl`, `dmem`, `mdbg`=601, `ampr`=721, `test_debug_rwmem`=619), AIO-debug (726/727),
   SCSI/CAM (`xpt_*` присутствует), pipe/filedesc, sysctl, jitshm (533/534), nmount (378), ptrace (26), kld* (304–308, 337).
   Все они **есть в 13.60** (доказательства — строки/номера syscall'ов из дампа), но **статус на 14.22 неизвестен**:
   без образа 14.22/консоли его не доказать.
8. **Ответ по существу:** «AIO-вектор» (delete) на 14.22 вероятнее всего мёртв (press + заявление автора), «AIO-wait» —
   под вопросом; список «открытых поверхностей 14.22» доказательно составить нельзя — только список кандидатов и чек-лист
   проверки, когда появится образ (см. §6–§8). Без образа/консоли любые «открыто/закрыто» — домысел.

## 1. Задание и метод

Задача (task-14): 1) проверить по первоисточникам заявление cyber-forge, что на 14.20+ «aio_multi_delete Blocked»;
2) по дампу 13.60 найти код AIO (`aio_multi_wait`/`aio_multi_delete`/`aio_submit_cmd`), оценить, что патчила Sony и какие
признаки патча искать в 14.22; 3) дать список альтернативных userland→kernel поверхностей FreeBSD 11 с оценкой
применимости к 14.22 и способом проверки без консоли.

Метод: GitHub REST (`gh api`), `curl` через DPI-обход для прессы, статический анализ дампа
`fw/ps5-kernel-13.60-live.bin` (sha256 `c3f745e2…d78cddd`, из task-2), `objdump -D -b binary -m i386:x86-64`,
скрипты извлечения sysent (`tools/sysent/scanner.py`, `fw/sysent-13.60.json`). Локальные копии источников — `recon/_src/t14/`.

## 2. Утверждение cyber-forge: что там на самом деле (факт vs пересказ)

### 2.1 Точный фрагмент

`oscarlaradev/cyber-forge-ps5-ps4-exploit-host`, `app.js` (66 503 B), массив `HARDWARE_MATRIX.ps5.firmwares` (объявлен на
строке 219), последняя карточка (строки 272–281; поле `kernel` — стр. 277; в `recon/_src/t14/cyberforge-app.js.lines265-290.txt`):

```js
      {
        fw: "14.00 - 14.22",
        codename: "PROLAPSE / 14.20 RESEARCH",
        status: "PATCHED",
        entry: "WebKit Probe (Khal0da)",
        kernel: "aio_multi_delete Blocked",
        repo: "Khal0da/PS5-14.20-WebKit-Research",
        repoUrl: "https://github.com/Khal0da/PS5-14.20-WebKit-Research",
        rate: "0% (Stay Offline)"
      }
```

Это **статический литерал** в UI-матрице; поле `kernel` — просто строка для отображения.

### 2.2 Почему это нельзя считать анализом

- В `app.js` нет кода, который проверяет AIO/syscall'ы: `grep -n -i 'aio|blocked|14.20'` даёт только строки карточек
  (247, 257, 273–279), текст `etaHEN v2.5B AIO Enabler` (286 — другое значение слова AIO), описание Relapse (449)
  и Notice (1040–1049: «Sony sealed kernel R/W on 14.20/14.22» — тоже литерал).
- Динамические запросы в файле только: GitHub releases для payload'ов (`fetch(api.github.com/repos/.../releases/latest)`,
  стр. 827) и «radar» (`fetch` поиска, стр. 863+). Статусы прошивок не обновляются ниоткуда.
- Карточка ссылается на `Khal0da/PS5-14.20-WebKit-Research`. Проверено: `search/code?q=aio_multi_delete+repo:Khal0da/...` → **0**;
  в его документах (`docs/DEAD_ENDS.md`, `docs/CONFIRMED_VULNS.md`, `CHANGELOG.md`) слова aio/AIO нет. Его «BLOCKED»
  относится к WebKit-багам и означает: «All require code execution outside browser sandbox. Unreachable from JavaScript»
  (DEAD_ENDS.md, раздел «Kernel Probes — BLOCKED»). Т.е. репозиторий-«источник» не подтверждает фразу.
- Репозиторий cyber-forge: 0★, push 2026-11-07; это «exploit host» (статический сайт-каталог), не исследовательский репозиторий.
- Пресса того же периода: NotebookCheck (21.10.2026, Adam Corsetti) — «It's unclear whether the new 14.20 firmware update
  addresses any security flaws. The notes only mention improving “messages and usability on some screens.”» — т.е. на
  момент выхода 14.20 подтверждения AIO-патча не было.
- LavX News (25.10.2026, Lukas Brandt) — уже прямо: «A new PS5 kernel exploit dubbed Prolapse functions on firmware 14.00
  and 14.10, though Sony patched it in the 14.20 update… The exploit targets a memory management flaw in the
  **aio_multi_delete** function… Coixao confirmed the update closed the vulnerability Prolapse uses.»

**Вывод §2:** «aio_multi_delete Blocked» = короткое переложение «баг Prolapse (TOCTOU в `aio_multi_delete`) исправлен в
14.20». Это **не** «AIO вырезан», **не** «syscall заблокирован» и **не** доказательство механизма патча.
Сам факт «14.20 закрыла этот баг» имеет источник (заявление Coixao → LavX); конкретика «generation-id» — нет (§3).

## 3. Цепочка происхождения «generation-id»-версии (кто что заявил)

| # | Источник | Дата | Что утверждает | Статус |
|---|---|---|---|---|
| 1 | LavX News, статья о Prolapse | 2026-10-25 | Prolapse работает на 14.00/14.10; баг — «memory management flaw in `aio_multi_delete`»; Coixao подтвердил, что 14.20 закрыла его | `ПОДТВЕРЖДЕНО` как пресс-сообщение; механизм не назван |
| 2 | gist `zecoxao/80dff057…` («current (non working) prolapse code», 25 024 B) | created 2026-10-26 (updated 2026-11-02) | «patched in 14.20 by the `*state != saved_generation_id` recheck, so the recycled-slot step (stage 3/4) is exactly what dies on >=14.20»; «VERIFIED in IDA (**kernel_1410.elf**)» | `ЗАЯВЛЕНО АВТОРОМ`; верификация — по образу **14.10**, не 14.20 |
| 3 | `kuzibelit/PS5-14.00-14.10-Jailbreak-PoC` (50★, push 2026-10-27) — «compiling publicly available … research» | 2026-10-27 | Почти дословно копия шапки gist: «Patched in 14.20 via strict generation-id validation checks (`*state != saved_generation_id`)… Verified via static analysis in IDA Pro (`kernel_1410.elf`)» | `ЗАЯВЛЕНО АВТОРОМ`; **не независимый** источник (копия) |
| 4 | ZigZagBoi1/PS5-14.10-Research: `docs/AIO_OBJECT_FORENSICS.md`, `docs/AIO_RANGE_14_10_EVIDENCE.md` | 2026-10-24/25 | Пересказывают «14.20 fix note» как «post-lock-drop generation revalidation», но в своих пробах показывают: generation-сравнение **уже есть** в обоих lookup'ах 13.60/14.10; окно — «десять инструкций», 900 попыток гонки — без попадания | `ЧАСТИЧНО`: TOCTOU-код подтверждён, механизм патча — не доказан |
| 5 | ZigZag `docs/2026-10-25/VERIFICATION_LAPSE_CLAIMS.md` | 2026-10-25 | Про механизм: «**HALF CONFIRMED**. The 14.20 fix is confirmed. The “generation-ID revalidation” mechanism is **our inference** … **not sourced from any external document**» | Аудит самих авторов — механизм = догадка |
| 6 | cyber-forge `app.js` | repo push 2026-11-07 | `kernel: "aio_multi_delete Blocked"`, `status: "PATCHED"` | `ПЕРЕСКАЗ` (без ссылки на первоисточник; цитируемый репо не содержит темы) |

**Как читать:** факт «14.20 закрыла баг Prolapse» — подтверждается (Coixao → LavX). Фраза «generation-id revalidation» —
авторская версия механизма, которую сам 14.10-репозиторий называет inference; проверялась она на 14.10-образе
(`kernel_1410.elf`), где 14.20-патча быть не может. Итог: **факт = патч есть; механизм = НЕ ПОДТВЕРЖДЁН**.

## 4. Что реально известно про AIO на 14.22 (сводка)

| Утверждение | Источник | Статус |
|---|---|---|
| Relapse: WebKit + `aio_multi_wait` UAF, поддерживает 7.00–13.60 | `ntfargo/Relapse-Exploit/README.md` (2713★, push 2026-09-30): «Supported firmware: 7.00 through 13.60… kernel stage combines … a `aio_multi_wait` uaf race» | `ПОДТВЕРЖДЕНО` (README) |
| Prolapse: работает на 14.00/14.10, баг в `aio_multi_delete` | LavX 2026-10-25 | `ПОДТВЕРЖДЕНО` (пресс, со ссылкой на Coixao) |
| 14.20 закрыла баг Prolapse | LavX 2026-10-25 + Coixao | `ПОДТВЕРЖДЕНО` (пресс/заявление автора); официальные патчноуты 14.20 безопасности не упоминают |
| Механизм патча = generation-id revalidation / `*state != saved_generation_id` | gist 2026-10-26, kuzibelit 2026-10-27; ZigZag: inference | `НЕ ПОДТВЕРЖДЕНО` (нет анализа 14.20/14.22-образа) |
| В 13.60/14.10 generation-проверка в lookup **уже есть** | наш дамп §5.3; ZigZag AIO_RANGE (10.10/13.60 decode) | `ПОДТВЕРЖДЕНО` (два независимых источника) |
| «14.00 reportedly closed the wait-vs-submit race» | ZigZag `AIO_OBJECT_FORENSICS.md` §6 («reportedly»); их же аудит: «Relapse “663 race” claim unsourced» | `НЕ ПОДТВЕРЖДЕНО` |
| Публичного образа 14.22 (ELF/дамп) нет | task-2 (`recon/kernel-dumps.md` §6, §13) | `ПОДТВЕРЖДЕНО` (перечень проверенного с кодами) |
| Kernel R/W на 14.1x–14.2x никем не продемонстрирован | S1/S2/S3/S4 (см. `recon/1422-status.md` §3.3–4.5) | `ПОДТВЕРЖДЕНО` (несколько независимых авторов) |
| Официальные примечания 14.22: «We've made some security fixes to the system software» (без конкретики) | GBAtemp 2026-11-03 (цитата Sony), IGN 2026-11-02 (26.07-14.22.00, ≈1.267 ГБ) | `ПОДТВЕРЖДЕНО` (по `recon/1422-status.md` S9/S10) |

## 5. Дамп 13.60: анатомия AIO (наш вклад, проверено на бинарнике)

Все адреса ниже — **RVA от text-base** (`0xffffffff9e3f0000`), потому что дамп flat: `file_offset == RVA` для
`0x0..0xCC0000` (text) и `file_offset = 0xCC0000 + (VA − 0xffffffff9f0b0000)` (data).

### 5.1 Сисколлы и реальные хендлеры (через jump-стабы sysent)

В таблице sysent записи 661–670 указывают не на тела функций, а на 8-байтные стабы (`e9 rel32 cc cc cc`, таблица
стабов ~`0x265xxx`); после декодирования `jmp` получаем настоящие хендлеры (наш скрипт по `fw/sysent-13.60.json`):

| Syscall | Имя (CSV ZigZag) | Стаб RVA (sys_call) | Хендлер RVA | narg |
|---:|---|---:|---:|---:|
| 661 | `aio_submit` | `0x265710` | **0x3af8f0** | 4 |
| 662 | `aio_multi_delete` | `0x265718` | **0x3af900** | 3 |
| 663 | `aio_multi_wait` | `0x265720` | **0x3b01f0** | 5 |
| 664 | `aio_multi_poll` | `0x265728` | **0x3b0fb0** | 3 |
| 665 | `aio_get_data` | `0x265730` | **0x3b1670** | 2 |
| 666 | `aio_multi_cancel` | `0x265738` | **0x3b1680** | 2 |
| 668 | `aio_create` | `0x265708` | **0x3af8e0** | 4 |
| 669 | `aio_submit_cmd` | `0x265740` | **0x3b2060** | 5 |
| 670 | `aio_init` | `0x265748` | **0x3b28d0** | 4 |

Проверка: имена/номера взяты из CSV ZigZag (`docs/sysent-names-13.60.csv`, `docs/sysent-compat-names-13.60.csv`), и эти CSV
**полностью сошлись с нашей таблицей sysent из дампа**: `handler_rva` совпадает для всех **677/677** compat-строк и
**735/735** native-строк (0 расхождений) → маппинг имён надёжен, AIO — это именно 661–670.

> ⚠️ **Ловушка в исходниках ZigZag (важно для команды):** файлы `docs/rea_13.60/aio_*_63x.txt` (aio_submit_631,
> aio_multi_delete_632, aio_multi_wait_633, aio_submit_cmd_639…) названы неверно — по CSV 631–640 это
> `resume_internal_hdd` (631), `thr_suspend_ucontext` (632), `thr_resume_ucontext` (633), `thr_get_ucontext` (634),
> `thr_set_ucontext` (635), `set_timezone_info` (636), `set_phys_fmem_limit` (637), `utc_to_localtime` (638),
> `localtime_to_utc` (639), `set_uevt` (640) — **не AIO**. Их адреса (`0x9e828e30` = RVA 0x438e30 и т.п.) — это хендлеры
> ucontext/time, а не AIO. Для AIO использовать 661–670 и RVA из таблицы выше.

### 5.2 Lookup с generation-id: проверка **уже есть в 13.60** (функция `0x39a2a0`)

`objdump -D -b binary -m i386:x86-64 --start-address=0x39a2a0 --stop-address=0x39a3c0 fw/ps5-kernel-13.60-live.bin`:

```
39a2b4: 81 fe ff ff 00 00     cmp    $0xffff,%esi            ; id <= 0xffff
39a2d8: 81 e3 ff 1f 00 00     and    $0x1fff,%ebx            ; slot = id & 0x1fff
39a30d: c1 e8 07              shr    $0x7,%eax              ; page = slot >> 7
39a363: 48 8b 45 b0           mov    -0x50(%rbp),%rax
39a367: 4d 8b 2c c4           mov    (%r12,%rax,8),%r13     ; page table entry
39a36b: 41 8b 44 0d 28        mov    0x28(%r13,%rcx,1),%eax ; slot's generation
39a370: c1 e0 0d              shl    $0xd,%eax              ; gen << 13
39a373: 0f b7 c0              movzwl %ax,%eax
39a376: 09 d8                 or     %ebx,%eax              ; reconstructed id = slot | gen<<13
39a378: 44 39 f0              cmp    %r14d,%eax             ; == requested id?
39a37b: 0f 85 92 00 00 00     jne    0x39a413               ; not found
39a381: 49 01 cd              add    %rcx,%r13
39a384: 66 41 83 7d 26 03     cmpw   $0x3,0x26(%r13)        ; state == 3 (completed)
39a38a: 0f 85 83 00 00 00     jne    0x39a413
39a390: 41 0f b7 45 20        movzwl 0x20(%r13),%eax        ; expected count
39a395: 39 45 c8              cmp    %eax,-0x38(%rbp)
39a398: 75 79                 jne    0x39a413
```

Это **побайтово совпадает** с независимым дизасмом ZigZag по 13.60 (`AIO_RANGE_14_10_EVIDENCE.md`, «The re-lookup compares
slot and generation»): `0xa2b4 cmp esi,0xffff`, `0xa2d8 and ebx,0x1fff`, `0xa36b`, `0xa370`, `0xa378`, `0xa384`, `0xa395`.
**Следствие:** «14.20 добавила generation-id check» в формулировке gist — неверно/неточно: generation-проверка есть
в lookup'е 13.60 и 14.10. Если Sony что-то добавляла в 14.20, это должна быть *дополнительная* revalidation
после разлока (см. §5.4), которую надо искать отдельно.

### 5.3 `aio_multi_delete` (662, хендлер `0x3af900`): путь TOCTOU

Ключевые точки (дизасм нашего дампа):

```
3af9c6: 83 be a0 04 00 00 01  cmpl   $0x1,0x4a0(%rsi)      ; process-mode gate (до count)
3af9fb: 41 8d 87 7f ff ff ff  lea    -0x81(%r15),%eax
3afa02: 3d 7f ff ff ff        cmp    $0xffffff7f,%eax
3afa07: 77 2a                 ja     ...                    ; count 1..0x80
...
3afc2a: e8 81 a2 fe ff        call   0x399eb0               ; (un)lock D / таблицы
3afc3f: e8 9c a2 fe ff        call   0x399ee0               ; lock D (read)
3afd14: 4c 8b 34 c8           mov    (%rax,%rcx,8),%r14     ; W = D.table[index]
...
3afda1: e8 ca 19 84 00        call   0xbf1770               ; Q lock (op 0x80000)
3afdaa: 41 80 7e 0c 00        cmpb   $0x0,0xc(%r14)         ; W/Q completion flag?
3afddc: 49 83 7e 50 00        cmpq   $0x0,0x50(%r14)        ; waiter head
3afe29: e8 42 19 84 00        call   0xbf1770               ; Q unlock (0x100000)
3afe32: 43 83 3c ae 00        cmpl   $0x0,(%r14,%r13,4)     ; per-id status array
3afe4f: 83 79 04 00           cmpl   $0x0,0x4(%rcx)         ; W+4 gate
3afe53: 0f 85 42 fd ff ff     jne    0x3afb9b               ;   -> next id (без unlock)
3afe59: 80 79 0c 00           cmpb   $0x0,0xc(%rcx)         ; W+0xc gate
3afe5d: 0f 84 38 fd ff ff     je     0x3afb9b               ;   -> next id (без unlock)
3afe63: 48 8b 7b 78           mov    0x78(%rbx),%rdi
3afe67: e8 44 a0 fe ff        call   0x399eb0               ; UNLOCK (окно открывается)
3afe7c: e8 1f a4 fe ff        call   0x39a2a0               ; lockless re-lookup (§5.2!)
3afe84: 0f 84 21 01 00 00     je     0x3affab               ; not found -> status 0, без free
...
3afea3: 66 41 83 f8 01        cmp    $0x1,%r8w              ; mode gate
```

Смысл: между unlock (`0x3afe67`) и re-lookup (`0x3afe7c`) — **несколько инструкций** (у ZigZag: «десять инструкций»);
сам re-lookup снова проверяет generation (§5.2). Поэтому «окно» крайне узкое, а «переиспользованный слот со старым id»
re-lookup отсекает. Именно это окно (по версии «14.20 fix note») закрывают дополнительной revalidation.

### 5.4 `aio_multi_wait` (663, хендлер `0x3b01f0`): массив waiter'ов — цель Relapse

Дизасм тела (`0x3b0384`+):

```
3b0384: 48 8b 4b 70           mov    0x70(%rbx),%rcx        ; count (аргумент syscall)
3b0388: 8d 81 7f ff ff ff     lea    -0x81(%rcx),%eax
3b038e: 3d 7f ff ff ff        cmp    $0xffffff7f,%eax
3b0393: 77 23                 ja     ...                    ; 1 <= count <= 0x80
3b03b8: 41 83 fd 03           cmp    $0x3,%r13d             ; mode < 3
3b03be: 89 c8                 mov    %ecx,%eax
3b03cb: 48 89 43 20           mov    %rax,0x20(%rbx)        ; сохранить count
3b03d4: 8d 04 8d 0f 00 00 00  lea    0xf(,%rcx,4),%eax      ; alloca count*4 (+align)
3b0403: e8 e8 8b ea ff        call   0x258ff0               ; bzero alloca
3b0468: e8 13 8e ea ff        call   0x259280               ; copyin(count*4) — id[] (ещё copyin на 0x3b04f3)
3b0524: 4c 8b 73 20           mov    0x20(%rbx),%r14        ; count
3b0528: 48 8d 35 d1 d2 6c 01  lea    0x1a7d800(%rip),%rsi   ; zone diagnostic array
3b0534: 4a 8d 04 f5 ...        lea    0(,%r14,8),%rax
3b053c: 48 8d 3c 40           lea    (%rax,%rax,2),%rdi     ; count*0x18
3b0540: e8 0b 86 85 00        call   0xc08b50               ; alloc count*0x18
...
3b0576: 49 6b fe 38           imul   $0x38,%r14,%rdi        ; count*0x38
3b057a: 48 8d 35 cf 54 70 01  lea    0x1ab5a50(%rip),%rsi   ; zone waiter-array
3b0581: ba 02 01 00 00        mov    $0x102,%edx            ; M_WAITOK|M_ZERO
3b0586: e8 c5 85 85 00        call   0xc08b50               ; alloc count*0x38 = waiter array
...
3b0783: e8 e8 0f 84 00        call   0xbf1770               ; Q lock
3b0a18: e8 53 0d 84 00        call   0xbf1770
3b0a87: e8 64 83 85 00        call   0xc08df0               ; free ...
3b0dc6: e8 a5 09 84 00        call   0xbf1770
3b0e10: e8 5b 09 84 00        call   0xbf1770
```

**Это и есть UAF-цель Relapse:** `aio.waiterSize: 0x38` из `offsets/13.60.js` (см. `recon/relapse-anatomy.md` §3.1) —
ровно размер элемента массива `count*0x38`, который выделяется здесь и освобождается в этом же хендлере (0x3b0a87).
Relapse гоняет `aio_multi_wait` против `aio_multi_cancel`/churn + спрея `aio_submit_cmd`, освобождая waiter-ноды,
пока `aio_multi_wait` их держит.

### 5.5 Почему delete-путь «достижим» на каждом успешном delete (важно для патча)

`aio_multi_poll` (664) ставит `W+0xc = 1`:

```
3b1553: c6 41 0c 01           movb   $0x1,0xc(%rcx)         ; W+0xc = 1 (после poll)
```

`aio_submit_cmd` (669) создаёт W (0x58 B) из зоны `0x1ab5900` и пишет только 4 поля:

```
3b2530: bf 58 00 00 00        mov    $0x58,%edi
3b2535: 48 8d 35 c4 33 70 01  lea    0x1ab5900(%rip),%rsi   ; zone W
3b253c: ba 02 01 00 00        mov    $0x102,%edx
3b2541: e8 0a 66 85 00        call   0xc08b50               ; alloc(0x58)
3b2552: 89 08                 mov    %ecx,(%rax)            ; W+0x00 = id
3b2554: 4c 89 60 10           mov    %r12,0x10(%rax)        ; W+0x10 = descriptor D
3b2558: 48 89 70 18           mov    %rsi,0x18(%rax)        ; W+0x18 = context C
3b255c: 4c 89 74 20 20        mov    %r14,0x20(%rax)        ; W+0x20 = work object S
```

Т.е. `W+4` и `W+0xc` создание не пишет; `W+0xc` появляется только после poll → для любого удаляемого объекта
(delete требует state 3/4) `W+4==0`, `W+0xc==1`, и delete **всегда** проходит через unlock+re-lookup путь.
Это совпадает с разбором ZigZag (`AIO_RANGE…`: «every delete that succeeds at all runs the unlock/re-lookup path»)
и наш дамп подтверждает и запись `W+0xc` (v poll), и создание W.

## 6. Что должна была патчить Sony и как искать патч в 14.22

Без образа 14.22 можно только перечислить **кандидатов** (все — из анализа кода 13.60/14.10, не из 14.22):

| Гипотеза | Как выглядела бы в коде | Вероятность |
|---|---|---|
| A. Пост-lock-drop revalidation (заявлено автором Prolapse: `*state != saved_generation_id`) | после `call 0x399eb0` (unlock) и/или после re-lookup — новая загрузка `[slot+0x28]`/сохранённого gen и `cmp`/`jne` на error-path; либо повторный lookup с возвратом EAGAIN при несовпадении | Высокая (единственная конкретная версия; но не доказана) |
| B. Изменение блокировок/порядка | re-lookup и фризы идут под удержанным bucket-lock (в 13.60 unlock делает окно; патч может убрать unlock или взять exclusive lock раньше) | Средняя |
| C. Refcount/state-гейт на объект до free | доп. проверки `count`/state перед `entry_dispose`; новые lock/unlock вокруг Q/C | Средняя |
| D. Гейт на syscall/аргументы | 662 перестаёт принимать комбинации (или стаб ведёт на error-путь) | Маловероятно (press говорит про «memory management flaw», а не про вырезание API) |

**Чек-лист проверки, когда появится образ 14.22** (идеально — 14.20 или 14.22 decrypted image; публично их нет):

1. Достать sysent: `python3 tools/sysent/scanner.py <image> --base <text_base> --json scan.json` (для ELF base из PT_LOAD;
   для live dump — из манифеста payload'а). Валидация: compat 677 / native 735 записей, stride 48 (как в `fw/sysent-13.60.json`).
2. Decode стабы 661–670 → хендлеры (`e9 rel32`): в 13.60 delete=0x3af900, wait=0x3b01f0, poll=0x3b0fb0, submit_cmd=0x3b2060.
3. В delete: найти сигнатуры тела — гейт `cmpl $0x1,0x4a0(%rsi)`, `lea -0x81 / cmp 0xffffff7f`, пару вызовов lock'ов
   (`0x399eb0`/`0x399ee0` в 13.60) и re-lookup (`0x39a2a0` в 13.60). **Признак патча A:** между unlock и re-lookup
   появились инструкции, либо после re-lookup добавлена генерационная сверка/`jne` на error, либо re-lookup заменён на
   проверку сохранённого gen; в 14.22 byte-паттерн `e8 ?? ?? ?? ??` (вызов unlock) и `e8 ?? ?? ?? ??` (lookup) будет
   разнесён иначе, чем в 13.60 (в 13.60 — 5 инструкций между ними, см. §5.3).
4. В wait: проверить `imul $0x38,%r14,%rdi` + `lea zone` перед аллокацией waiter-массива и вызов free; **признак патча:**
   новый refcount/лок вокруг массива, изменённый размер/зона, или гейт на count/mode.
5. Проверить, не стали ли стабы 661–670 короче/не указывают ли на общий error/nosys — но это маловероятно.
6. Сравнить `narg` в sysent (662:3, 663:5, 664:3, 669:5) — если Sony меняла API, narg изменится.
7. Дополнительно: `strings | grep -E 'aio_multi_delete|aio_multi_wait|_aio_submit_cmd'` — строки должны остаться.

## 7. Альтернативные userland→kernel поверхности FreeBSD 11 (кандидаты для 14.22)

**Важный общий контекст:** «userland→kernel» на PS5 — это не только дыра в ядре, но и (1) userland-примитив в WebKit
(иначе syscall'ы не вызвать), (2) доступность syscall-стабов: в Relapse-цепочке финальная эскалация патчит
`dynlib->syscallStart/End`, `restrictFlags`, `libkernelRef` (см. `recon/relapse-anatomy.md` §E4) — значит Sony умеет
ограничивать набор/диапазон syscall'ов для процесса; на 14.2x эта политика может быть иной. Это отдельный риск,
который тоже нельзя проверить без образа/консоли.

| # | Поверхность | Точка входа (№ syscall из нашего имени-CSV) | История (публичные факты) | Есть в 13.60 (доказательство) | Статус 14.22 | Как проверять без консоли |
|---:|---|---|---|---|---|---|
| 1 | AIO `aio_multi_delete` TOCTOU | 662 (`narg=3`) | Prolapse: 14.00/14.10, закрыт в 14.20 (LavX/Coixao); Lapse-родственник (blog.gistre) | да: хендлер `0x3af900`, TOCTOU-путь (§5.3), строки `aio_multi_delete` ×2 | **вероятно закрыт** (пресс), механизм не доказан | образ 14.22 → §6; пресс/issue-трекеры |
| 2 | AIO `aio_multi_wait` UAF массива waiter'ов | 663 (`narg=5`) | Relapse: 7.00–13.60 (README, 2713★); «14.00 reportedly closed» — unsourced | да: хендлер `0x3b01f0`, alloc `count*0x38` zone `0x1ab5a50` (§5.4) | **неизвестен** (ни за, ни против) | образ 14.22 → сравнить wait-тело; на консоли — Relapse-подобный прогон |
| 3 | AIO debug info (`get_aio_debug_request_info/submit_info`) | 726, 727 | по S1 (14.10-репо): info leak закрыт в 14.00 | да: syscalls 726/727 в CSV; строки `_get_aio_debug_request_info`, `_get_aio_debug_submit_info` | неизвестен | образ; строки; тесты info-leak |
| 4 | UMTX / UMTX2 | 454 (`_umtx_op`) | idlesauce/umtx2: 1.00–5.50; PS5Dev/PS5-UMTX-Jailbreak: 3.x–4.x | да: `_umtx_op` в sysent; строка `umtx_op` | неизвестен | образ; проверить тело `_umtx_op` и гейты |
| 5 | IPv6 socket UAF (netinet6) | 27/28 (`recvmsg`/`sendmsg`), 97 (`socket`), 113 (`socketex`) | TheFlow HackerOne #1441103; Cryptogenic PS5-IPV6-Kernel-Exploit: 3.00–4.51 | да: строки `in6_pcb` ×2, netinet6-код в дампе | неизвестен | образ; строки/символы netinet6; дифф обработчиков send/recv |
| 6 | kqueue/kevent | 362 (`kqueue`), 363 (`kevent`), 141 (`kqueueex`) | FreeBSD kqueue исторически давал UAF (класс CVE), публичной PS5-цепочки нет | да: syscalls + строки `kqueue` ×35, `kevent` ×7, `knote` ×2 | неизвестен | образ; strings/sysent; статический аудит handler'ов |
| 7 | Sony ioctl-хендлеры драйверов | 54 (`ioctl`); `gc_ioctl`, `mmap_dmem` (628), `mdbg_service` (601), `ampr_ctrl_debug` (721), `test_debug_rwmem` (619) | PS5-драйверы (dmem/gc/a53mm) — историческая поверхность; `SYS_601_MDBG_SERVICE_LIMITS_13_60.md` (ZigZag) | да: строки `gc_ioctl_internal`, `m_aio_debug`, `dmem` (syscall `mmap_dmem`), `mdbg` ×22 | неизвестен; доступность fd из браузерного процесса под вопросом | образ; список /dev и ioctl-номеров из payload'ов |
| 8 | pipe/filedesc-пересечение | `pipe`/`pipe2`, `filedesc` | Relapse V8 (пост-R/W примитив, не вход); FreeBSD pipe UAF'ы | да: строки `pipe` ×103, `filedesc` ×5 | n/a как вход; как техника — от образа не зависит | образ: `struct pipe` layout |
| 9 | sysctl / sysctl_oid | `sysctl` (нэкзотич. номера); `kern.*` | Relapse V7 (kind-flip, пост-R/W); logicalpeyote: sysctl kind swap на 14.00 (S3) | да: строки `sysctl` ×48, `sysctl_oid` структуры в data | неизвестен | образ; сравнить `sysctl_oid`/handler'ы |
| 10 | SCSI/CAM passthrough | нет syscall; `/dev/pass*`, `cam` | FreeBSD CAM/xpt UAF-класс; PS5: нет публичной цепочки | да: `xpt_*` ×22, `scsi_*`, `cam_xpt` ×4 | неизвестен; нужны device-ноды (из браузера недоступны) | образ; strings; на консоли — список /dev |
| 11 | nmount/namei | 378 (`nmount`), `namei` | FreeBSD mount/namei CVE-класс | да: `nmount` ×49, `namei` ×29 | неизвестен | образ; аудит путей |
| 12 | jitshm (RWX/alias) | 533 (`jitshm_create`), 534 (`jitshm_alias`) | Relapse kexp: `jitshm_create`+`alias` обход W^X (post-exploit primitive) | да: строки `jitshm_create`, `jitshm_alias`, `jitshmrgn` | неизвестен; как примитив — зависит от W^X-политики | образ; проверить гейты jitshm |
| 13 | kld* (kernel modules) | 304–308, 337 (`kldload`…`kldsym`) | kstuff: загрузка kernel-модулей только с kernel R/W | да: syscalls в CSV | не вход (нужен R/W) | — |
| 14 | ptrace | 26 | FreeBSD ptrace RFI (HackTricks: `freebsd-ptrace-rfi-vm_map-prot_exec-bypass-ps5.md`) | да: syscall 26 | неизвестен; традиционно закрыт для браузерного процесса | образ; гейты `cap_*`/sandbox |
| 15 | Гипервизор (не FreeBSD, но слой) | Byepervisor/HV-эксплойт | Byepervisor-Reborn (PS5Dev) — обход HV; 14.10 HV-баг закрыт (S1) | n/a | неизвестен | репозитории/пресс; образ HV-компонента недоступен |

**Оценка применимости к 14.22 (честно):** ни одну из строк нельзя назвать «открытой» или «закрытой» — нет ни образа 14.22,
ни публичного прогона на 14.10+ с kernel R/W. Единственная поверхность с *публичным* указанием на патч — AIO delete (662).
Для остальных статус = «неизвестен»; проверка требует либо decrypted image 14.22 (не существует публично), либо консоли
с userland-входом (тоже нет: на 14.10+ нет публичной цепочки до syscall'ов).

## 8. Ограничения (что нельзя доказать)

1. **Нет публичного образа 14.20/14.22** (ни ELF, ни dump, ни decrypted kernel.bin): task-2 — `recon/kernel-dumps.md` §6/§13;
   на 2026-11-11 найдены только live-дампы 13.60. Значит, «что Sony изменила в 14.22», можно узнать только из прессы/заявлений
   или с консоли.
2. **Нет публичного userland→kernel пути на 14.10+**: kernel R/W ни на 14.10, ни на 14.20/14.22 не продемонстрирован
   (S1/S2/S3/S4; см. `recon/1422-status.md`). Поэтому «проверить AIO на консоли» сейчас нечем — нет входа.
3. **Механизм 14.20-патча** (generation revalidation) — inference, а не результат анализа 14.20-образа; gist/kuzibelit
   верифицировали по `kernel_1410.elf` (14.10), где патча быть не может. Круговая цитата: kuzibelit ← gist; ZigZag
   «14.20 note» ← по сути тот же тезис; cyber-forge ← без ссылки.
4. **Маркетинговый источник cyber-forge** не является техническим; его «Blocked» переоценивать нельзя.
5. **Числа sysent/имена** взяты из нашего дампа 13.60 + CSV ZigZag, которые сошлись 677/677 и 735/735; но это 13.60, не 14.22.

## 9. Источники (проверено 2026-11-11, коды/локальные копии)

| Источник | URL / доступ | Код/размер | Локальная копия |
|---|---|---|---|
| cyber-forge app.js (66 503 B) | `gh api repos/oscarlaradev/cyber-forge-ps5-ps4-exploit-host/contents/app.js` | 200 | `_src/t14/cyberforge-app.js.lines265-290.txt` |
| Khal0da/PS5-14.20-WebKit-Research | `gh api repos/Khal0da/...` + tree + docs | 200; `search/code` aio_multi_delete → **0** | (цитаты в §2) |
| LavX News, 2026-10-25 | https://news.lavx.hu/article/ps5-kernel-exploit-prolapse-works-on-firmware-14-10-but-gta-6-piracy-remains-unlikely-for-now | 200, 144 861 B | `_src/t14/lavx-prolapse-2026-10-25.txt` |
| NotebookCheck, 2026-10-21 | https://www.notebookcheck.net/Firmware-14-20-may-stop-PS5-console-jailbreak-but-an-exploit-has-already-surfaced.1430271.0.html | 200, 135 160 B | (цитата в §2) |
| zecoxao gist (Prolapse code, 25 024 B) | `gh api gists/80dff057233c1f203352ff8bf317294d` | 200; created 2026-10-26T23:05:53Z | `_src/t14/zecoxao-prolapse-gist.txt` |
| kuzibelit PoC (50★, push 2026-10-27) | `gh api repos/kuzibelit/PS5-14.00-14.10-Jailbreak-PoC` | 200; `aio_lapse_exploit.c` 577 строк | `_src/t14/kuzibelit-aio_lapse-header.txt` |
| ZigZag AIO forensics | `repos/ZigZagBoi1/PS5-14.10-Research/contents/docs/AIO_OBJECT_FORENSICS.md` | 200, 13 691 B | `_src/t14/zigzag-aio-object-forensics.md` |
| ZigZag AIO 14.10 evidence | `.../docs/AIO_RANGE_14_10_EVIDENCE.md` | 200, 120 842 B | `_src/t14/zigzag-aio-range-14-10-evidence.md` |
| ZigZag verification (HALF CONFIRMED) | `.../docs/2026-10-25/VERIFICATION_LAPSE_CLAIMS.md` | 200, 8 225 B | `_src/t14/zigzag-verification-lapse-claims.md` |
| ZigZag sysent name CSVs | `.../docs/sysent-names-13.60.csv`, `.../docs/sysent-compat-names-13.60.csv` | 200; сверка с дампом 735/735 и 677/677 | `_src/t14/sysent-names-13.60-{native,compat}.csv` |
| Relapse README (FW 7.00–13.60) | `repos/ntfargo/Relapse-Exploit/contents/README.md` | 200 | — |
| Cryptogenic IPv6 exploit (3.xx/4.xx) | `repos/Cryptogenic/PS5-IPV6-Kernel-Exploit/contents/README.md` | 200 | — |
| UMTX2 (1.00–5.50) | `repos/idlesauce/umtx2/contents/README.md` | 200 | — |
| Наш дамп 13.60 + sysent | `fw/ps5-kernel-13.60-live.bin` (sha256 `c3f745e2…`), `fw/sysent-13.60.json` | — | — |
| Командный recon | `recon/1422-status.md` (S1–S12, коды/статусы), `recon/relapse-anatomy.md` (§3.1 offsets, §E4 dynasty) | — | — |

## 10. Легенда достоверности

| Метка | Значение |
|---|---|
| `ПОДТВЕРЖДЕНО` | проверено командой/файлом в этой сессии (дизасм, sha256, HTTP 200, сверка таблиц) |
| `ЗАЯВЛЕНО АВТОРОМ` | слова автора репозитория/gist'а без аппаратного подтверждения |
| `НЕ ПОДТВЕРЖДЕНО` | источников не найдено / есть противоречие (напр. «механизм generation-id») |
| `ПЕРЕСКАЗ` | утверждение третьей стороны без первоисточника (cyber-forge) |
| `НЕИЗВЕСТЕН` | проверить нельзя без образа 14.22/консоли |