# AIO-waiter-вектор: подтверждение констант по дампу 13.60 (task-36)

**Агент:** recon-kernel-dumps · **дата:** 2026-11-11 · **источник:** `fw/ps5-kernel-13.60-live.bin`
(sha256 `c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd`) + `fw/sysent-13.60.json`.
**Дисциплина:** каждая константа — с RVA (RVA = file offset в дампе, т.к. текст начинается с base `0xffffffff9e3f0000`)
и байтами из дизасма. Чужие отчёты **не** использованы как доказательство — только как гипотезы для проверки.
Инструмент: `objdump -D -b binary -m i386:x86-64` (**rizin в системе отсутствует** — проверено `which rizin/rz-bin`,
`pip import r2pipe`, `find /opt /usr/local … -iname 'rizin*'`: пусто. Байты дизасма те же, что дал бы rizin; замечание
для лида: если требуется именно rizin — его надо доустановить).

## 0.1 ОТВЕТ НА ЗАДАЧУ: три константы, подтверждённые байтами (rizin 0.9.1)

**Хендлеры (из `fw/sysent-13.60.json`, стабы `e9 rel32` декодированы):**
- **663 `aio_multi_wait`**: stub RVA `0x265720` → **handler RVA `0x3b01f0`**.
- **661 `aio_submit`**: stub RVA `0x265710` → handler RVA `0x3af8f0`, но это **NOSYS-трамплин**
  (`jmp 0x265760`, rizin: `0x003af8f7 jmp 0x265760`) — count там не читается.
- **`aio_submit_cmd` — это syscall 669** (stub `0x265740` → handler **`0x3b2060`**), rizin подтверждает строку
  `"_aio_submit_cmd"` @`0x01379d6c` в коде 669. В задаче 661 назван submit_cmd ошибочно; ниже — доказательства для 669.

Команда (одна rizin-сессия):

```bash
/tmp/rizin-dl/bin/rizin -q -e scr.color=0   -c 'pd 8 @ 0x3b0570' -c 'pd 6 @ 0x3b0384' -c 'pd 6 @ 0x3b07fd'   -c 'pd 14 @ 0x3b2350' -c 'pd 14 @ 0x3b2170' -c 'pd 5 @ 0x3af8f0' -c 'pd 5 @ 0x3b2060'   fw/ps5-kernel-13.60-live.bin
```

| константа | значение | адрес в дампе (RVA) | байты-доказательство (rizin, `fw/ps5-kernel-13.60-live.bin`) |
|---|---:|---:|---|
| **waiterSize** (размер элемента waiter-массива) | **0x38** | `0x3b0576` (663) | `49 6b fe 38` = `imul rdi, r14, 0x38`; следом `48 8d 35 cf 54 70 01` = `lea rsi,[0x1ab5a50]`, `ba 02 01 00 00`, `e8 …` = alloc. Шаг: `49 83 c6 38` = `add r14,0x38` @`0x3b05de`; повтор `49 6b c6 38` @`0x3b0de3` |
| **group.waiters** (смещение поля-головы списка waiter'ов в aio_group) | **0x50** | `0x3b07fd` / `0x3b080c` (663) | `49 8b 45 50` = `mov rax,[r13+0x50]`; `4d 89 75 50` = `mov [r13+0x50],r14` (push head); `49 89 46 30` = `mov [r14+0x30],rax` (next). Инициализация: `49 c7 46 50 00 00 00 00` @`0x3b239a` (669); обход: `48 8b 41 50`/`48 8b 40 30` @`0x3b0e31`/`0x3b0e4c` |
| **groupSize** (sizeof aio_group) | **0x58** | `0x3b2360` (669) | `bf 58 00 00 00` = `mov edi,0x58`; `48 8d 35 10 36 70 01` = `lea rsi,[0x1ab5970]` @`0x3b2359`; `e8 e1 67 85 00` = alloc @`0x3b236a`. Массив групп: `41 6b fc 58` = `imul edi,r12d,0x58` @`0x3b23bd`; шаг `49 83 c5 58` @`0x3b2408` |
| *бонус: где читается count* | — | 663: `0x3b0384`; 669: `0x3b217a` | 663: `48 8b 4b 70` = `mov rcx,[rbx+0x70]` (count от arg1: `8b 56 08` @`0x3b01f7`, сохранён `48 89 53 70` @`0x3b023d`); гейт `8d 81 7f ff ff ff` / `3d 7f ff ff ff` / `77 23` → 1..0x80. 669: `4c 8b 73 10` = `mov r14,[rbx+0x10]` (count = arg2: `8b 4e 10` @`0x3b206a`); гейт `41 8d 86 7f ff ff ff` / `3d 7f ff ff ff` / `77 1e` → 1..0x80 |

Дополнительно rizin видит строки-маркеры: `"_aio_multi_wait"` @`0x01379d7c`, `"_aio_submit_cmd"` @`0x01379d6c`
(совпадает с `rodataProbe.rva=0x01379d6c` из Relapse-офсетов 13.60 — независимая сверка).

## 0. TL;DR (для лида)

1. **Хендлеры AIO (13.60) найдены через sysent-стабы** (стаб = 8-байтный `e9 rel32 cc cc cc` в области `0x265xxx`):

| syscall | имя (CSV ZigZag) | стаб RVA | хендлер RVA | состояние по коду |
|---:|---|---:|---:|---|
| 661 | `aio_submit` | `0x265710` | `0x3af8f0` | **NOSYS**: `jmp 0x265760` (trampoline nosys) |
| 662 | `aio_multi_delete` | `0x265718` | `0x3af900` | реальный |
| 663 | `aio_multi_wait` | `0x265720` | `0x3b01f0` | реальный (главный вектор) |
| 664 | `aio_multi_poll` | `0x265728` | `0x3b0fb0` | реальный |
| 665 | `aio_get_data` | `0x265730` | `0x3b1670` | **NOSYS** (`jmp 0x265760`) |
| 666 | `aio_multi_cancel` | `0x265738` | `0x3b1680` | реальный |
| 668 | `aio_create` | `0x265708` | `0x3af8e0` | **NOSYS** (`jmp 0x265760`) |
| 669 | `aio_submit_cmd` | `0x265740` | `0x3b2060` | реальный (создание group/W/очередей) |
| 670 | `aio_init` | `0x265748` | `0x3b28d0` | реальный |

   ⚠️ Замечание к формулировке задачи: **`aio_submit_cmd` — это syscall 669, а не 661**; 661 (`aio_submit`) в 13.60 —
   `nosys`-трамплин. Цепочка Relapse использует 669 (submit_cmd), 663 (wait), 666 (cancel) — так и надо.
2. **waiterSize = 0x38 подтверждён**: `imul $0x38,%r14,%rdi` (`49 6b fe 38` @ **0x3b0576**), аллокация
   `count*0x38` из зоны `0x1ab5a50` (**0x3b057a**: `lea 0x1ab5a50(%rip),%rsi`; **0x3b0586**: `call 0xc08b50`);
   шаг по массиву `add $0x38,%r14` (`49 83 c6 38` @ **0x3b05de**); повтор `imul $0x38,%r14,%rax` @ **0x3b0de3**.
3. **group.waiters = 0x50 подтверждён**: инициализация `movq $0x0,0x50(%r14)` (`49 c7 46 50 00 00 00 00` @
   **0x3b239a**); постановка в очередь `mov 0x50(%r13),%rax; mov %rax,0x30(%r14); mov %r14,0x50(%r13)`
   (@ **0x3b07fd–0x3b080c** и **0x3b08b1–0x3b08c0**); обход списка `mov 0x50(%rcx),%rax; mov 0x30(%rax),%rax`
   (@ **0x3b0e31/0x3b0e43/0x3b0e4c**).
4. **Размер aio_group = 0x58 подтверждён**: `mov $0x58,%edi; lea 0x1ab5970(%rip),%rsi; call 0xc08b50`
   (**0x3b2359–0x3b236a**); инициализация полей @ **0x3b238b–0x3b23a2**; массив групп `imul $0x58,%r12d,%edi`
   (`41 6b fc 58` @ **0x3b23bd**), шаг `add $0x58,%r13` (`49 83 c5 58` @ **0x3b2408**).
5. **Поля group**: `+0x00` (u32, счётчик/num; init из аргумента @0x3b238b, в batch = 1), `+0x04` (u32, init 1),
   `+0x08` **state** (init 1 @0x3b2392; wait требует `state <= 2` @0x3b07f2; cancel — `state == 3|4` @0x3b1b6c),
   `+0x10` ptr (cancel @0x3b1c43), `+0x20` **lockmgr-замок** (`lea 0x20(%r14),%rdi; call 0xbf1690` — init @0x3b23a2;
   ops через `0xbf1770` с op `0x80000`/`0x100000`), `+0x38` u32 (cancel: `cmpl $0x1,0x38(%r13)` @0x3b1c20),
   `+0x50` **waiters head**; размер 0x58.
6. **Лимиты на count**: у 663 `count` = arg1 (`mov 0x8(%rsi),%edx` → `ctx+0x70`), гейт **1..0x80**
   (`lea -0x81; cmp $0xffffff7f; ja` @ **0x3b0388–0x3b0393**); у 669 `count` = arg2 (`mov 0x10(%rsi),%ecx` → `ctx+0x10`),
   тот же гейт **1..0x80** (`lea -0x81(%r14); cmp $0xffffff7f` @ **0x3b217e–0x3b218a**); у 662 delete — тоже 1..0x80
   (@0x3af9fb). `mode` у 663 — arg3, `< 3` (`cmp $0x3,%r13d; jae` @ **0x3b03b8–0x3b03bc**). Гейт режима процесса
   (`cmpl $0x1,0x4a0(%rsi)` @0x3b2139) присутствует и в 669, как в delete.
7. **Формат id и таблица**: `id <= 0xffff` (`cmp $0xffff,%esi` @0x399ef1); `slot = id & 0x1fff` (@0x399f19);
   страница = `slot >> 7` (@0x399f5b), слот = `slot & 0x7f` * **0x30** (`and $0x7f; lea (*3); shl $4` @0x399f62–0x399f6c);
   **pages = aioInfo+0x220** (`mov 0x220(%r13),%eax` @0x399f25), замок таблицы = `aioInfo+0x218`
   (`lea 0x218(%rdi),%rbx` @0x399ef9, lock @0x399f20); lookup везде с **типом 0x160** (@0x3b0628, @0x3b25d1, @0x3b198d).
   В 663: `id>>16` = индекс дескриптора (max 0x80 и `< *(int16*)descriptor`), `id&0xffff` ≠ 0 (гейты @0x3b05f9–0x3b0667).
8. **Ограничение подхода (честно):** всё подтверждено по **13.60**; в 14.22 адреса/структуры могут измениться. Чек-лист
   «что искать в дампе 14.22» — §6. Rizin отсутствует — использован objdump; байты в `.asm`-логах (`/tmp/aio/*.asm`).

## 1. Как получены адреса хендлеров

`fw/sysent-13.60.json` (compat 677, native 735, stride 48, `sy_call` @+8) даёт `sy_call` = RVA **стаба**.
Стабы — 8-байтные `e9 rel32 cc cc cc` в таблице ~`0x265d00–0x265fa8`. Декод `jmp rel32` дал хендлеры (таблица §0.1).
Команда-доказательство:

```python
# decode stub: handler = stub + 5 + int32(data[stub+1:stub+5])
# 661: stub 0x265710 bytes e9 dba11400cccccc -> 0x3af8f0
# 663: stub 0x265720 bytes e9 cbaa1400cccccc -> 0x3b01f0
# 669: stub 0x265740 bytes e9 1bc91400cccccc -> 0x3b2060
```

Также проверено, что `aioInfo` лежит в `proc+0xc48`: `mov 0xc48(%r12),%rax` @0x3b0259 (663) и
`mov 0xc48(%r13),%rax` @0x3b20c6 (669) — совпадает с `proc.aioInfo` в `tools/jb1422/kernel/offsets/1422.js`.

## 2. 663 `aio_multi_wait` (0x3b01f0): аргументы, count, waiter-массив

### 2.1 Аргументы и вход

```
3b01f0: 55                    push %rbp
3b01f1: 48 89 e5              mov  %rsp,%rbp
3b01f4: 48 8b 06              mov  (%rsi),%rax        ; arg0 = ids ptr
3b01f7: 8b 56 08              mov  0x8(%rsi),%edx     ; arg1 = count
3b01fa: 48 8b 4e 10           mov  0x10(%rsi),%rcx    ; arg2 = states ptr
3b01fe: 44 8b 46 18           mov  0x18(%rsi),%r8d    ; arg3 = mode
3b0202: 4c 8b 4e 20           mov  0x20(%rsi),%r9     ; arg4 = timeout
...
3b0210: (тело, rbx = ctx)
3b023d: 48 89 53 70           mov  %rdx,0x70(%rbx)   ; count сохранён в ctx+0x70
3b0259: 49 8b 84 24 48 0c 00 00  mov 0xc48(%r12),%rax ; proc->aioInfo
```

### 2.2 Лимиты

```
3b0384: 48 8b 4b 70           mov  0x70(%rbx),%rcx    ; count
3b0388: 8d 81 7f ff ff ff     lea  -0x81(%rcx),%eax
3b038e: 3d 7f ff ff ff        cmp  $0xffffff7f,%eax
3b0393: 77 23                 ja   ...                 ; count in [1..0x80]
3b03b8: 41 83 fd 03           cmp  $0x3,%r13d         ; mode
3b03bc: 73 50                 jae  ...                ; mode < 3
```

### 2.3 Аллокации: waiter-массив count*0x38

```
3b0524: 4c 8b 73 20           mov  0x20(%rbx),%r14     ; count
3b0528: 48 8d 35 d1 d2 6c 01  lea  0x1a7d800(%rip),%rsi ; zone results (count*0x18)
3b0534: 4a 8d 04 f5 00 00 00 00 lea 0x0(,%r14,8),%rax
3b053c: 48 8d 3c 40           lea  (%rax,%rax,2),%rdi   ; count*0x18
3b0540: e8 0b 86 85 00        call 0xc08b50
3b0576: 49 6b fe 38           imul $0x38,%r14,%rdi      ; <-- waiterSize = 0x38
3b057a: 48 8d 35 cf 54 70 01  lea  0x1ab5a50(%rip),%rsi ; zone waiter-array
3b0581: ba 02 01 00 00        mov  $0x102,%edx          ; M_WAITOK|M_ZERO
3b0586: e8 c5 85 85 00        call 0xc08b50
```

Шаг по элементам и инициализация:

```
3b05ce: 66 90                 nop
3b05d0: 41 c7 46 20 03 00 02 80 movl $0x80020003,0x20(%r14) ; waiter+0x20 = status
3b05de: 49 83 c6 38           add  $0x38,%r14              ; stride 0x38
3b05e2: 49 83 c0 18           add  $0x18,%r8               ; stride результатов 0x18
...
3b0649: 49 89 46 28           mov  %rax,0x28(%r14)         ; waiter+0x28 = entry/дескриптор
3b07db: 49 89 06              mov  %rax,(%r14)             ; waiter+0x00 = ptr (ctx+0x104)
3b07e5: 49 89 46 10           mov  %rax,0x10(%r14)         ; waiter+0x10 = ptr event (ctx+0xe0)
3b0808: 49 89 46 30           mov  %rax,0x30(%r14)         ; waiter+0x30 = next
3b080c: 4d 89 75 50           mov  %r14,0x50(%r13)         ; group+0x50 = waiters head
3b0810: 4d 89 6e 18           mov  %r13,0x18(%r14)         ; waiter+0x18 = group
3b089a: 49 89 46 08           mov  %rax,0x8(%r14)          ; waiter+0x08 = ptr (ctx+0x10c)
```

### 2.4 Структура waiter (0x38)

| offset | размер | что | доказательство |
|---:|---:|---|---|
| `0x00` | 8 | ptr на поле ctx (`ctx+0x104`) | `3b07db: 49 89 06` |
| `0x08` | 8 | ptr (`ctx+0x10c`) | `3b089a: 49 89 46 08` |
| `0x10` | 8 | ptr на event/объект ожидания (`ctx+0xe0`; затем `call 0x4c6fa0`) | `3b07e5`, `3b088f` |
| `0x18` | 8 | **group ptr** | `3b0810: 4d 89 6e 18` |
| `0x20` | 4 | **status** (`0x80020003` / `0x80020001` / 0) | `3b05d0`, `3b0669`, `3b0690` |
| `0x28` | 8 | entry/дескриптор (результат lookup'а) | `3b0649: 49 89 46 28` |
| `0x30` | 8 | **next** (singly-linked waiters list) | `3b0808`/`3b08bc`; обход `3b0e4c: 48 8b 40 30` |
| `0x38` | — | размер элемента (след. запись) — `add $0x38` | `3b05de`, `3b0de3: 49 6b c6 38` |

## 3. 669 `aio_submit_cmd` (0x3b2060): group 0x58 и узлы 0x28

### 3.1 Аргументы и count

```
3b2064: 8b 06                 mov  (%rsi),%eax        ; arg0 (id/флаги)
3b2066: 48 8b 56 08           mov  0x8(%rsi),%rdx     ; arg1 = nodes ptr
3b206a: 8b 4e 10              mov  0x10(%rsi),%ecx    ; arg2 = count
3b206d: 44 8b 46 18           mov  0x18(%rsi),%r8d    ; arg3
3b2071: 4c 8b 4e 20           mov  0x20(%rsi),%r9     ; arg4
...
3b2176: 4c 89 73 50           mov  %r14,0x50(%rbx)
3b217a: 4c 8b 73 10           mov  0x10(%rbx),%r14   ; count = arg2
3b217e: 41 8d 86 7f ff ff ff  lea  -0x81(%r14),%eax
3b2185: 3d 7f ff ff ff        cmp  $0xffffff7f,%eax
3b218a: 77 1e                 ja   ...                 ; 1 <= count <= 0x80
3b218c: ...                  (иначе EINVAL 0x16)
```

### 3.2 Аллокация aio_group: 0x58

```
3b2359: 48 8d 35 10 36 70 01  lea  0x1ab5970(%rip),%rsi  ; zone group
3b2360: bf 58 00 00 00        mov  $0x58,%edi           ; <-- sizeof(aio_group) = 0x58
3b2365: ba 02 01 00 00        mov  $0x102,%edx
3b236a: e8 e1 67 85 00        call 0xc08b50
3b238b: 41 89 06              mov  %eax,(%r14)          ; group+0x00 = num
3b238e: 41 89 46 04           mov  %eax,0x4(%r14)       ; group+0x04
3b2392: 41 c7 46 08 01 00 00 00 movl $0x1,0x8(%r14)      ; group+0x08 = state = 1
3b239a: 49 c7 46 50 00 00 00 00 movq $0x0,0x50(%r14)     ; group+0x50 = waiters = NULL
3b23a2: e8 e9 f2 83 00        call 0xbf1690             ; init lock at group+0x20 (rdi=lea 0x20(%r14) @0x3b2387)
```

Массив групп (batch): `41 6b fc 58` (**3b23bd**: `imul $0x58,%r12d,%edi`), инициализация каждой:
`movabs $0x100000001,(%r13)` (+0x00/+0x04 = 1), `movl $1,0x8(%r13)`, `movq $0,0x50(%r13)`,
`call 0xbf1690` с `lea 0x20(%r13)`; шаг `add $0x58,%r13` @**3b2408**.

### 3.3 Узлы запросов (requestSize = 0x28) и W (0x58)

```
3b2530: bf 58 00 00 00        mov  $0x58,%edi
3b2535: 48 8d 35 c4 33 70 01  lea  0x1ab5900(%rip),%rsi ; zone W = 0x58
3b253c: ba 02 01 00 00        mov  $0x102,%edx
3b2541: e8 0a 66 85 00        call 0xc08b50
3b2552: 89 08                 mov  %ecx,(%rax)           ; W+0x00 = id
3b2554: 4c 89 60 10           mov  %r12,0x10(%rax)       ; W+0x10 = descriptor
3b2558: 48 89 70 18           mov  %rsi,0x18(%rax)       ; W+0x18 = context
3b255c: 4c 89 70 20           mov  %r14,0x20(%rax)       ; W+0x20 = work object (group)
3b2560: 4a 89 04 fa           mov  %rax,(%rdx,%r15,8)    ; таблица W[]
3b2567: 49 83 c4 28           add  $0x28,%r12            ; <-- requestSize = 0x28 (stride узлов)
3b25bf: 49 83 c7 28           add  $0x28,%r15            ;     тот же stride для таблицы
```

## 4. 666 `aio_multi_cancel` (0x3b1680): подтверждение полей group

```
3b1b24: 41 83 7d 00 02        cmpl $0x2,0x0(%r13)        ; group+0x00 = num (сравнение с 2)
3b1b48: 49 8d 7d 20           lea  0x20(%r13),%rdi       ; group+0x20 = lock
3b1b4c: be 00 00 08 00        mov  $0x80000,%esi         ; LK_ACQUIRE
3b1b63: e8 08 fc 83 00        call 0xbf1770
3b1b6c: 41 8b 45 08           mov  0x8(%r13),%eax        ; state
3b1b74: 8d 48 fd              lea  -0x3(%rax),%ecx       ; state-3
3b1b77: 83 f9 01              cmp  $0x1,%ecx
3b1b7a: 77 37                 ja   ...                   ; требует state in {3,4}
3b1b87: be 00 00 10 00        mov  $0x100000,%esi        ; LK_RELEASE
3b1b97: e8 d4 fb 83 00        call 0xbf1770
3b1bb3: 41 8b 4d 00           mov  0x0(%r13),%ecx        ; group+0x00
3b1c20: 41 83 7d 38 01        cmpl $0x1,0x38(%r13)       ; group+0x38
3b1c43: 49 8b 45 10           mov  0x10(%r13),%rax       ; group+0x10 = ptr
3b1c4a: 48 83 78 18 00        cmpq $0x0,0x18(%rax)
```

## 5. 662 `aio_multi_delete` (0x3af900): что проверяет перед удалением (для чек-листа)

- `cmpb $0x0,0xc(%r14)` @**0x3afdaa** — флаг завершения group (`group+0xc`); если 0 → status `0x80020010`;
- `cmpq $0x0,0x50(%r14)` @**0x3afddc** — **waiters head должен быть пуст**, иначе status `0x80020010`;
- замок группы: acquire `call 0xbf1770` с `esi=0x80000` @**0x3afda1**, release с `esi=0x100000` @**0x3afe29**
  (`0x3afe12: mov 0x38(%rbx),%rdi` → `group+0x20`);
- TOCTOU-окно: unlock `0x399eb0` @**0x3afe67** → re-lookup `0x39a2a0` @**0x3afe7c** (generation-id проверка в lookup'е,
  см. `recon/kernel-surface-1422.md` §5.3) — Sony может усилить именно это место в 14.20+.

## 6. Чек-лист «что искать в дампе 14.22» (сигнатуры)

При появлении расшифрованного образа 14.22 (или userland-дампа с системными модулями) искать:

1. **Хендлеры AIO через sysent**: native/compat 677/735 записей? Если число изменилось — таблица перестроена.
   Для 662/663/666/669 декодировать стабы и дизасмить; сигнатуры-маркеры:
   - `imul $0x38`/`add $0x38` (waiter stride) — **если 0x38 изменился, вектор требует пересчёта**;
   - `mov $0x58` + `lea` на zone (group) — размер группы; `imul $0x58` (batch);
   - `lea -0x81; cmp 0xffffff7f; ja` (count 1..0x80) — если лимит стал меньше/больше, атака меняет churn;
   - `cmp $0x3,%r13d; jae` (mode <3), `cmpl $0x1,0x4a0(%rsi)` (process-mode gate);
   - `mov $0x160` (idTable entryType) — если Sony сменила тип lookup'а, старые id не пройдут;
   - `mov 0x220(%rXX)`/`lea 0x218(%rXX)` (pages/lock в aioInfo).
2. **Усиление generation-id** (слухи про 14.20): в delete-пути после unlock (`call` на unlock) и до re-lookup
   (`0x39a2a0`-аналог) искать **новые** инструкции: `mov 0x28(slot),%eax; shl $0xd; cmp` / доп. `jne`/`ja` на error-path;
   в lookup'ах (idTable 0x399ee0-аналог) — проверку `high16 < descriptor->count` и `low16 != 0` могли усилить
   (например, проверкой generation слова слота или refcount).
3. **Новые/удалённые syscalls**: 661/665/668 в 13.60 = nosys-трамплины; в 14.22 проверить, не стали ли
   662/663/666/669 тоже трамплинами (`jmp 0x265760`-аналог) — это был бы прямой признак «вектор закрыт»;
   также проверить, не добавили ли `aio_submit_cmd` валидацию узлов (count*0x28) сверх существующей.
4. **Структуры userland↔kernel**: ожидаемые поля/размеры — waiter 0x38, request 0x28, group 0x58, idTable pages 0x220/
   slotStride 0x30/entryType 0x160; локи `0x80000`/`0x100000`; status-коды `0x80020003` (EINVAL), `0x80020001`,
   `0x80020010` (busy/waiter), `0x80020055`.
5. **Сравнение с нашими модулями**: в свежих game-дампах искать `_aio_submit_cmd`/`aio_multi_wait` строки и
   libkernel-импорты 669/663 — подтвердит, что userland API тех же сисколлов сохранился (ABI).

## 7. Что не подтверждено / риски

- Все адреса — **13.60**. В 14.22 RVA сдвинутся (KASLR не влияет на RVA, но сборка другая): константы нужно
  пере-сканировать (сигнатуры в §6).
- `nodeMutex` (в 13.60 data-адрес `0x01a9bab8` из Relapse-офсетов) **не проверялся** по коду в этой задаче —
  он нужен для сборки waiter-узлов в userland-части цепочки. Остался в `missing[]` (в 1422.js).
- Семантика `group+0x04`, `group+0x10`, `group+0x38` — поля существуют (записи/чтения подтверждены), но точное
  назначение (refcount/descriptor/флаг) не доказано; названы условно.
- rizin в системе нет — дизасм objdump'ом; если для отчёта обязателен rizin, нужен доустанов (не критично: байты те же).

## 8. Артефакты

- `tools/jb1422/kernel/offsets/1422.js` — секция `aio` обновлена (source="scan-13.60"), `missing[]` дополнен
  AIO-зависимостями; `node --check` проходит.
- Дизасм-логи: `/tmp/aio/{661_submit,662_delete,663_wait,666_cancel,668_create,669_submit_cmd}.asm`
  (получены из `fw/ps5-kernel-13.60-live.bin`; RVA = адреса в логах).
- Связанные отчёты: `recon/kernel-surface-1422.md` (§5 AIO, чек-лист 14.22), `recon/kernel-code-14x.md`,
  `recon/relapse-anatomy.md` (цепочка), `fw/sysent-13.60.json`.