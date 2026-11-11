# tools/kexpl — payload-триггеры для проверки kernel-багов на PS5 (14.22 и ниже)

Пять безопасных probe-триггеров из `recon/kernel-bug-hunt-1422.md`. Каждый пишет лог
в `/data/kexpl-<имя>.log` (fallback `/tmp`) и возвращает exit-код 0 (отрицательно) / 2 (положительно).

| ELF | syscall'ы | Что проверяет | Позитивный маркер |
|---|---|---|---|
| `t1_aio_wait_race.elf` | 661/663/666 | инвариант id-таблицы AIO multi-wait (вектор Relapse) | `DOUBLE-CANCEL-ACCEPTED` |
| `t2_aio_del_reuse.elf` | 662 | идемпотентность `aio_multi_delete` (вектор Prolapse; в 14.20 закрыт) | повторный delete вернул 0 |
| `t3_umtx_shm.elf` | 454 | refcount UMTX_OP_SHM (FreeBSD-SA-24:14) | `REFCOUNT-UNDERFLOW` |
| `t4_ip6_msfilter.elf` | 105 | гонка IPV6_MSFILTER (FreeBSD-SA-26:29) | `LAYOUT-ACCEPTED` + поведение под нагрузкой |
| `t5_aio_poll_abuse.elf` | 663/664/665 | валидация userland-указателей в Sony-AIO | `VALIDATION-GAP` |

## Сборка

```bash
make clean && make all && make verify      # freestanding gcc (как собрано здесь)
make clean && make PS5=1                   # через ps5-payload-dev SDK (нужен clang-18/lld-18)
```

Freestanding-режим: `gcc -nostdlib -static -no-pie`, никакой libc/libkernel, все вызовы — raw `syscall`.
ELF64 ET_EXEC, elfldr его грузит (`elfldr.c:172-178`). Учитывайте: **elfldr не обнуляет `.bss`**
(`data_load` = memcpy p_filesz), поэтому триггеры инициализируют всё нужное явно.

## Запуск на консоли

```bash
nc <PS5_IP> 9021 < t3_umtx_shm.elf
# лог: ftpsrv (1337) или shsrv (telnet 2323):
#   cat /data/kexpl-t3-umtx-shm.log
```

Порядок: `t5` → `t2` → `t1` → `t3` → `t4` (от самого безопасного к самому «шумному»).
