# 14.22: эмулятор userland-кода PS5 без консоли — AVX снят, PRX грузятся

Статус: **шаг 1 (AVX) закрыт с цифрами; шаг 2 (PRX + мок-слой по NID) реализован;
шаг 3 (исполнение реального модуля) доведён до точной причины, почему нельзя
больше ~24k инструкций без runtime-загрузчика.**

Предыдущий результат (task-6): `tools/emu/emu.py` на Unicorn 2.1.4 исполнял
23 726 инструкций eboot.elf и умирал на AVX-инструкции `vmovups ymm0,[rsp+0x40]`
по адресу `0xcb0c5c` (`UC_ERR_INSN_INVALID`).

Артефакты этой задачи:

| файл | что внутри |
|---|---|
| `tools/emu/qemu_harness.c` | загрузчик PS5-образа как Linux-процесса + резолвер импортов по NID + моки + трамплины-счётчики |
| `tools/emu/qemu_harness` | собранный бинарник харнесса (PIE) |
| `tools/emu/prx.py` | загрузчик SCE/PRX-модулей: парсинг ELF/PHDR/DYNAMIC, карта загрузки, импорты по NID, мок-слой, раскладка в Unicorn |
| `tools/emu/run_qemu.sh` | воспроизводимый прогон: манифест → сборка → QEMU TCG с подсчётом инструкций |
| `tools/emu/avx_probe.c` | проба AVX2 на хосте и под QEMU |
| `tools/emu/output/imports.tsv` | 930 импортов eboot: `stub -> GOT -> library:NID` (из реестра проекта) |
| `tools/emu/output/run-qemu-mock.out` | прогон QEMU, все импорты — моки, **23 992 инструкции** |
| `tools/emu/output/run-qemu-mock-ptr.out` | моки возвращают указатель на нулевую кучу |
| `tools/emu/output/run-qemu-mock-vtable.out` | + fake-vtable: 24 022 инструкции, SIGTRAP |
| `tools/emu/output/run-qemu-realnid.out` | реальный резолв 878/930 импортов → падение в первой же реальной функции |
| `tools/emu/output/prx-libc.prx.out` | libc.prx: 104 импорта, 100 с реальной реализацией |
| `tools/emu/output/prx-libScePfs.prx.out` | libScePfs.prx: 16 импортов, 5 с реальной реализацией |
| `tools/emu/output/avx-probe.out` | сравнение декодеров Unicorn vs QEMU TCG |

---

## 1. Сводка прогонов (подтверждено экспериментом)

| # | Движок / режим | Старт | Инструкций в образе | Где и почему остановился |
|---|---|---|---|---|
| 1 | Unicorn 2.1.4 (task-6) | `0x70` (entry) | **23 726** | `UC_ERR_INSN_INVALID` на `0xcb0c5c` = `vmovups ymm0,[rsp+0x40]` (AVX) |
| 2 | **QEMU TCG 10.2.2**, все импорты — моки | `0x70` | **23 992** | AVX исполнен; далее SIGSEGV `rip=0x1d8d48ebebd0ffef` |
| 3 | QEMU, моки возвращают указатель на кучу | `0x70` | 23 992 | то же — причина не в конкретном возврате |
| 4 | QEMU, моки + fake-vtable в глобалах | `0x70` | **24 022** | SIGTRAP `rip=0x1`; импортов вызвано 10 |
| 5 | QEMU, **реальный резолв по NID** (878/930) | `0x70` | 11 | SIGSEGV внутри `libc.prx:bzQExy189ZI` (addr=0) — нет runtime anyps5 |

Инструкции считаются как число строк `Trace` в логе QEMU с
`-one-insn-per-tb -d exec -dfilter 0x0+0xafb7470` (фильтр оставляет только
код образа PS5, отсекая лоадер/моки/стек).

## 2. AVX-ограничение снято (шаг 1)

**Unicorn 2.1.4** (на нём стоит `emu.py`): SSE исполняет, AVX/AVX2/EVEX — нет:

```
SSE  movaps xmm0,[rsp]        (0f 28 04 24)          -> ОК
AVX  vmovups ymm0,[rsp]       (c5 fc 10 44 24 40)    -> UC_ERR_INSN_INVALID
AVX2 vpxor ymm0,ymm0,ymm0     (c5 fd ef c0)          -> UC_ERR_INSN_INVALID
EVEX vmovups zmm0,[rsp]       (62 f1 7c 48 10 04 24) -> UC_ERR_INSN_INVALID
```

**QEMU user-mode TCG 10.2.2** (`qemu-x86_64`) AVX2 считает верно:

```
нативно (i5-12400F):  sum=396 d0=3.500000
qemu-x86_64:          sum=396 d0=3.500000
```

И главное — на **реальном коде PS5**: в прогоне №2 инструкция по адресу
`0xcb0c5c` (`c5 fc 10 44 24 40`, та самая) **исполнилась** (1 попадание в
Trace-логе). То есть барьер «Unicorn не умеет AVX» снят сменой движка:
`qemu-x86_64 -B <guest_base> -one-insn-per-tb -d exec -dfilter …`.

Для запуска кода как процесса понадобился харнесс `qemu_harness.c`:
* разложил 5 PT_LOAD eboot по `p_vaddr` через `mmap(MAP_FIXED)` (192.6 МБ;
  в QEMU с `-B 0x4000000000` доступна даже страница 0, поэтому старт с `0x70`,
  а не только с `main`);
* нашёл те же 930 PLT-заглушек и пропатчил их слоты GOT на 32-байтные
  трамплины: `inc dword [log]` + (`mov rax,fn; jmp rax` | `xor eax,eax; ret`);
* дал стек 8 МБ, argc/argv, TLS;
* обработал SIGSEGV/SIGILL/SIGBUS/SIGFPE **без libc** (после подмены FS нельзя
  звать glibc) и вывел регистры + трассу импортов.

## 3. Реальный резолв импортов по NID работает (шаг 2, ключевая находка)

В проекте (`anyps5/libs/*.prx`) лежат **Linux-разделяемые библиотеки**, у которых
экспорты названы **NID** (`nm -D libkernel.prx | head`: `04AjkP0jO9U`, …).
Реестр `cyberpunk2077.registry.json` даёт для каждой PLT-заглушки
`callSites/stub -> targetOffset/GOT -> nid + library`. Сопоставив это, харнесс
через `dlopen`+`dlsym` резолвит импорты в **настоящие функции** anyps5:

```
[h] PLT-заглушек найдено: 930
[h] манифест импортов: 930 записей (output/imports.tsv)
[h] импортов: 930 всего; резолвлено в реальные функции anyps5: 878,
    моков (вернут 0): 52, без манифеста: 0
[h] библиотек anyps5 открыто: 34
```

Топ-библиотек в импортах eboot: libSceAgc.prx 191, libc.prx 166,
libkernel.prx 151, libSceNpCppWebApi.prx 89, libSceAmpr.prx 60.
Не нашлось `.so` только для `libREDGalaxy64.prx` (лежит в `app0/modules`).

Но прогон №5 падает на **первом же** вызове реальной функции
(`libc.prx:bzQExy189ZI`): `SIGSEGV addr=0` внутри .so. Причина: библиотеки
anyps5 — это уже **реализация системного слоя**, они рассчитаны на свой
runtime (свои глобалы, контекст, регистрацию модулей), а мы вызываем их из
«сырого» процесса.

## 4. Точная причина, почему прогон всё равно ~24k инструкций

Хвост трассы прогона №2 (последние инструкции перед SIGSEGV):

```
0x00c9b6b6: mov qword ptr [rip+0x778e6d3], rax   ; глобал 0x8456d90 = результат вызова
...
0x00c7fa5a: mov rax, qword ptr [rip+0x77d735f]   ; rax = *(0x8456dc0) — глобальный объект
0x00c7fa61: lea r13, [rip+0x77d7358]
0x00c7fa68: mov rdi, r13
0x00c7fa6b: call qword ptr [rax+0x40]            ; <- падение: [rax+0x40] = мусор
```

Код PS5 после инициализации вызывает методы через **глобальный объект**, который
в настоящей системе заполняет загрузчик/ядро (у anyps5 — его собственный
runtime: `Aps5CallGuestEntry_nid_no_patch`, `AmmGiveDirectMemory_nid_no_patch`,
`__aps5_set_module_init_result_nid_no_patch` — эти символы реально есть в
экспортах `anyps5/libs/libkernel.prx`). Мок, возвращающий 0/указатель, этот
объект не создаёт; подложенная fake-vtable даёт всего +30 инструкций (прогон №4),
потому что таких объектов/полей много и они семантические, а не «вернуть 0».

Итог по критерию задачи: **>100k инструкций не достигнуто**, но причина
зафиксирована точно и не является ни AVX, ни ISA: **нужен bootstrap
PS5-загрузчика (procparam + инициализация libc/libkernel-состояния)**.

Варианты (по возрастанию усилий):
1. **Bootstrap anyps5-runtime**: загрузить `libkernel.prx` и вызвать его
   `Aps5CallGuestEntry`-подобный путь (то, что делает сам anyps5), предварительно
   отдав ему образ eboot через `AmmGiveDirectMemory`. Фактически это повторное
   использование загрузчика anyps5 — самый короткий путь к реальному userland.
2. **Свой загрузчик SCE**: распарсить `DT_SCE_PROCPARAM`/`DT_SCE_MODULE_PARAM`,
   создать структуры модулей (module info, libc-глобалы, TLS-блок процесса) и
   только потом прыгать на entry. Это то, что делает ядро PS5 при старте eboot.
3. **Не эмулировать, а исполнять нативно** (путь anyps5): в `anyps5-run` есть
   готовый нативный ELF `cyberpunk2077` (170 МБ) и отчёт: 33 020 кадров,
   22.09 fps — этот же eboot уже реально работает на ПК, только через
   перекомпиляцию/релинк, а не через эмулятор.
4. QEMU **system**-режим с ядром PS5 — не вариант: ядра нет, PUP зашифрован,
   модели платы Oberon в QEMU нет (см. `recon/emulation.md`, §3.1).

## 5. PRX-модули: загрузка + мок-слой (шаг 3)

`prx.py` на реальных модулях дампа игры:

| модуль | размер | e_type | entry | PT_LOAD | регионы | импорты | из них real |
|---|---|---|---|---|---|---|---|
| `sce_module/libc.prx` | 1 352 554 | `0xfe18` (ET_SCE_DYNAMIC) | `0x0` | 5 | 3 (1.32 МБ) | **104** | **100** |
| `sce_module/libScePfs.prx` | 1 381 071 | `0xfe18` | `0x0` | 5 | 3 (1.35 МБ) | **16** | **5** |

`libc.prx` (PHDR: `PT_LOAD r-x 0..0xccc12`, `r-- 0xd0000..`, `rw- 0x110000..`,
`PT_TLS`, `PT_SCE_MODULE_PARAM 0x113e68`, `PT_DYNAMIC 0x146038`, `PT_SCE_COMMENT`,
`PT_SCE_VERSION`); DYNAMIC 43 тега, включая SCE-специфичные
`0x61000017`(×2), `0x61000019`(×3), `0x6100003d/3f/41/43`, `0x61000045`(×3),
`0x61000047`(×2), `0x61000049`(×3).

Что делает `prx.py`:
1. парсит ELF64-модуль (заголовок, PHDR, DYNAMIC) — без SCE-специфичного SDK;
2. строит карту загрузки: 3 объединённых региона с правами `--x / r-- / rw-`;
3. берёт импорты модуля из реестра
   (`cyberpunk2077.libc.prx.guest.prx.registry.json`: `nid/library/targetOffset`)
   и для каждого проверяет наличие **реальной** реализации в `anyps5/libs/<lib>`
   (по имени символа = NID, через чтение `.dynsym` .so — работает без запуска);
4. создаёт мок-слой: `MockImport` с счётчиком вызовов и трассой
   (`NID, библиотека, GOT-слот, real/mock`);
5. раскладывает образ в Unicorn и патчит GOT-слоты на шимы
   (libc.prx: 104 слота, libScePfs.prx: 16).

Особенность: у `.prx`-модулей PS5 `e_entry = 0` и нет обычной точки входа —
исполнение начинается через экспорт/`module_start`-механизм ядра, поэтому
«просто прыгнуть в модуль» нельзя; для прогона модуля нужен тот же
bootstrap-загрузчик, что и в §4.

## 6. Воспроизведение

```bash
cd ps5jb/tools/emu
# 1) AVX на двух движках:
gcc -O1 -mavx2 -o /tmp/avx_probe avx_probe.c && /tmp/avx_probe
qemu-x86_64 /tmp/avx_probe
python3 emu.py                      # Unicorn: упрётся в AVX (output/run.out)

# 2) QEMU TCG с моками импортов (930 шт.) и подсчётом инструкций:
./run_qemu.sh                       # ~20 c, печатает число инструкций и AVX-попадание
./run_qemu.sh --real-nid            # реальный резолв в anyps5 libs
./run_qemu.sh --vtable              # + fake-vtable

# 3) PRX-модули:
python3 prx.py --elf /home/oleg/Документы/ps5semulator/games/cyberpunk/anyps5-run/sce_module/libc.prx
python3 prx.py --elf /home/oleg/Документы/ps5semulator/games/cyberpunk/anyps5-run/sce_module/libScePfs.prx
```

## 7. Что нужно, чтобы прогнать userland 14.22, когда он появится

1. Собрать манифест импортов из нового реестра (формат тот же:
   `relocationType=R_X86_64_JUMP_SLOT`, `callSites`, `targetOffset`, `nid`,
   `library`) — это делает `run_qemu.sh`; харнесс сам находит PLT-заглушки.
2. Проверить, что под новую прошивку есть `anyps5/libs/<library>.prx`
   (или пересобрать их из anyps5) — иначе импорт уйдёт в мок и поведение
   станет фиктивным (ровно то, что мы видим в прогоне №2).
3. Реализовать bootstrap-загрузчик (§4, вариант 1 или 2) — без него реальный
   userland после ~24k инструкций упирается в неинициализированный глобальный
   объект, а не в эмулятор.
4. AVX больше не ограничение: QEMU TCG 10.2.2 исполняет AVX/AVX2 (проверено и
   синтетикой, и реальной инструкцией eboot `0xcb0c5c`). Unicorn для userland
   14.22 не годится.