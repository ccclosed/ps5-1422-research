# Как разрабатывать эксплойты PS5 без консоли — методичка

> Задача: task-7. Машина: Nobara Linux 44, x86_64, пользователь `oleg` (root НЕТ), 199 ГБ свободно на `/home`.
> Сеть: прямой HTTPS режется DPI (`curl https://api.github.com/` → **http=403**), работает SOCKS5:
> `curl -x socks5h://127.0.0.1:10810 ...` → **http=200**; для `git`/`gh`/`pip` нужен `export HTTPS_PROXY=socks5h://127.0.0.1:10810`.
> Дата прогонов: 2026-11-11. Всё ниже либо выполнено на этой машине, либо помечено `[НЕ ПРОВЕРЕНО]`/`[НЕ ДОСТУПНО]`.

## 0. Правило доказательности (как читать этот файл)

1. **Проверено** = команда выполнена здесь, ниже приведён её фактический вывод (иногда сокращённый).
2. **Ссылка проверена** = получен HTTP-код (указан).
3. **`[НЕ ПРОВЕРЕНО]`** = метод описан, но не запускался (обычно не хватает root/JDK/времени).
4. Никаких «известно, что…» без источника: утверждения сообщества даны с атрибуцией (`по данным <репозиторий/файл>`).

## 1. Baseline: что реально есть на машине

```bash
for t in rizin rz-bin radare2 r2 ghidra ghidraRun bindiff binwalk qemu-x86_64 \
         qemu-system-x86_64 gdb lldb objdump readelf nm strings file afl-fuzz \
         clang gcc cmake ninja make node python3 pip3 cargo git gh curl wget jq unzip 7z xz; do
  p=$(command -v "$t" 2>/dev/null); printf "%-20s %s\n" "$t" "${p:-MISSING}"; done
```

Фактический результат (сокращённо):

| Есть | Чего нет |
|---|---|
| `qemu-x86_64`, `qemu-system-x86_64` (QEMU 10.2.2) | `rizin`, `radare2`, `rz-bin`, `ghidra`, `ghidraRun` |
| `objdump`, `readelf`, `nm`, `strings`, `file` | `bindiff`, `binwalk`, `afl-fuzz` |
| `gcc`, `make`, `lldb`, `node v24.18.0`, `python3 3.14.7` | `clang`, `cmake`, `ninja`, `gdb`, `patchelf`, `strace` |
| `git`, `gh` (залогинен как `ccclosed`), `curl`, `wget`, `jq`, `7z`, `xz`, `cargo` | root-права (установка системных пакетов закрыта) |

Python-пакеты (важно: RE-стек уже стоит):
```bash
python3 -m pip list | grep -iE "unicorn|capstone|pwntools|keystone"
# capstone  5.0.9
# unicorn   2.1.4
```
Проверка доступности остальных через pip (скачивание колес, статус **OK**):
`python3 -m pip download --no-deps -d /tmp/pipdl <pkg>` →
`qiling 1.4.6`, `keystone-engine 0.9.2`, `pwntools 4.15.0`, `lief 1.0.0`, `ropgadget 7.7`, `pyelftools 0.33`, `capstone 5.0.9`, `unicorn 2.1.4`.

Практический вывод: **всё необходимое либо уже стоит, либо ставится в `$HOME` без root**:
- rizin — статический релиз (раздел 2.1);
- Ghidra — tarball + свой JDK 21 (раздел 2.4);
- питон-стек — `pip install --user`;
- отсутствие `clang`/`afl-fuzz` — единственный настоящий барьер (раздел 3.4).

## 2. (а) Статический анализ и дифф прошивок

### 2.1 rizin без root — рабочий статический анализатор

Установка (всё в `$HOME`/`/tmp`, root не нужен):
```bash
curl -x socks5h://127.0.0.1:10810 -L -o /tmp/rizin.tar.xz \
  https://github.com/rizinorg/rizin/releases/download/v0.9.1/rizin-v0.9.1-static-x86_64.tar.xz
# http=200 size=137626404 time=35.2
mkdir -p /tmp/rizin-dl && tar -xJf /tmp/rizin.tar.xz -C /tmp/rizin-dl
export PATH=/tmp/rizin-dl/bin:$PATH
rz-bin -v
# rz-bin 0.9.1 @ linux-x86-64
# commit: c3a90e9226d977f58f4e9c75f78fa6b07afe13c7
ldd bin/rz-bin   # «не является динамическим исполняемым файлом» → статика, ничего не тянет
```

Реальный объект: `games/cyberpunk/anyps5-run/eboot.elf` (155 014 364 байт) — ELF игрового eboot PS5:

```bash
file games/cyberpunk/anyps5-run/eboot.elf
# ELF 64-bit LSB x86-64, version 1 (FreeBSD)

readelf -hW games/cyberpunk/anyps5-run/eboot.elf
# OS/ABI: UNIX - FreeBSD; Type: OS-specific (fe10); Machine: x86-64
# Entry: 0x70; Program headers: 14; Number of section headers: 0

rz-bin -I games/cyberpunk/anyps5-run/eboot.elf | sed 's/\x1b\[[0-9;]*m//g'
# arch x86, bits 64, os freebsd, subsys freebsd, static true, va true, stripped true
# WARNING: Number of sections is 0 → секций нет, работаем только по PT_LOAD
```

Карта сегментов (это ключ ко всем пересчётам, см. раздел 5):
```bash
readelf -lW games/cyberpunk/anyps5-run/eboot.elf
# LOAD off 0x004000 va 0x0         filesz 0x6e10c3c  E   align 0x4000   ← .text
# LOAD off 0x6e18000 va 0x6e14000 filesz 0xee7d79   R   align 0x4000   ← .rodata
# LOAD off 0x7d00000 va 0x7cfc000 filesz 0x53dc70   RW  align 0x4000   ← .data
# LOAD off 0x8240000 va 0x823c000 filesz 0x1bef98   RW  align 0x4000
# LOAD off 0x83fff20 va 0xa12ff20 filesz 0xe87550        align 0x4000
# DYNAMIC off 0x9286840 va 0xafb6840 (OS-specific; libs загружаются динамически)
```

Дизассемблирование и поиск гаджетов (работает на 155-МБ файле за десятые доли секунды):
```bash
rizin -2 -q -c "pd 4 @ 0x11494" games/cyberpunk/anyps5-run/eboot.elf
# 0x00011494  pop rax
# 0x00011495  ret
# 0x00011496  int3
# 0x00011497  int3
```

Свой сканер байт-паттернов с пересчётом offset→VA (лежит в проекте, `ps5jb/recon/_src/tools/scan_gadgets.py`):
```bash
python3 ps5jb/recon/_src/tools/scan_gadgets.py
# LOAD off=0x4000 va=0x0 filesz=0x6e10c3c X
# ...
# pop_rax;ret          hits=8  file=0x6803 va=0x2803 | file=0x15494 va=0x11494 | ...
# pop_rdi;ret          hits=8  file=0x66e06 va=0x62e06 | ...
# pop_r8;ret (REX.RXB) hits=8  file=0x6802 va=0x2802 | ...
# mov [rdi],rax;ret    hits=8  file=0xf5f3 va=0xb5f3 | ...
```
Плюс счётчик syscall-сайтов (чтобы оценить, сколько кода вообще говорит с ядром):
```bash
python3 - <<'EOF'
import mmap
f=open('games/cyberpunk/anyps5-run/eboot.elf','rb'); mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
n=0; i=mm.find(b'\x0f\x05'); first=[]
while i!=-1:
    n+=1
    if len(first)<3: first.append(i-0x4000)
    i=mm.find(b'\x0f\x05',i+1)
print('syscall sites:',n,'first VAs:',[hex(x) for x in first])
EOF
# syscall sites: 2688 first VAs: ['0xa1e8', '0x19e45', '0x19f1b']
```

### 2.2 Дифф бинарей: `rz-diff` вместо Bindiff

Демонстрация на двух сборках (`gcc -O1`, изменена одна константа 0x41414141→0x41414142):
```bash
gcc -O1 -o /tmp/jdiff/a /tmp/jdiff/a.c && gcc -O1 -o /tmp/jdiff/b /tmp/jdiff/b.c
rz-diff -d myers -j /tmp/jdiff/a /tmp/jdiff/b
# {"similarity":0.998413,"distance":40}
```
Боевой пример — две версии реального payload PS5 (`kstuff-lite 1.1` vs `1.2`):
```bash
cd ps5jb/tools/payload/payloads
rz-diff -d myers -j kstuff-lite-1.1-dr.elf kstuff-lite-1.2-dr-test2.elf
# {"similarity":0.975378,"distance":51636}
# размеры: 1 527 064 → 1 558 040 байт
```
`rz-diff` умеет `myers / leven / lcs-roll / ssdeep`; на нашей сборке `-d ssdeep` для этой пары вывел пусто (короткий файл/сигнатура не строится) — используем myers/leven.

**Bindiff**: проприетарен, требует IDA → `[НЕ ДОСТУПНО]` (нет ни IDA, ни лицензии). Бесплатный аналог `Diaphora` тоже требует IDA. Полноценная замена при работе без IDA — `rz-diff` + Ghidra headless + свои скрипты сопоставления функций (адрес → первые N байт/константы).

### 2.3 Дифф прошивок: что реально можно и нельзя

**Нельзя**: скачанные PUP-образы зашифрованы. Проверено на головах PUP (первые 64 МБ, файлы `ps5jb/fw/r64-*.bin`):
```bash
xxd -l 64 ps5jb/fw/r64-1420-2026_1014.bin
# 534c 4232 0300 0000 ... 5053 3555 5044 4154 4531 2e50 5550  → «SLB2», v3, «PS5UPDATE1.PUP»
python3 - <<'EOF'   # энтропия 1 МиБ
import math, collections
for f in ["r64-1410-2026_0928.bin","r64-1420-2026_1014.bin"]:
    d=open(f,"rb").read(1<<20); c=collections.Counter(d); n=len(d)
    print(f, f"{(-sum((v/n)*math.log2(v/n) for v in c.values())):.3f} бит/байт")
EOF
# r64-1410…: entropy(1MiB)=8.000 bits/byte
# r64-1420…: entropy(1MiB)=8.000 bits/byte
```
8.000 бит/байт = шифртекст/сжатие: **побайтовый дифф содержимого PUP без ключей бессмысленен**. Сравнивать можно только заголовки (версию/серийник):

| Файл (голова PUP) | magic | ver | 0x08 | 0x0c | size@0x10 | серийник @0x20/0x24 | имя |
|---|---|---|---|---|---|---|---|
| r64-1410-2026_0928 | SLB2 | 3 | 0x10000 | 1 | 2 463 688 | 0x4b2f8a3d00000002 | PS5UPDATE1.PUP |
| r64-1420-2026_1014 | SLB2 | 3 | 0x10000 | 1 | 2 472 826 | 0x4b76ee5d00000002 | PS5UPDATE1.PUP |
| r64-q-2026_1027  | SLB2 | 3 | 0x10000 | 1 | 2 472 834 | 0x4b76fe7d00000002 | PS5UPDATE1.PUP |

**Можно**: диффить расшифрованные образы. Публичный дамп ядра 13.60 (получен командой проекта, лежит в `ps5jb/fw/`):
```bash
ls -la ps5jb/fw/ps5-kernel-13.60-live.bin
# 103 546 880 байт
cd ps5jb/fw && sha256sum -c ps5-kernel-13.60-live.bin.sha256
# ps5-kernel-13.60-live.bin: ЦЕЛ   (OK)
strings -a ps5jb/fw/ps5-kernel-13.60-live.bin | grep -oE "W:/Build/[A-Za-z0-9_]+" | sort -u
# W:/Build/J03950001
strings -a -n 12 ps5jb/fw/ps5-kernel-13.60-live.bin | grep -oE "modules/[a-z0-9_]+" | sort -u
# 12 модулей: a53mm ajm deci5s gc mp1 mp4 ppr_pfs_proto sbl trace transactionfs utils wlan
```
Это сырой блоб памяти (нет ELF-заголовка: `rz-bin -I` → `bintype N/A`, но `bits 64`), поэтому анализатору надо задавать базу вручную (`rizin -a x86 -b 64 -m 0xffffffff80000000 …`) либо резать по известным диапазонам.

Итог по диффу прошивок:
- **PUP** — только метаданные/хэши/версии (см. `ps5jb/recon/pup-format.md`, `ps5jb/recon/1422-exists.md`);
- **ядро/модули** — только при наличии расшифрованных дампов: 13.60 есть (`kernel-dumps.md`, 35 КБ, с sysent-таблицей), 14.10/14.20/14.22 нет;
- между прошивками сравнивать имеет смысл **списки модулей, sysent-границы, строки** (`strings` + `sort`), а не байты.

### 2.4 Ghidra: ставится без root, но нужен JDK 21

Проверено (HTTP + размеры):
```bash
curl -sS -x socks5h://127.0.0.1:10810 -o /tmp/ghidra.zip -L \
  https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip
# http=200 size=569712708
unzip -q ghidra.zip -d /tmp/ghidra         # 879 МБ распакованного
```
Запуск headless на **этой** машине:
```bash
/tmp/ghidra/ghidra_12.2_PUBLIC/support/analyzeHeadless /tmp/ghproj proj1 -import /tmp/jdiff/a
# WARNING: JAVA_HOME environment specifies unsupported java version: /usr/lib/jvm/java-25-openjdk
# ERROR: Unable to prompt user for JDK path, no TTY detected.
```
Голая `java` здесь — **OpenJDK 25**, Ghidra 12.2 её не принимает; каталог `/usr/lib/jvm/java-21-openjdk` присутствует, но пустой (нет `bin/java`). Решение без root — свой JDK 21:
```bash
curl -x socks5h://127.0.0.1:10810 -o /tmp/jdk21.tar.gz -L \
 "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.13%2B9/OpenJDK21U-jdk_x64_linux_hotspot_21.0.13_9.tar.gz"
# проверено: api.adoptium.net/v3/assets/latest/21/... → http=200, файл 207 858 352 байт
mkdir -p ~/opt && tar -xzf /tmp/jdk21.tar.gz -C ~/opt
JAVA_HOME=~/opt/jdk-21.0.13+9 ~/opt/ghidra_12.2_PUBLIC/support/analyzeHeadless /tmp/ghproj p2 -import <file>
```
`[НЕ ПРОВЕРЕНО]` — headless-анализ с JDK 21 (загрузка JDK была в процессе). Достоверно проверено только: Ghidra 12.2 скачивается, распаковывается и **отказывается работать на JDK 25**.
Полезное из репозитория 14.10 для Ghidra: `ps5jb/recon/_src/zz/repo/tools/ghidra/` — `LabelRetainedSysent.java`, `ImportRetainedData.java`, `prepare_sysent_map.py` (скрипты разметки sysent для headless).

### 2.5 binwalk / прочее

`binwalk` отсутствует (`command -v binwalk` → MISSING); ставится как `pip install --user binwalk` `[НЕ ПРОВЕРЕНО]`, для ELF/PUP-голов он не нужен: магии хватает `xxd` + `readelf`. `readelf/objdump/strings` работают с FreeBSD-ELF корректно (проверено выше).

## 3. (б) Локальные сборки WebKit/JSC и фаззинг компонентов PS5

### 3.1 Что из WebKit есть на машине

```bash
rpm -q webkit2gtk4.1 javascriptcoregtk4.1
# webkit2gtk4.1-2.52.5-1.fc44.x86_64
# javascriptcoregtk4.1-2.52.5-1.fc44.x86_64
ls -la /usr/lib64/libjavascriptcoregtk-4.1.so.0*
# libjavascriptcoregtk-4.1.so.0 -> .so.0.10.13  (33 713 576 байт)  ← движок JSC + рантайм
```
Разработческих заголовков нет, но ABI JavaScriptCore C стабилен. В проекте уже собран минимальный `jsc`-shell
(`ps5jb/tools/jsc-lab/jsc`, 23 632 байта, gcc + `-l:libjavascriptcoregtk-4.1.so.0`), проверка:
```bash
ps5jb/tools/jsc-lab/jsc -e 'print("hello from system JSC " + (1+2)); print(typeof gc);'
# hello from system JSC 3
# function
```
Т.е. **JS-движок, живущий на PS5, есть локально**: можно исполнять/мутировать JS и ловить падения, не имея консоли.

### 3.2 Насколько локальный JSC соответствует консольному

- Консольный WebKit — ветка **605.1.15** (по данным сообщества; см. `ps5jb/recon/webkit-vector.md`, 26 КБ).
- Хостовый — WebKitGTK **2.52.5** (существенно новее). Это значит: локально воспроизводятся *механики* (UAF-классы, reclaim, GC-поведение), но **не** конкретные CVE старого форка — их фиксы в 2.52.5 уже есть.
- Важное подтверждение публичными данными — JIT на PS5 выключен. Проверено HTTP-кодом и содержимым:
```bash
curl -x socks5h://127.0.0.1:10810 -o /tmp/opts.cmake \
  https://raw.githubusercontent.com/WebKit/WebKit/main/Source/cmake/OptionsPlayStation.cmake
# http=200 size=16891
grep -nE "Turn off JIT|ENABLE_(JIT|FTL_JIT|DFG_JIT)" /tmp/opts.cmake
# 175: # Turn off JIT
# 176: WEBKIT_OPTION_DEFAULT_PORT_VALUE(ENABLE_JIT PRIVATE OFF)
# 177: WEBKIT_OPTION_DEFAULT_PORT_VALUE(ENABLE_FTL_JIT PRIVATE OFF)
# 178: WEBKIT_OPTION_DEFAULT_PORT_VALUE(ENABLE_DFG_JIT PRIVATE OFF)
```
Следствие для методики: локальный `jsc` надо запускать **без JIT** (сборка WebKitGTK обычно тоже с JIT — это надо учитывать; интерпретаторный режим задаётся опцией `--useJIT=false` у настоящего `jsc`, у нашего шелла такой ручки нет `[НЕ ПРОВЕРЕНО]`, можно добавить в `jsc.c`).

### 3.3 Полноценная сборка WebKit из исходников

Нужны: `clang`, `cmake`, `ninja`, питон-обвязка, много места. На машине **ни одного из clang/cmake/ninja нет** (проверено `command -v`), root нет. Значит:
- `[НЕ ДОСТУПНО]` в текущем окружении без установки компилятора;
- обход №1: `pip install --user cmake ninja` (колеса существуют — проверено `pip download`), но WebKit официально требует **clang**; gcc-сборка JSC не поддерживается;
- обход №2 (дешёвый и рабочий): prebuilt-библиотека JavaScriptCore из WebKitGTK (раздел 3.1) + свой шелл;
- обход №3: официальные nightly-сборки WebKit (для Linux) `[НЕ ПРОВЕРЕНО]`;
- обход №4: `npx playwright install webkit` (Node v24 есть) даёт готовый WebKit-браузер для JS-фаззинга `[НЕ ПРОВЕРЕНО]`.

### 3.4 Фаззинг JS-движка локально

В репозитории 14.10 есть готовый инструмент, рассчитанный именно на PC-запуск JSC:
```bash
head -30 ps5jb/recon/_src/zz/repo/tools/jsc_mutate.py
# «Mutate JavaScriptCore regression tests and run them under the local jsc.
#  Every run is a fresh `jsc` process. A finding is an ASAN report, a signal exit,
#  or a timeout; the mutated source is written next to the report …
#  python tools/jsc_mutate.py --jsc ~/webkit-7617/WebKitBuild/Debug/bin/jsc \
#      --src results/webkit/corpus/jsc_src --iterations 40 --jobs 4»
```
Т.е. схема: взять публичные регрессионные тесты JSTests (они проверяют недавно исправленные пути) → мутировать → прогнать под локальным `jsc` → падения/ASAN сложить в корпус.

Что нужно, чтобы это заработало у нас:
```bash
ps5jb/tools/jsc-lab/jsc -e 'print(1)'        # движок работает (проверено)
# но: в клоне нет каталога с тестами (results/webkit/corpus/... не публикуется),
#     а ASAN-сборки нет (нет clang) → без ASAN ловим только сигналы/таймауты.
```
Практичный фаззинг без ASAN/root: Python-цикл «мутация → `jsc file.js` с таймаутом → запись кода возврата/сигнала». Живой аналог из репозитория: `tools/webkit_crash_corpus.py` (сбор публичных crash-тестов), `tools/jsc_fuzz_pages.py`, `tools/jsc_struct_mutate.py`.
AFL/`afl-fuzz` — отсутствует, для сборки нужен clang → `[НЕ ДОСТУПНО]`.
`lldb` есть — им удобно разбирать падения хостового JSC локально (без консоли).

## 4. (в) Эмуляция подсистем (Unicorn / Qiling / QEMU)

### 4.1 Unicorn 2.1.4 — рабочий пример на реальном eboot

Скрипт в проекте: `ps5jb/recon/_src/tools/emu_demo.py` (раскладывает PT_LOAD реального `eboot.elf`, запускает код с точки входа, демонстрирует хук syscall).
```bash
python3 ps5jb/recon/_src/tools/emu_demo.py
# unicorn 2.1.4, PT_LOAD в eboot: 5
#   PT_LOAD va=0x0 size=0x6e11000 -> mapped
#   PT_LOAD va=0x6e14000 size=0xee8000 -> mapped
#   PT_LOAD va=0x7cfc000 size=0x53e000 -> mapped
#   PT_LOAD va=0x823c000 size=0x1ef4000 -> mapped
#
# [1] реальный код eboot: точка входа 0x70
#   [entry] инструкций=7 RIP=0x1000007a (останов: Invalid memory read (UC_ERR_READ_UNMAPPED))
#
# [2] самотест хука syscall: mov rax,0x22a; syscall; ret (getpid)
#   [selftest] syscall rax=0x22a rdi=0x0 rsi=0x0 rdx=0x0
#   [selftest] инструкций=3 RIP=0x0
```
Что это доказывает: (1) образ PS5 можно разложить в память на PC и **реально исполнять код** (7 инструкций с entry до первого обращения по несуществующему адресу — ожидаемо, т.к. эмулятор не поднял окружение ядра); (2) перехват `syscall` и подмена возврата работают (`rax=0x22a` = getpid) — значит можно эмулировать нужные syscall-контракты и изучать userland-логику без PS5.
Ограничение: для 155-МБ образа разумно грузить только `.text` и нужные страницы, а не весь образ (скорость).

### 4.2 QEMU user-mode: Linux — да, FreeBSD/PS5 — нет

```bash
qemu-x86_64 --version | head -2
# qemu-x86_64 version 10.2.2 (qemu-10.2.2-1.fc44)
qemu-x86_64 -h | head -2
# usage: qemu-x86_64 [options] program [arguments...]
# Linux CPU emulator (compiled for x86_64 emulation)

qemu-x86_64 /bin/echo hi
# hi                                     ← Linux-бинарь работает

qemu-x86_64 ps5jb/tools/jsc-lab/jsc -e 'print("qemu-user ok "+(40+2))'
# qemu-user ok 42                        ← Linux ELF под эмуляцией работает

qemu-x86_64 -strace games/cyberpunk/anyps5-run/eboot.elf; echo "exit=$?"
# (пусто) exit=1                         ← FreeBSD-ELF PS5 отвергнут молча
```
То же для настоящих payload-ELF PS5 (`ET_DYN`, osabi FreeBSD), по одному файлу и со `-strace`:
```bash
cd ps5jb/tools/payload/payloads
for f in *.elf; do python3 - "$f" <<'EOF'
import sys,struct; d=open(sys.argv[1],'rb').read(64)
print(sys.argv[1], "type=0x%04x osabi=%d machine=%d phnum=%d" % (*struct.unpack_from("<H",d,16), d[7], struct.unpack_from("<H",d,18)[0], struct.unpack_from("<H",d,56)[0]))
EOF
done
# elfldr-ps5-v0.27.elf   type=0x0003 osabi=9 machine=62 phnum=4
# kstuff-lite-1.1-dr.elf type=0x0003 osabi=0 machine=62 phnum=4   (и остальные 5 — так же)
qemu-x86_64 -strace ./elfldr-ps5-v0.27.elf; echo "exit=$?"    # пусто, exit=1
```
Причина: `qemu-x86_64` — это **linux-user** (его собственный help: «Linux CPU emulator»); FreeBSD-ABI не поддерживается, `qemu-*-bsd-user` в системе нет (`ls /usr/bin/qemu-*bsd*` → пусто). Вывод: **QEMU user-mode для PS5-кода неприменим**, для исследования годится как «другой Linux-эмулятор» (например, гонять хостовые бинари в другом окружении) — не более.

### 4.3 QEMU full-system и публичный проект ядра

`qemu-system-x86_64` установлен. По данным `ps5jb/recon/kernel-dumps.md` (§5) существует публичный проект **R0nov4/ps5-kernel-qemu**, который поднимает дамп ядра 13.60 под QEMU — это единственный известный «полноценный» путь эмуляции уровня ядра. Проверять/запускать его надо отдельной задачей; здесь фиксируем: инфраструктура для этого на машине есть (`qemu-system-x86_64`), дамп ядра — тоже (`ps5jb/fw/ps5-kernel-13.60-live.bin`, sha256 совпадает).

### 4.4 Qiling

Пакет доступен (`qiling-1.4.6-py3-none-any.whl` — проверено `pip download`), ставится `pip install --user qiling`; но Qiling эмулирует **Linux/Windows/…** через свой rootfs, FreeBSD-гостя из PS5 он не даёт. Годится для отладки userland-кода и syscall-хуков того же типа, что в 4.1. `[НЕ ПРОВЕРЕНО]` — в этой сессии не запускался (нужен скачиваемый rootfs).

## 5. (г) Пересчёт ROP-гаджетов и смещений между прошивками

### 5.1 Две базовые формулы (проверены на реальном ELF)

1) файл ↔ виртуальный адрес (по PT_LOAD):
```
va = file_offset - p_offset + p_vaddr
```
Для `.text` этого eboot: `p_offset = 0x4000, p_vaddr = 0` ⇒ **`va = file_offset - 0x4000`**.
Проверка «туда-обратно»: паттерн `58 c3` найден в файле по 0x6803 → VA 0x2803; `rizin pd 4 @ 0x11494` для файла 0x15494 показывает `pop rax; ret`. Совпадает.

2) адрес в рантайме (при известной базе образа):
```
runtime_addr = image_base + va
```
По данным сообщества, eboot грузится в районе `0x5320000000` (`ps5jb/recon/relapse-anatomy.md`), т.е. `pop rax; ret` из примера = `0x5320000000 + 0x11494`.

### 5.2 Что НЕЛЬЗЯ пересчитать простым сложением (главная ловушка)

**Каталог гаджетов привязан к конкретному бинарю.** Каталог из исследования 14.10 (`README`/`CLAUDE.md` репозитория) даёт `pop_rax; ret` = `eboot+0x992`, `pop_rdi` = `+0xC9DFE`, `mov [rdi],rax;ret` = `+0x92C67`. Я проверил эти байты в **нашем** eboot (Cyberpunk 2077) — не совпадают:

| Опубликованный offset (их eboot) | Байты в нашем eboot по этому VA | Совпадение |
|---|---|---|
| `pop_rax;ret @+0x992` | `eb fd` | нет |
| `pop_r8;ret @+0x991` | `85 eb fd` | нет |
| `pop_rdi;ret @+0xC9DFE` | `89 45` | нет |
| `mov [rdi],rax;ret @+0x92C67` | `10 41 f7 dc` | нет |
| `pop_rdx;ret @+0x3B02D7` | `65 8a` | нет |
| `bare ret @+0x42` | `d0` | нет |

Вывод: **чужие `eboot+0x...` нельзя переносить на другое издание игры**. Пересчёт возможен только когда:
- тот же бинарь, но другая база загрузки → `+ (new_base - old_base)`;
- та же игра и та же версия eboot, другая прошивка → **eboot лежит на диске и от прошивки не зависит**: смещения гаджетов в eboot остаются теми же (это сильный аргумент в пользу eboot-only ROP: не ломается обновлением прошивки);
- системные библиотеки (`libkernel`, `.sprx`) и ядро — **per-firmware**, их смещения меняются: брать можно только из дампа конкретной прошивки (для 13.60 дамп есть, для 14.1x — нет).

### 5.3 Проверка кандидатного смещения без консоли (скрипт, которым это делается)

```bash
python3 - <<'EOF'
import mmap
f=open('games/cyberpunk/anyps5-run/eboot.elf','rb'); mm=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)
def foff(va): return va + 0x4000          # первый PT_LOAD: off 0x4000 -> va 0
for va, pat in [(0x992,b"\x58\xc3"), (0x11494,b"\x58\xc3")]:
    got=mm[foff(va):foff(va)+len(pat)]
    print(hex(va), got.hex(), "OK" if got==pat else "MISMATCH")
mm.close(); f.close()
EOF
# 0x992 eb fd MISMATCH
# 0x11494 58c3 OK
```
Так же проверяются: длина/валидность `mov [rdi],rax;ret`, наличие `pop rsi/rdx/rcx/r8` и «мусорные» кандидаты, которых в реальном коде нет.

### 5.4 Что говорит `relapse-offset-dumper` и что нужно для 14.2x

По разбору `relapse-anatomy.md` (46 КБ, §3–4): смещения делятся на (1) `offsets/<fw>.js` для `window.KRW` (ядро: `sysent`thunks, `md_*`, UMTX и т.п.), (2) userland-часть цепочки. Dumper извлекает их **из живой консоли** — т.е. соответствует «Public data заменяют консоль» только если кто-то уже выложил дамп/дамп-offsets. Для 14.22 таких публикаций нет (подтверждено в `1422-status.md`). Практический вывод: ROP-часть можно отлаживать локально (гаджеты в eboot — считаются и проверяются на PC), а вот **рантайм-смещения ядра и системных модулей для 14.2x без дампа получить нечем** — это в списке «нельзя без консоли».

## 6. (д) Какие публичные данные заменяют консоль

| Источник / артефакт (в проекте) | Объём / проверка | Что даёт |
|---|---|---|
| Игровой `eboot.elf` (`games/cyberpunk/anyps5-run/`) | 155 014 364 байт; `readelf` → ELF64 FreeBSD, type 0xfe10, entry 0x70, 14 PT | реальный код PS5: статический анализ, ROP-гаджеты, syscall-сайты (2688 шт.) |
| Публичный дамп ядра 13.60 (`ps5jb/fw/ps5-kernel-13.60-live.bin`) | 103 546 880 байт; sha256 `c3f745e2…` совпадает; 12 модулей; build `W:/Build/J03950001` | единственный публичный «снимок» ядра: строки, модули, sysent-разбор (`kernel-dumps.md`) |
| Payload-ELF PS5 (`ps5jb/tools/payload/payloads/`) | 7 файлов: elfldr 394 568, kstuff-lite 1 527 064/1 558 040, websrv 1 597 864, ftpsrv 192 432, klogsrv 136 016, shsrv 986 184; все `ET_DYN`, x86-64 | образцы реального PS5-userland: дизасм, дифф версий (`rz-diff`), шаблоны для локальной сборки |
| WebKit-источник (public) | `OptionsPlayStation.cmake` http=200, 16 891 байт | настройки PS5-порта (JIT/DFG/FTL OFF), поведение движка |
| JS-движок локально (WebKitGTK 2.52.5) | `jsc`-шелл работает | фаззинг/мутации JS без консоли |
| Репозиторий 14.10 (клон в `ps5jb/recon/_src/zz/repo`) | 458 МБ; 58 фаз, 3 328 probe-файлов (2 931 Lua / 66 JS / 329 HTML), 4 453 result-файла, 210 docs, 126 tools | 100 % методологии и наблюдений: syscall-контракты, WebKit-корпус, sysent-карта, dead ends |
| PUP-образы (`ps5jb/fw/*.PUP`, r64-*.bin) | 1 266 091 008 байт + 3×64 МБ голов; SLB2, энтропия 8.000 | версии/метаданные прошивок (`1422-exists.md`, `pup-format.md`); содержимое зашифровано |
| Отчёты команды | `relapse-anatomy.md` 46 КБ, `1422-status.md` 41 КБ, `kernel-dumps.md` 35 КБ, `webkit-vector.md` 26 КБ, `1422-exists.md` 20 КБ, `lua-vector.md` 19 КБ | проверенные первичные источники и таблицы «этап → что нужно → есть ли» |

Проверка «hardware-free CI» репозитория 14.10 на нашей машине:
```bash
cd ps5jb/recon/_src/zz/repo && python3 tools/verify_offline.py
# Ran 356 tests in 4.961s
# OK (skipped=3)
```
Это доказывает: значительная часть валидации исследования **не требует консоли** — её можно воспроизвести у нас (и это готовый шаблон для нашего CI).

## 7. (е) Чего нельзя проверить без консоли — честный список

1. **Kernel R/W как факт.** Всё, что делает примитив полезным (чтение/запись памяти ядра, стабильность, ASLR-слайд), проверяется только на живой PS5. Локально — только статика дампа 13.60 (и он не 14.x).
2. **KASLR per-boot.** Слайд меняется каждую загрузку; без консоли не измерить. Публичные дампы дают лишь один снимок.
3. **Гипервизор.** Его поведение (W^X ниже ядра, XOM, SMAP) локально не воспроизводится ни QEMU, ни Unicorn. По `relapse-anatomy.md` §3.3 — это принципиальная граница.
4. **W^X / XOM / SMAP в этой прошивке.** Проверяются только пробами на устройстве (по данным 14.10: `mprotect(EXEC)` всегда -1; XOM у системных библиотек).
5. **Реальные контракты Sony-syscall'ов** (аргументы, коды ошибок, «слот отсутствует» vs «handler упал»). По 14.10 это измерялось пробами; локально — только догадки по строкам дампа.
6. **Поведение драйверов `/dev/*` и ioctl.** Нужен живой процесс с открытыми нодами (34/76 на 14.10).
7. **Timing-каналы** (mprotect/clock_gettime и т.п.) — шум и разрешение проверяются только на железе.
8. **Доступность вектора входа** (Lua-загрузчик через сохранение, порт 9026; WebKit-браузер) — нужен экземпляр игры/браузера на консоли.
9. **Статус «закрыто/не закрыто» в 14.2x для конкретной CVE** — публичных подтверждений нет (`1422-status.md`); без консоли не проверить, только догадки по дампам (а дампа 14.2x нет).
10. **Скорость/пробивная способность цепочки** (сколько проб на соединение, таймауты) — измеряется только в бою.
11. **Сборка ASAN-JSC/WebKit** — не «консоль», а окружение: без clang/root полноценная инструментальная сборка у нас недоступна (см. 3.3). Это ограничение машины, а не PS5.

## 8. Как организовано исследование 14.10 (ZigZagBoi1/PS5-14.10-Research) → чеклист для нас

Клон: `ps5jb/recon/_src/zz/repo` (последний коммит `3926da7`, PR #249), 458 МБ, лицензия CC BY-NC 4.0.

**Структура и масштаб (посчитано командами):**
```bash
ls -d probes/*/ | wc -l          # 58 фаз
find probes -type f | wc -l      # 3 328 проб (2 931 Lua, 66 JS, 329 HTML)
find results -type f | wc -l     # 4 453 снятых результата
ls docs | wc -l                  # 210 документов
ls tools | wc -l                 # 126 инструментов
```
**Ключевые элементы организации:**
- **Фазовая раскладка** `probes/phaseN_*` (58 фаз) + зеркальные `results/phaseN_*`; одна проба = один файл, один прогон = один capture.
- **Леджер доказательств**: `results/STATE.md` (переписывается, последний замер) + `results/INDEX.md` (append-only, по строке на прогон), оценки достоверности `M/S/I/V/D` (измерено/из источника/вывод/пусто/тупик. Правило: «отрицательный результат без capture не существует»).
- **Протокол сессии**: перед каждой пробой — `grep -rn "<номер/тема>" results/ docs/ probes/` и строка `-- prior art:` в заголовке; без неё пробу не отправляют.
- **Шаблон пробы**: `-- CRASH_CLASS: LOW|MODERATE|HIGH|RISKY`, стандартные helper'ы (`make_syscall`, `safe_rd/wr`, `to_num`), запрет `goto` (Lua 5.1), всё под `pcall`.
- **Мультиагентность**: `swarm/` — `swarm.py` (10 027), `agents.py` (36 103), `task_queue.py`, `dashboard.py`, `ps5_connection.py`, `ps5_recovery.py` (автовосстановление консоли), `ai_client.py`, `config.py`.
- **Неинтерактивная консоль**: `tools/console_control/` (управление через Remote Play) + `tools/browser_battery/`, `browser_runner/` (прогон JS/HTML кейсов на устройстве).
- **Hardware-free CI**: `tools/verify_offline.py` — проверено у нас: 356 тестов, 4.96 с, OK (skipped=3); плюс 22 тест-модуля.
- **Ghidra-скрипты** (`tools/ghidra/`): `LabelRetainedSysent.java`, `ImportRetainedData.java`, `prepare_sysent_map.py` — разметка sysent по дампу 13.60.
- **Дампер 13.60**: `tools/v1360-dumper/` (C-payload + приёмник) — как получают образ ядра, если есть консоль.
- **Документация для машин и людей**: `docs/ALL_PROBES.md` / `docs/ALL_RESULTS.md` (склейка всего для LLM), `AGENT_PROMPT.md`, `AI_HANDOFF_PROMPT.md`, `CLAUDE.md` (правила для ИИ), `docs/PROGRESS_AUDIT.md` + `docs/progress.json` (рубрика 65/100), `CHANGELOG.md` (фазы 1–25+ с датами).
- **Публикация**: всё выкладывается (осознанный отказ от bug bounty), PR-модель (последний merge — PR #249), 25 CVE-разборов в `docs/`.

**Чеклист для нас (что повторить без консоли, а что нет):**

| № | Действие | Без консоли? | Команда/файл |
|---|---|---|---|
| 1 | Поставить rizin static и завести `scan_gadgets.py` | да | §2.1; `ps5jb/recon/_src/tools/scan_gadgets.py` |
| 2 | Снять карту PT_LOAD/секций для своего eboot и зафиксировать формулу `va=off-0x4000` | да | `readelf -lW` |
| 3 | Собрать свой каталог гаджетов (не брать чужие смещения) | да | §5.2–5.3 |
| 4 | Поставить локальный `jsc` (WebKitGTK) и прогнать JS-мутации | да | `ps5jb/tools/jsc-lab/jsc`, §3.1 |
| 5 | Поднять Unicorn-эмуляцию `.text` + хук syscall | да | `ps5jb/recon/_src/tools/emu_demo.py` |
| 6 | Разобрать дамп ядра 13.60 (строки, модули, sysent) | да | §2.3; `kernel-dumps.md` |
| 7 | Сравнить версии payload-ов и прошить дифф-workflow (`rz-diff`) | да | §2.2 |
| 8 | Взять публичный корпус проб/результатов 14.10 и прогнать их офлайн-валидатор | да | `python3 tools/verify_offline.py` |
| 9 | Собрать свой «hardware-free CI» (unittest на артефакты, без сети) | да | по образцу `verify_offline.py` |
| 10 | Собрать WebKit/JSC с ASAN (нужен clang) | нет (нет root/clang) | §3.3 |
| 11 | Получить/диффить образ ядра 14.2x (нужен дамп с консоли) | нет | §2.3, §7 |
| 12 | Проверить W^X/XOM/SMAP, KASLR, контракты syscall на 14.2x | нет | §7 |
| 13 | Проверить доступность вектора входа (Lua 9026 / WebKit) | нет (нужна игра/браузер на PS5) | §7 |

## 9. Сводка «можно/нельзя» одной таблицей

| Работа | Без консоли | Чем |
|---|---|---|
| Дизасм/гаджеты/строки PS5-ELF | ✅ | rizin static, readelf, свой сканер |
| Дифф ELF-версий | ✅ | `rz-diff -d myers/leven` |
| Анализ дампа ядра 13.60 | ✅ | `strings`/rizin base, `kernel-dumps.md` |
| JS-фаззинг движка | ✅ (без ASAN) | WebKitGTK `jsc` + мутации |
| Эмуляция userland-кода | ✅ | Unicorn (проверено), Qiling (поставить) |
| Полноценная сборка WebKit | ❌ (нет clang/root) | — |
| Дифф прошивок по содержимому | ❌ (PUP зашифрован) | только заголовки |
| Kernel R/W, KASLR, гипервизор, syscall-контракты | ❌ | только живая PS5 |

## 10. Приложение: артефакты, созданные этой задачей

- `ps5jb/recon/no-console-methods.md` — этот документ.
- `ps5jb/recon/_src/tools/scan_gadgets.py` — сканер паттернов PS5-ELF с offset↔VA (проверен).
- `ps5jb/recon/_src/tools/emu_demo.py` — Unicorn-эмуляция реального eboot + хук syscall (проверен).
- `ps5jb/recon/_src/zz/repo/` — клон исследования 14.10 (458 МБ, для офлайн-разбора).
- Внешние бинарники (в `/tmp`, не в проекте): rizin 0.9.1 static, Ghidra 12.2 (879 МБ), JDK21-загрузка.