# PS5: публичные дампы/образы ядра — разведка

Статус: **завершено 2026-11-11**. Машина: Linux Nobara, root нет, сеть через `socks5h://127.0.0.1:10810` (проверено: прямой `api.github.com` отдаёт 403, через socks — 200).
Write-scope: `ps5jb/recon/`, `ps5jb/fw/`.

## 0. TL;DR

1. **Публичный дамп ядра PS5 13.60 СУЩЕСТВУЕТ и скачан/проверен.** Это не ELF, а live-RAM слепок (flat binary):
   `terrafirma2021/ps5-13.60-kernel-dump` → `kernel-13.60-live.bin.gz` (23 286 602 B) → 103 546 880 B,
   SHA-256 `c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd` — совпал с заявленным в репозитории.
   Внутри — настоящий код/данные FreeBSD-ядра Sony: строки `SIE CONFIDENTIAL`, `r229358/releases/13.60 Jul 17 2026 02:16:29 amd64`,
   `Copyright (c) 1992-2016 The FreeBSD Project.`, x86-64 код (см. §3).
2. **Второй публичный набор того же ядра 13.60** — `ZigZagBoi1/PS5-V13.60-Research/docs/dumps_13.60/`: `kernel_text.bin` (15 132 096 B),
   `sysent_raw.bin` (32 592 B = 679×48), `sysent_index.json`, `sysent_area.bin`, `ucred.bin`, манифест с base `0xffffffff8a9c0000`.
   Побайтовая сверка с (1): первые 15 132 096 B совпадают, кроме 4 байт; 5 543 qword-а отличаются ровно на KASLR-сдвиг `0x13a30000`;
   таблица sysent нормализованно совпадает 677/679 → **тот же билд 13.60** (см. §4).
3. **Готового decrypted kernel ELF (а также `kernel.prx`) в публичном доступе НЕТ.** ELF, собранный из дампа, у `R0nov4/ps5-kernel-qemu`
   (62.2 MiB, sha256 `e87dbe64…`) явно помечен «not in this archive» → скачать нельзя; собирается локально из дампа (1)
   скриптом `build_kernel.py`/`fetch_and_build.sh` этого же репозитория (см. §5).
4. **Ядро из PUP не расшифровано публично**: PUP-записи шифруются, ключи не публичны (проверки — в `recon/pup-format.md`, отдельная задача).
   `kernel.prx`/модули PS5 требуют console-bound расшифровки; публичных наборов не найдено (поиск в §6).
   Это же прямо подтверждают исследователи 14.10 в issue #239: «the 14.10 PUP is encrypted with a universal container key held
   by the security processor, so the kernel … cannot be extracted on PC» (§13).
5. **Другие прошивки**: публичных *дампов* ядра 12.xx/13.20/14.10 не найдено — есть только **инструменты**, снимающие дамп
   с джейлбрейкнутой консоли (Gl0ttis 13.20, Wigglez-sudo 12.00–12.70, ZigZag native dumper 13.60, kdump_ps5 и др. — §7).
   Автор 14.10-исследования сам пишет: аутентифицированного 14.10 kernel-образа нет (цитата в §6).
6. Практический вывод для проекта: для анализа sysent/офсетов и QEMU-экспериментов **можно законно опираться на дамп 13.60 (1)**;
   файлы положены в `ps5jb/fw/` (§8). Для 14.22/PUP-пути дампов нет — придётся либо снимать с консоли, либо строить по PUP-ключам.
7. **SDK от ps5-payload-dev (`tools/fwsim/vendor/sdk`) — не образ, но ценные kernel-офсеты**: per-FW таблица в `crt/kernel.c`
   (71 `case`, FW 1.00–**14.22**), включая 13.60/14.22: TEXT/DATA base, ALLPROC, ROOTVNODE, SECURITY_FLAGS, VMSPACE-офсеты (§12).
   Для 13.60 SDK-дельта `text→data = 0x0CC0000` совпала с дампом (независимая сверка). Ядрового образа/symbol-map в SDK нет.
   `drakmor/kstuff-lite` и релизы ps5-payload-dev/kstuff — payload'ы/офсеты (3.00–12.70), тоже без образов ядра.
8. **Из дампа извлечены обе таблицы sysent** (`tools/sysent/scanner.py`, §14–§17): compat `+0xe6e5c0` — 677 валидных записей
   (368 nosys, 309 реализованных), native `+0xe76e50` — 735 записей (239 nosys, 496 реализованных). После отката KASLR
   compat-таблица совпала с ZigZag `sysent_raw.bin` **677/677** (в файле 679×48 — 2 хвостовые записи оказались не-sysent),
   а счётчики native/compat совпали с CSV ZigZag (735/239/496 и 677/368/309). SDK-дельта `text↔data = 0x0CC0000` сошлась
   с дампом бит-в-бит; ucred-смещения SDK подтверждены на реальных байтах. Результат: `fw/sysent-13.60.json`.

## 1. Что искали

Расшифрованный образ ядра PS5 (FreeBSD-производное «Orbis/Prospero» ядро Sony): `kernel.elf`, `kernel.prx`,
dump ядра из RAM консоли — либо доказательство отсутствия таковых в публичном доступе.
Критерий приёмки: ссылка + размер + версия прошивки + доказательства магии (`file`, `readelf`, `strings`, хэши).

## 2. Методика и доступ

- GitHub REST: `gh api search/code`, `search/repositories` (аккаунт `ccclosed`, авторизован; токен в keyring).
  `gh` ходит напрямую к api.github.com — работает (проверено `gh api user` → `ccclosed`).
- Скачивание файлов: `curl -x socks5h://127.0.0.1:10810` (raw.githubusercontent.com через DPI-обход).
- Локальные проверки: `file`, `xxd`, `strings`, `gzip -t`, `sha256sum`, `python3` (разбор sysent), `objdump`.
- Внешние сайты: archive.org API, web.archive.org, psxhax.com, psdevwiki.com, huggingface API — HTTP-коды в §6.

## 3. Находка №1 — публичный дамп ядра PS5 13.60 (основной)

**Источник:** https://github.com/terrafirma2021/ps5-13.60-kernel-dump (public, default branch `main`,
updated 2026-11-07; описание «PS5 13.60 live kernel memory capture»).
Состав (GitHub tree API): `README.md` 1 400 B, `kernel-13.60-live.bin.gz` 23 286 602 B, `kernel-13.60-live.bin.json` 1 043 B.

**Скачано (2026-11-11), проверка:**

```
$ curl -x socks5h://127.0.0.1:10810 -L -o kernel-13.60-live.bin.gz \
    https://raw.githubusercontent.com/terrafirma2021/ps5-13.60-kernel-dump/main/kernel-13.60-live.bin.gz
$ ls -l kernel-13.60-live.bin.gz
-rw-r--r-- 1 oleg oleg 23286602 ... kernel-13.60-live.bin.gz
$ sha256sum kernel-13.60-live.bin.gz
77c6010ef52269f3b451783ae9853d34ee82e15473dec2015884b79386f5370f  kernel-13.60-live.bin.gz
$ gzip -t kernel-13.60-live.bin.gz && echo 'GZIP OK'
GZIP OK
$ gzip -dc kernel-13.60-live.bin.gz > kernel-13.60-live.bin
$ stat -c%s kernel-13.60-live.bin
103546880
$ sha256sum kernel-13.60-live.bin
c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd  kernel-13.60-live.bin
$ file kernel-13.60-live.bin
kernel-13.60-live.bin: data          # НЕ ELF — это ожидаемо: raw live-RAM слепок, а не decrypted ELF
$ readelf -h kernel-13.60-live.bin
readelf: Ошибка: Не ELF-файл — он содержит неверные magic-байты в начале   # ELF-заголовка нет by design
$ file kernel-13.60-live.bin.gz
kernel-13.60-live.bin.gz: gzip compressed data, original size modulo 2^32 103546880
```

SHA-256 и размер **точно совпали** с заявленными в README/JSON репозитория
(`...bin.json`: `"size": 103546880`, `"sha256": "c3f745e2…d78cddd"`, `"firmware": "13.60"`).

**Раскладка (из `kernel-13.60-live.bin.json`, проверена по содержимому):**

| Регион | File offset | Размер | Виртуальный адрес (снят с консоли) |
|---|---:|---:|---|
| Kernel text | `0x0` | 13 369 344 (`0xcc0000`) | `0xffffffff9e3f0000` |
| Kernel data | `0xcc0000` | 90 177 536 | `0xffffffff9f0b0000` |
| (дыры) | — | 688 немаппированных страниц, залиты нулями | диапазон `0xffffffffa4400000–a46b0000` |

**Доказательства, что это именно ядро Sony/FreeBSD 13.60** (`strings`, смещения в файле):

```
$ for s in 'SIE CONFIDENTIAL' 'FreeBSD ELF64' 'r229358/releases/13.60' 'mDBG: Kernel Build ID = %lx' \
           'Copyright (c) 1992-2016 The FreeBSD Project.'; do grep -abo -m1 "$s" kernel-13.60-live.bin; done
19558995:FreeBSD ELF64
19700917:mDBG: Kernel Build ID = %lx
27803456:r229358/releases/13.60 Jul 17 2026 02:16:29
28115440:SIE CONFIDENTIAL
28115512:Copyright (c) 1992-2016 The FreeBSD Project.
```

- `r229358/releases/13.60 Jul 17 2026 02:16:29` — формат build-строки Sony (внутренний релизный путь), дата сборки;
- **независимая сверка раскладки**: `data_base − text_base = 0xffffffff9f0b0000 − 0xffffffff9e3f0000 = 0x0CC0000` — ровно столько же,
  сколько в публичном SDK от ps5-payload-dev для 13.60 (`case 0x13600000: KERNEL_ADDRESS_TEXT_BASE = KERNEL_ADDRESS_DATA_BASE - 0x0CC0000`,
  см. §12) — две независимые публичные базы сходятся;
- `SIE CONFIDENTIAL` + `SIE`-copyright — баннер ядра Sony;
- `FreeBSD ELF64`, `Copyright (c) 1992-2016 The FreeBSD Project.` — FreeBSD-происхождение;
- `mDBG: Kernel Build ID = %lx` — формат лога ядра PS5;
- Все эти строки лежат в data-регионе (offset > `0xcc0000`), а не в начале файла — поэтому их нет в первых мегабайтах (см. §4).

**Код валиден как x86-64** (начало файла — реальный код ядра, не мусор):

```
$ xxd -l 64 kernel-13.60-live.bin
00000000: e86b 5d4f 0000 0000 0000 0000 0000 0000  .k]O............
00000010: 5548 89e5 5348 83ec 1848 8d1d f0c2 9103  UH..SH...H......
00000020: 488b 0348 8945 f048 8d05 b2dc a901 66c7  H..H.E..f..H...
$ objdump -D -b binary -m i386:x86-64 --start-address=0x10 --stop-address=0x40 kernel-13.60-live.bin
  10: 55                    push   %rbp
  11: 48 89 e5              mov    %rsp,%rbp
  14: 53                    push   %rbx
  15: 48 83 ec 18           sub    $0x18,%rsp
  19: 48 8d 1d f0 c2 91 03  lea    0x391c2f0(%rip),%rbx
  20: 48 8b 03              mov    (%rbx),%rax
  ...
```

**Что это НЕ такое:** README честно пишет: «It is **not** an ELF file or a bootable kernel image», «not a decrypted nested PUP kernel.bin».
Это слепок живой RAM (text+data одного бута), пригодный для Ghidra/IDA и для реконструкции образа.

## 4. Находка №2 — второй публичный слепок того же ядра 13.60 + таблица sysent

**Источник:** https://github.com/ZigZagBoi1/PS5-V13.60-Research — каталог `docs/dumps_13.60/`
(README: «Raw kernel data dumps extracted from a jailbroken PS5 on firmware 13.60 using Relapse + Byepervisor»,
base = `0xffffffff8a9c0000` — **другой KASLR-слайд**, чем у (1), т.е. другой бут/сессия).

Состав (GitHub tree) и наши проверки:

| Файл | Размер, B | SHA-256 (скачано и проверено) |
|---|---:|---|
| `kernel_text.bin` | 15 132 096 | `406ab210236d4123e06495bcc8da82d8f89dac07266558dc8c0f80cc6cf55cf1` |
| `kernel_data.bin` | 4 194 304 | `e46b98aa2155b29d33de3b11582a31051900f192058acaa10517e934dc2c5e46` |
| `sysent_area.bin` | 65 536 | `a4308ef3987180dcfeec2f8f3aa8680383c736efe0a817e3d1be50edce2633f5` |
| `sysent_raw.bin` | 32 592 | `fa12c87b6eedfee857a6721c2128fdb7406aee8c150dbdfd43983102e9d5f236` |
| `ucred.bin` | 256 | `58ebb419e71a396094018d9dc418dc29273f2629c834ab218401b985aa9f9d82` |
| `sysent_index.json` | 80 795 скачано | ⚠ `2262291b…` — см. «расхождения» ниже |
| `kernel_base.json` | 56 | `{"firmware":"13.60","kernel_base":"0xffffffff8a9c0000"}` |
| `kernel_dump_manifest.json` | 475 | 3 диапазона: text `0x0+0xe6e5c0`, data `0x1000000+0x400000`, sysent_area `0xe6d5c0+0x10000` |

Все хэши, кроме `sysent_index.json`, совпали с внутренним аудитом репозитория
(`docs/audits/2026-10-18-dump-reconciliation.md`, таблица SHA-256). `sysent_index.json` в аудите указан как
84 874 B / `9db4cf65…`, а в репозитории лежит 80 795 B — **расхождение в метаданных**, но наш парсер проверил:
скачанный индекс внутренне согласован с `sysent_raw.bin` (679 записей, 0 расхождений).

**Таблица sysent (проверено нами, не только на слово):**

- `sysent_raw.bin` = 32 592 B = 679 × 48 — точное совпадение, stride 48 B;
- структура: `sy_narg` int32 @+0, `sy_call` ptr64 @+8 (у всех 679 записей поле +8 — валидный указатель в диапазоне ядра);
- пример: syscall 532 → `narg=5`, `sy_call=0xffffffff8ac25ce8` = base `0xffffffff8a9c0000` + `0x265ce8` — совпадает с README;
- `nosys`-стаб встречается **368 раз** (один и тот же адрес), уникальных обработчиков 301 → «активных» 679−368=311 (как в README);
- RVA таблицы `+0xe6e5c0` (=15 132 096) — ровно длина `kernel_text.bin`, таблица начинается сразу за ним (манифест: area с `+0xe6d5c0`, т.е. за 4 KiB до таблицы); это согласовано между всеми файлами;
- `sysent_index.json` парсится в 679 записей: `narg`, `sy_call`, `sy_call_off`; наш пересчёт из raw дал **0 расхождений**.

**Перекрёстная проверка (1)↔(2) — доказывает один и тот же билд 13.60:**

```
первые 15 132 096 B файла (1) vs kernel_text.bin (2):
  различающихся байт: 11 090 (0.073%), все — либо
  * offset 0x8..0xb: `00 00 00 00` (1) vs `41 41 41 41` (2) — метка "AAAA" (артефакт дампера/ручная пометка), единственные 4 отличия ниже 0xcc0000;
  * выровненные qword в data-части (offset ≥ 0xe56fc2): 5 544 шт., из них 5 543 отличаются РОВНО на KASLR-сдвиг
    base(1)−base(2) = 0xffffffff9e3f0000 − 0xffffffff8a9c0000 = 0x13a30000 (релокация при другом слайде), 1 — та самая метка.
  sysent (679×48) нормализованно по base: совпало 677/679; 2 «хвостовых» (677, 678) в ОБОИХ наборах имеют
  мусорный narg, но одинаковые sy_call → одинаковая структура таблицы.
```

Вывод: (1) и (2) — один и тот же образ ядра 13.60 (сборка `r229358/releases/13.60 Jul 17 2026`), снятый при двух разных
KASLR-слайдах (либо (2) сделан из (1) с перебазированием; в любом случае содержимое согласовано и это реальное ядро PS5 13.60).

**Бонус — имена syscall'ов и их назначение (только текстовые артефакты, не образ):**
`docs/SYSCALL_NAME_MAP_13.60.md` (ZigZagBoi1/PS5-14.10-Research): утверждается, что `dumps_13.60/sysent_index.json` — это
**compat (ELF32) таблица** (677 записей, 368 nosys, 309 implemented), а нативная (ELF64) — 735 записей, 239 nosys, 496 implemented;
это заявлено по «full 13.60 kernel dump… 16 391 symbol database», которого в публичном репо нет. Считать «ЗАЯВЛЕНО АВТОРОМ».

**Расхождения/осторожность:**
- `docs/KERNEL_DUMP_ANALYSIS.md` (ZigZagBoi1/PS5-14.10-Research) указывает источник как `zigzagboi1/ps5-13.60-kernel-dump` —
  такого репозитория **нет** (`gh api repos/ZigZagBoi1/ps5-13.60-kernel-dump` → HTTP 404). Файл с тем же размером и SHA-256
  лежит в `terrafirma2021/ps5-13.60-kernel-dump`. Т.е. атрибуция в доках неточная, но публичный артефакт существует и хэш сходится.
- В этих же доках счётчики sysent расходятся между README (311/368) и KERNEL_DUMP_ANALYSIS (308/371) — вероятно, разные таблицы
  (native/compat). Для нас важен сам факт: образ и таблица существуют и проверяемы.

## 5. Находка №3 — публичный QEMU-проект, который ЗАПУСКАЕТ это ядро, и его ELF

**Источник:** https://github.com/R0nov4/ps5-kernel-qemu (upd. 2026-11-11; «Research harness for booting the PS5 (13.60)
kernel in QEMU, reaching complete SYSINIT execution and SceSwapper idle state»).

- `fetch_and_build.sh` **явно скачивает тот же публичный дамп**:
  `URL_PRIMARY="https://github.com/terrafirma2021/ps5-13.60-kernel-dump/raw/main/kernel-13.60-live.bin.gz"`,
  `gzip -dc` → `kernel-13.60-live.bin`, затем `build_kernel.py` реконструирует плоский образ (`kernel_raw.bin`, 65 224 704 B, md5 `520808c9…`).
- В репозитории есть `serial.log` (59 795 B) — лог реального запуска в QEMU. Доказательство, что это настоящее ядро Sony:
  ```
  PS5-TRAMPOLINE: booting 13.60 kernel
  SIE CONFIDENTIAL
  Copyright (c) 1992-2016 The FreeBSD Project.
  r229358/releases/13.60 Jul 17 2026 02:16:29 amd64
  mDBG: Kernel Build ID = 99dd70d51abadddd
  FreeBSD/SMP: Multiprocessor System Detected: 0 CPUs
  ... SceSwapper ...
  ```
  (здесь build ID уже конкретный: `99dd70d51abadddd`; в дампе (1) формат-строка `mDBG: Kernel Build ID = %lx`, т.е. значение подставляется).
- **Реконструированный ELF (62.2 MiB, sha256 `e87dbe643e285d0b59a18c926fc0eb1a20f3157ea99cde6d2e7ade5ea7b17cae`) в публичном доступе НЕТ**:
  README прямо: «The ELF itself … is **not** in this archive». В репозитории нет releases, ассетов и LFS-файлов.
  Его можно получить только локально, прогнав `fetch_and_build.sh` + `build_kernel.py` (скрипты в репо).

## 6. Чего НЕТ: отрицательные результаты (с HTTP-кодами)

| Что проверялось | Как | Результат |
|---|---|---|
| Decrypted kernel ELF (готовый файл) в GitHub | `gh api search/code?q="kernel.elf" ps5`, `q=ps5_kernel_1360_reconstructed.elf`, `q=kernel_raw.bin` | только упоминания/скрипты; **ни одного ELF с ядром PS5**; реконструированный ELF у R0nov4 — «not in this archive» |
| `kernel.prx` (PS5) | `gh api search/code?q="kernel.prx" ps5`, `search/repositories?q=ps5+prx+kernel` | только `libkernel.prx` из PS4 SDK/AnyPS5 и `.cmake`; **публичных decrypted kernel.prx PS5 нет** (0 репозиториев по запросу) |
| Дампи для 14.10 | репо `ZigZagBoi1/PS5-14.10-Research` (121 MB) | сам автор: «a validated 14.10 kernel primitive and verified 14.10 kernel image remain unavailable» (docs/audits/2026-10-18-dump-reconciliation.md); в `docs/dumps_13.60/` — только 13.60 |
| 12.xx/13.20 дампы | repo search `ps5 live kernel dump`, `kimg2 ps5`, `ps5 13.60 kernel`, `ps5 kernel image` | только **инструменты** (Gl0ttis 13.20 — release `ps5-kernel-probe.elf` 113 872 B, dl=4; Wigglez-sudo «PS5 kernel and hypervisor dumper for firmware 12.00 to 12.70»; earthonion/kdump_ps5; maldinipunisher/Fuzz-ps5 `tools/kdump`) — публичных образов в них нет |
| archive.org (items) | `advancedsearch.php?q="PS5" AND kernel` → 24 items; `q=title:(ps5 kernel) OR (ps5 AND "kernel dump")` → 3 items; `q=identifier:"github.com-terrafirma2021*"` → 0 | **дампов нет**; попадаются только снапшоты GitHub-репо (Byepervisor, sharpemu, ps5-linux-loader) и YouTube-новости |
| psdevwiki | `curl https://www.psdevwiki.com/ps5/Kernel` | **HTTP 403** — Cloudflare «Just a moment...» (бот-защита). Обход: `web.archive.org/web/2025/https://www.psdevwiki.com/ps5/Kernel` → **HTTP 200**, 29 402 B (кэш-копия; проверка содержимого — см. §6.1) |
| psxhax | `https://www.psxhax.com/` → **200** (95 793 B), `https://www.psxhax.com/search/?q=PS5+kernel+dump` → **403** (страница логина форума) | поиск без аккаунта недоступен; на главной статьи про китайский kernel exploit/Y2JB, дампов ядра нет |
| HuggingFace | `https://huggingface.co/api/datasets?search=ps5%20kernel` → **200**, `[]` | пусто |
| `relapse-offset-dumper` | `gh api search/code?q=relapse-offset-dumper` → 0; `search/repositories` находит `tidewell/relapse-offset-dumper` (12 KB) | это **инструмент** извлечения kernel-офсетов (7.00–13.60), не дамп |
| `kernel_offsets` | `search/code?q=kernel_offsets+ps5` → 96 результатов | `PS5Dev/PS5SDK/ps5/kernel_offsets/offsets_300..451.h` (PS5 3.00–4.51) — производные офсеты, не образы; публично доступны, полезны для старых FW |
| `0xffffffff8` | `search/code?q=0xffffffff8+ps5` → 2316 | только код инструментов/офсетов, готовых образов нет |
| `sysent` | `search/code?q=sysent+ps5` → 1648 | код эмуляторов/дамперов/анализа (RPCSX sysvec, Byepervisor bn_view, ZigZag-доки) — образов нет |

### 6.1 Что на кэш-странице psdevwiki (архив)
`web.archive.org/web/2025/.../ps5/Kernel` отдаёт 200 и 29 402 B. Полноценно искать по ней не удалось (страница — обзор
архитектуры/списков, дампов как файлов wiki не хранит by design). Вывод: psdevwiki **не является** источником дампов;
это вики по форматам/офсетам.

## 7. Инструменты снятия дампа с консоли (для полноты — что доступно публично)

| Инструмент | FW | Что делает | Проверено |
|---|---|---|---|
| `ZigZagBoi1/PS5-V13.60-Research/native-kernel-dumper/` | 13.60 | `full_dump.c` через `elfldr`: 3 фикс. диапазона, POST на приёмник; в репо — `ps5-full-kernel-dumper.elf` 111 320 B | tree + README |
| `Gl0ttis/ps5-13.20-kernel-dumper` | 13.20 | live kernel memory capture, стрим на хост, SHA-256 | release `ps5-kernel-probe.elf` 113 872 B, dl=4 |
| `Wigglez-sudo/ps5dump-12xx` | 12.00–12.70 | пишет `kimg2`+`hv` дампы на USB | README |
| `R0nov4/ps5-kernel-qemu` | 13.60 | `fetch_and_build.sh` + `build_kernel.py` — сборка QEMU-образа из публичного дампа | скрипты в репо, serial.log с запуском |
| `maldinipunisher/Fuzz-ps5/tools/kdump` | — | `kdump.c`/`kernel_receiver.py` | code search |
| `earthonion/kdump_ps5` | — | «dumps ps5 kernel to usb» | repo search |
| `tidewell/relapse-offset-dumper` | 7.00–13.60 | извлекает kernel-значения для порта Relapse | 12 KB, main.c 29 508 B |

## 8. Артефакты, положенные в `ps5jb/fw/`

Скачано и проверено (хэши в §3–4):

| Путь | Размер | Что это |
|---|---:|---|
| `fw/ps5-kernel-13.60-live.bin.gz` | 23 286 602 | публичный дамп ядра PS5 13.60 (gz), sha256 `77c6010e…f5370f` |
| `fw/ps5-kernel-13.60-live.bin` | 103 546 880 | распакованный слепок, sha256 `c3f745e2…d78cddd` (совпал с заявленным) |
| `fw/ps5-kernel-13.60-sysent/` | ~104 KB | `sysent_raw.bin` (679×48, sha `fa12c87b…`), `sysent_area.bin`, `sysent_index.json`, `kernel_base.json`, `kernel_dump_manifest.json`, README/аудит + `SHA256SUMS` — таблица syscall'ов 13.60, готовая к разбору |
| `fw/ps5-kernel-13.60-live.bin.sha256` | 100 B | контрольная сумма для `sha256sum -c` (значение в §3) |
| `fw/sysent-13.60.json` | 183 578 B | **таблицы sysent, извлечённые из дампа** (§17): compat 677 валидных (RVA +0xe6e5c0, 368 nosys) + native 735 (RVA +0xe76e50, 239 nosys) с абсолютными адресами и RVA |
| `recon/_src/scan-13.60-by-scanner.py.json` | 9 148 B | полный JSON-вывод `tools/sysent/scanner.py` по дампу (§14) |

Проверено после копирования: `sha256sum` файлов в `fw/` совпадают с §3–4; `file … gz` → `gzip compressed data, original size 103546880`.

## 9. Как воспроизвести проверку (для команды)

```bash
cd ps5jb/fw
sha256sum -c ps5-kernel-13.60-live.bin.sha256        # c3f745e2…
grep -abo 'SIE CONFIDENTIAL' ps5-kernel-13.60-live.bin        # 28115440
grep -abo 'r229358/releases/13.60' ps5-kernel-13.60-live.bin  # 27803456
python3 - <<'PY'   # таблица sysent 13.60, base 0xffffffff9e3f0000, RVA 0xe6e5c0
import struct
d=open('ps5-kernel-13.60-live.bin','rb').read(); off=0xe6e5c0
for i in (0,532,676):
    narg=struct.unpack_from('<i',d,off+i*48)[0]; call=struct.unpack_from('<Q',d,off+i*48+8)[0]
    print(i,'narg=',narg,'sy_call=',hex(call),'rva=',hex(call-0xffffffff9e3f0000))
PY
# для QEMU-сборки образа: см. R0nov4/ps5-kernel-qemu (fetch_and_build.sh / build_kernel.py)
```

## 10. Источники (все проверены 2026-11-11)

- https://github.com/terrafirma2021/ps5-13.60-kernel-dump — дамп (основной; README + json + gz)
- https://github.com/ZigZagBoi1/PS5-V13.60-Research — `docs/dumps_13.60/` (kernel_text/data, sysent_*, ucred, base.json, manifest, README, audit)
- https://github.com/ZigZagBoi1/PS5-14.10-Research — `docs/KERNEL_DUMP_ANALYSIS.md`, `docs/SYSCALL_NAME_MAP_13.60.md`, `docs/SYSENT_TAIL_677_734_CONTRACTS_13_60.md`, audit
- https://github.com/R0nov4/ps5-kernel-qemu — fetch_and_build.sh, build_kernel.py, serial.log, README
- https://github.com/Gl0ttis/ps5-13.20-kernel-dumper — release v1.0.0 (probe ELF)
- https://github.com/Wigglez-sudo/ps5dump-12xx, https://github.com/earthonion/kdump_ps5, https://github.com/tidewell/relapse-offset-dumper
- https://github.com/PS5Dev/PS5SDK — `ps5/kernel_offsets/offsets_{300,320,321,402,403,450,451}.h` (производные, не образ)
- archive.org advancedsearch API (запросы в §6), web.archive.org (кэш psdevwiki), psxhax.com, huggingface.co API

## 11. Легенда достоверности

| Метка | Значение |
|---|---|
| `ПОДТВЕРЖДЕНО` | проверено в этой сессии командами/хэшами (§3–5) |
| `ЗАЯВЛЕНО АВТОРОМ` | так написано в репозитории, независимо не проверено (напр. «16 391 symbol database», счётчики native-таблицы) |
| `НЕ НАЙДЕНО` | искали, не нашли (см. §6) |
| `ОПРОВЕРГНУТО` | найдено прямое противоречие (напр. repo `ZigZagBoi1/ps5-13.60-kernel-dump` → 404) |

## 12. Дополнительные проверки по запросу лида: SDK, kstuff, релизы

### 12.1 `tools/fwsim/vendor/sdk` — что там есть (и чего нет)

Локальный `ps5jb/tools/fwsim/vendor/sdk` — это **ps5-payload-dev/sdk** (проверено: `git remote -v` → `https://github.com/ps5-payload-dev/sdk.git`,
HEAD `8816aee4cd88fc47b07819d2b6f4769c095a074b`, 2026-11-08). Содержит:

- FreeBSD-заголовки **releng/11.4** (`include/freebsd/sys/sysent.h`, `sys/sysproto.h`, `machine/vmparam.h` и др.) — т.е. ABI-описание ядра, а **не** его код;
- `include/freebsd/sys/sysent.h` → `struct sysent { int sy_narg; sy_call_t *sy_call; au_event_t sy_auevent; systrace_args_func_t …; u_int32_t sy_entry; sy_return; sy_flags; sy_thrcnt; }`
  → `sizeof = 48 B`, поле `sy_call` на +8 — **точно совпадает со stride 48 и полем +8, найденными нами в дампах (§4)**;
- `include/ps5/kernel.h` — `extern KERNEL_ADDRESS_TEXT_BASE/DATA_BASE/ALLPROC/PRISON0/ROOTVNODE/SECURITY_FLAGS/…` и
  `KERNEL_OFFSET_PROC_P_*`, `KERNEL_OFFSET_UCRED_*`, `KERNEL_OFFSET_FILEDESC_*`, `KERNEL_OFFSET_VMSPACE_*`;
- `crt/kernel.c` (1820 строк) — **per-firmware таблица kernel-адресов**: 71 `case`-метка, диапазон **1.00–14.22**.
  Для **13.60** (`case 0x13600000`): `TEXT_BASE = DATA_BASE − 0x0CC0000`, `ALLPROC = DATA + 0x28C9E80`,
  `SECURITY_FLAGS = DATA + 0x0D9C064`, `ROOTVNODE = DATA + 0x314B510`, `BUS_DATA_DEVICES = DATA + 0x2098228`, VMSPACE offsets `0x1d0/0x2e8`.
  Для **14.00–14.22** (`0x14000000..0x14220000`): `TEXT_BASE = DATA_BASE − 0x0CE0000`, `ALLPROC = DATA + 0x28D9EA0`, `SECURITY_FLAGS = DATA + 0x0DA4064`,
  `ROOTVNODE = DATA + 0x315B510`, `BUS_DATA_DEVICES = DATA + 0x20A8878`;
- `crt/rtld*.c`, `elfldr/` — загрузчики payload'ов (ELF/SELF), **не** образ ядра.

**Чего в SDK НЕТ:** ядрового образа/дампа, symbol-map (`.map`/`.sym`/`vmlinux`/`System.map` — `find` пусто),
двоичной таблицы syscall'ов. `grep 0xffffffff8` по sdk/freebsd/elfldr даёт только `KERNBASE 0xffffffff80000000` в `machine/vmparam.h`.
Вывод: SDK даёт **офсеты и ABI**, но не образ ядра; для 13.60 его числа согласуются с дампом (§3), для 14.22 — офсеты есть (полезно проекту),
но самого ядра 14.22 публично нет.

### 12.2 `drakmor/kstuff-lite` (и `ps5-payload-dev/kstuff`)

- `gh api repos/drakmor/kstuff-lite/releases` → 8 релизов, единственный asset всегда **`kstuff.elf`** (1 524 280–1 558 040 B, dl до 15 742) —
  это payload-модуль, **не** дамп ядра;
- в репо: `freebsd-headers/` (тот же набор заголовков FreeBSD, включая `sys/sysproto.h`), `prosper0gdb/offsets/*.h` —
  **45 per-FW файлов офсетов** для 3.00–12.70 (`offset_list.txt`, `struct offset_table`); 13.xx в lite **нет** (максимум `12_70.h`);
- `ps5-payload-dev/kstuff/releases`: `Payload.zip` 79 014 B / 1 969 088 B (payload'ы), **не** образ ядра;
- `ps5-payload-dev/sdk/releases`: `ps5-payload-sdk.zip` v0.45 8 838 658 B (dl 9 558) — тот самый SDK из §12.1, **не** образ ядра;
- `ps5-payload-dev` прочие репо (elfldr, ftpsrv, gdbsrv, klogsrv, websrv, …) — payload'ы/сервисы, образов ядра нет.

### 12.3 Итог по дополнительным источникам

Все проверенные «ядровые» артефакты в SDK/kstuff/релизах — это **офсеты, заголовки и payload'ы**, а не образы ядра.
Единственные публичные **образы** ядра, найденные за всю разведку, — live-дампы 13.60 из §3–4 (плюс собираемый локально из них
плоский образ/QEMU-ELF проекта R0nov4, §5).

## 13. Issue-трекеры и релизы Relapse-инструментов

### 13.1 `gh api search/issues` (проверено)

| Запрос | Найдено | Релевантное |
|---|---:|---|
| `ps5 "kernel dump"` | 81 | ZigZagBoi1/PS5-14.10-Research **issue #239** (open, 6 комментариев) — см. цитату ниже; ссылок на готовый дамп в issue/комментариях НЕТ |
| `"kernel.elf" ps5` | **0** | — |
| `kernel dump org:ps5-payload-dev` | 2 | `elfldr#5` (kernel panic 10.01), `websrv#1` (ошибка запуска) — к дампам отношения не имеют |

**Ключевая цитата (ZigZagBoi1/PS5-14.10-Research issue #239, open):**
> «the 14.10 PUP is encrypted with a universal container key held by the security processor, so the kernel and WebKit binaries
> cannot be extracted on PC. That blocks offsets, vtables, gadget work and any 13.60→14.10 diff. … We're looking for someone
> with a 13.60 (or lower) console with kernel R/W — Relapse + Byepervisor Reborn — willing to run it once or twice.»

Это прямое подтверждение (со стороны активных исследователей 14.10): **расшифрованного ядра из PUP публично нет**, ключ универсальный,
но живёт в security-процессоре и требует запуска payload'а на джейлбрейкнутой консоли. Согласуется с §6 и с `recon/pup-format.md`.

### 13.2 Релизы Relapse-инструментов (там дампов нет)

| Репозиторий | Релизы/ассеты | Вывод |
|---|---|---|
| `tidewell/relapse-offset-dumper` | **релизов нет** (API `releases` → `[]`) | инструмент: запускается на консоли, пишет `/data/relapse_dump/` (offsets.txt + сырые регионы памяти), передача по FTP; в README прямо: «Raw kernel memory regions — Binary dumps for offline analysis» — т.е. дамп делает сам пользователь на своей консоли |
| `ntfargo/Relapse-Exploit` | релизов нет | эксплойт-чейн, не образ |
| `m2k7m/Relapse-Exploit` | релизов нет | то же |
| `manos555555/Relapse-Exploit` | релизов нет | то же |
| `arg0WAK/WAK1360-Relapse` | 2 релиза (2026-11-08), единственный asset — `sce-hell0.elf` 10 749 264 B | exploit payload для 13.60, **не** дамп ядра |

Итог §13: ни issue-трекеры, ни релизы Relapse-инструментов **не содержат** публичного расшифрованного образа ядра;
максимум — консольные дамперы/офсет-экстракторы, результат которых у каждого свой (на консоли).

## 14. Извлечение sysent из скачанного дампа: прогон `tools/sysent/scanner.py`

Команда (2026-11-11; полный прогон 12.3 s):

```bash
cd ps5jb
time python3 tools/sysent/scanner.py fw/ps5-kernel-13.60-live.bin \
     --base 0xffffffff9e3f0000 --json /tmp/scan1360.json --verbose
```

Вывод (сокращённо):

```
[scanner] layout ps5: 91801 valid record offsets
[scanner] layout ps5-nof: 105639 valid record offsets
[scanner] layout freebsd9: 20012 valid record offsets
[scanner] layout freebsd13: 112284 valid record offsets
image : fw/ps5-kernel-13.60-live.bin
size  : 103546880 bytes (98.75 MiB)
sha256: c3f745e25dc25ee7afef89eb418b295b6334bbefe8aa17e6886483c35d78cddd
base  : 0xffffffff9e3f0000 (raw image load address)

[3] layout=freebsd9 stride=48 entries=735
    file_offset=0xe76e50 vaddr=0xffffffff9f266e50 syscalls=0..734
    score=73530.0 padding_zero_ratio=1.0 null_calls=0
    [0]   narg=0 call=0xffffffff9e655760 ... thrcnt=1
    [734] narg=3 call=0xffffffff9e656500 ... thrcnt=1

[4] layout=freebsd9 stride=48 entries=677
    file_offset=0xe6e5c0 vaddr=0xffffffff9f25e5c0 syscalls=0..676
    score=67730.0 padding_zero_ratio=1.0 null_calls=0
    [0]   narg=0 call=0xffffffff9e655760 ...
    [676] narg=0 call=0xffffffff9e655fa8 ...
```

- Полный машинный вывод (8 найденных таблиц, включая ложные срабатывания) сохранён:
  `recon/_src/scan-13.60-by-scanner.py.json` (9 148 B). Ложные (`ps5-nof` 69 455 @0xcc0038 и др.)
  отброшены по `padding_zero_ratio`/структуре полей — их «narg» вне допустимого для sysent диапазона.
- **Найдены обе настоящие таблицы**: compat `@0xe6e5c0` (**677** записей) и native `@0xe76e50` (**735** записей),
  обе stride 48, layout `freebsd9` (= `struct sysent` FreeBSD 9–12, см. заголовок из SDK в §12.1).
- Сканер сам по себе даёт RVA **+0xe6e5c0** и **+0xe76e50** — независимое подтверждение RVA из README ZigZag (+0xe6e5c0)
  и того, что «679 записей» в `sysent_raw.bin` — это 677 + 2 не-sysent записи (см. §15).

## 15. Сравнение с `fw/ps5-kernel-13.60-sysent/` и ZigZag `sysent_raw.bin` (679×48) — СОВПАЛО

Побайтовое сравнение среза дампа `[0xe6e5c0, +32592)` с `sysent_raw.bin` и нормализация по KASLR-базе:

```python
# база ZigZag: 0xffffffff8a9c0000, база дампа: 0xffffffff9e3f0000, delta = 0x13a30000
compat entries 0..676: ptr-RVA equal: 677 / 677  other-field mismatches: 0  ptr mismatches: 0
differing bytes over 677*48 (only KASLR pointers): 1354 = 677*2
records 677/678: narg differs (both non-sysent), ptr RVA equal: True
byte-identical dump slice vs sysent_raw.bin: False   # и должно быть False: разные KASLR-слайды
```

Итог сравнения:

| Что сравнивалось | Результат |
|---|---|
| 677 записей compat-таблицы (narg, флаги, прочие поля, `sy_call` RVA) | **677/677 совпали**; отличаются ровно 2 байта на каждый указатель — это KASLR-релокация (delta `0x13a30000`), а не расхождение данных |
| Записи 677/678 в `sysent_raw.bin` (679×48) | **не являются sysent**: narg — мусор в обоих источниках (разные значения), `sy_call` RVA совпадает; сканер независимо остановился на 677 записях |
| Native-таблица | в дампе **735** записей, 239 nosys, 496 реализованных — ровно как в CSV ZigZag (`735 / 239 / 496`) |
| Compat-таблица | 677 записей, 368 nosys, 309 реализованных — ровно как в compat-строке ZigZag (`677 / 368 / 309`) |
| Контрольные точки | syscall 532: narg=5, sy_call_off=`0x265ce8` (совпадает и в дампе, и в `sysent_index.json`); syscall 676: narg=0, off=`0x265fa8` |

**Ответ: да, совпало** — после отката KASLR таблица из скачанного дампа 1-в-1 соответствует
`fw/ps5-kernel-13.60-sysent/sysent_raw.bin` (677 валидных записей) и независимо подтверждает счётчики ZigZag (native 735/239/496).

## 16. Сверка с per-FW таблицей SDK для 13.60

SDK `tools/fwsim/vendor/sdk/crt/kernel.c` (`case 0x13600000:` для FW 13.60):

```
KERNEL_ADDRESS_TEXT_BASE        = KERNEL_ADDRESS_DATA_BASE - 0x0CC0000;
KERNEL_ADDRESS_ALLPROC          = KERNEL_ADDRESS_DATA_BASE + 0x28C9E80;
KERNEL_ADDRESS_SECURITY_FLAGS   = KERNEL_ADDRESS_DATA_BASE + 0x0D9C064;
KERNEL_ADDRESS_ROOTVNODE        = KERNEL_ADDRESS_DATA_BASE + 0x314B510;
KERNEL_ADDRESS_BUS_DATA_DEVICES = KERNEL_ADDRESS_DATA_BASE + 0x2098228;
```

**1) Дельта text↔data — точное совпадение:**

```
dump: DATA - TEXT = 0xffffffff9f0b0000 - 0xffffffff9e3f0000 = 0x0CC0000   ✓ (== SDK 0x0CC0000 == размеру text-региона дампа)
```

**2) Содержимое по адресам SDK (в data-регионе дампа, `file_off = 0xcc0000 + (addr − data_base)`):**

| SDK-поле | VA | file_off | qword[0] | qword[1] | Интерпретация |
|---|---|---:|---|---|---|
| `ALLPROC` = DATA+0x28C9E80 | `0xffffffffa1979e80` | `0x3589E80` | `0xffff8e777997d9e0` | `0xffff8e77017e7d80` | пара canonical-указателей `TAILQ_HEAD` (`tqh_first`/`tqh_last`) — как и должно быть у `struct proclist allproc` |
| `ROOTVNODE` = DATA+0x314B510 | `0xffffffffa21fb510` | `0x3E0B510` | `0xffff8e77033bcf00` | `0xffff8e77033a6080` | `vnode`/`mount`-указатели, оба canonical |
| `SECURITY_FLAGS` = DATA+0x0D9C064 | `0xffffffff9fe4c064` | `0x1A5C064` | `0x0100000000000017` | `0x0281a008202` | флаги: +0x09 targetid = `82 00 1a 28`, +0x24 qa_flags = `00 03 01 00`, +0x8C utoken_flags = `01` — осмысленные поля-флаги |
| `BUS_DATA_DEVICES` = DATA+0x2098228 | `0xffffffffa1148228` | `0x2D58228` | `0xffff8e77017db200` | `0xffff8e7701de0a18` | пара canonical-указателей списка |

Указатели ведут в heap/DMAP-подобные регионы (`0xffff8e77…`, `0xffff968f…`, `0xffff8f90…`), которых в дампе нет
(снят только KVA-диапазон text+data), поэтому дальше не разыменовываются — но **формат** содержимого
(canonical-пары в TAILQ-головах, битовые маски флагов) корректен и не противоречит SDK.

**3) Независимая проверка SDK-смещений `struct ucred` по реальным байтам (`ucred.bin`, 256 B из ZigZag):**

```
+0x04 cr_uid       = 0                       +0x08 cr_ruid = 0        +0x0c cr_svuid = 0
+0x10 cr_ngroups   = 1                       +0x14 cr_rgid = 0        +0x18 cr_svgid = 0
+0x30 cr_prison    = 0xffff8f900f6520        (canonical-указатель)
+0x58 cr_sceauthid = 0x4800000000000007       (типичный PS4/PS5 authid)
+0x60 cr_scecaps   = 0x40ff1cffffffffff       (битовая маска caps)
+0x80 cr_sceattrs  = 0x4000400080000000       (битовая маска attrs)
```

Все смещения `KERNEL_OFFSET_UCRED_CR_*` (UID/RUID/SVUID/RGID/SVGID/PRISON/SCEAUTHID/SCECAPS/SCEATTRS) из SDK
**подтверждены на реальных байтах ядра 13.60** (root-креды, канонические указатели, осмысленные authid/caps/attrs).

**Итог §16:** дельта text↔data сошлась бит-в-бит; остальные SDK-смещения для 13.60 ведут в корректные структуры
(подтверждено форматом TAILQ и полной проверкой ucred-полей); полная валидация ALLPROC/ROOTVNODE была бы
возможна только при наличии в дампе heap/DMAP-памяти, которой в capture нет.

## 17. Новый артефакт: `fw/sysent-13.60.json`

Создан скриптом из дампа (183 578 B, JSON): обе таблицы sysent с абсолютными адресами и RVA.

| Поле JSON | Значение |
|---|---|
| `firmware` / `build_string` | `13.60` / `r229358/releases/13.60 Jul 17 2026 02:16:29 amd64` |
| `source` | repo `terrafirma2021/ps5-13.60-kernel-dump`, size 103 546 880, sha256 `c3f745e2…d78cddd` |
| `layout` | text base `0xffffffff9e3f0000`, data base `0xffffffff9f0b0000`, delta `0xcc0000` |
| `sysent_compat` | file_off/RVA `0xe6e5c0`, stride 48, 679 записей в файле (677 валидных), nosys RVA `0x265760` (368), implemented 309 |
| `sysent_native` | file_off/RVA `0xe76e50`, stride 48, 735 записей, nosys 239, implemented 496 |
| `verification` | команда сканера + итог сверки с ZigZag (`677/677` после нормализации) |

Sanity-проверка: `entries[532] = {narg:5, sy_call_off:"0x265ce8", nosys:false}`, native `entries[734] = {narg:3, off:"0x266500"}`.

Проверка целостности всех артефактов (после копирования в `fw/`):

```bash
$ cd ps5jb/fw && sha256sum -c ps5-kernel-13.60-live.bin.sha256
ps5-kernel-13.60-live.bin: ЦЕЛ
$ cd ps5jb/fw/ps5-kernel-13.60-sysent && sha256sum -c SHA256SUMS
sysent_area.bin: ЦЕЛ
sysent_raw.bin: ЦЕЛ
kernel_base.json: ЦЕЛ
kernel_dump_manifest.json: ЦЕЛ
sysent_index.json: ЦЕЛ
```