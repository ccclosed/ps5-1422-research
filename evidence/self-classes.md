# Классификация SELF: что разворачивается, а что нет (атака, не описание)

Статус: task-27. Дата: 2026-11-11. Машина Linux, без root; консоли/ключей нет.
Цель: найти, что именно отличает разворачиваемый SELF от неразворачиваемого, и проверить, не в `key_type` ли дело.
Инструменты: `anyps5/unwrap_self.py` (AnyPS5), `ps5jb/tools/pup/self_probe.py` (наш, до­работан в этой задаче: таблица записей SELF + поиск plaintext ELF + вердикт класса).

## 0. TL;DR — главное

1. **Реальные SELF обоих «успешных» типов добыты из образа игры** `games/cyberpunk/PPSA04029.exfat` (243 ГБ), который сейчас не смонтирован: через `dump.exfat` получены каталоги и FirstCluster, данные вырезаны по карте кластеров (heap 0x1100000, кластер 0x10000). Никакого root не потребовалось.
2. Есть **три класса** (таблица в §2):
   - **A. decrypted SELF с PS4-магией** — `eboot.bin`, `fakelib/*.sprx`: magic-байты `4F 15 3D 1D` (u32 LE `0x1D3D154F`), version=0, attrs=0x12, **key_type=0x101**, header_size=1376, metadata_size=1296, **plaintext ELF @0x1A0, 11 записей**, энтропия сегментов 6.6 → **unwrap_self.py: OK**.
   - **B. decrypted SELF с PS5-магией** — `sce_module/*.prx`, `modules/libREDGalaxy64.prx`: magic-байты `54 14 F5 EE` (u32 LE `0xEEF51454`), version=0, attrs=0x12, **key_type=0x101**, header_size=1376, metadata_size=1552, **plaintext ELF @0x1A0, 11 записей**, энтропия 6.4–6.6 → **unwrap_self.py: OK**.
   - **C. retail-encrypted SELF прошивки** — sys-образ и recovery-`PS5UPDATE2.PUP`: magic-байты **те же `54 14 F5 EE`**, version=16, attrs=0x32, **key_type=4**, header_size 1456/576, metadata 3552/1440, поля 0x10+ — мусор (энтропия = случайной), **plaintext ELF НЕТ, 0 записей** → **unwrap_self.py: FAIL «no inner ELF header»**.
3. **Магия — не дискриминатор**: классы B и C имеют одинаковые байты `54 14 F5 EE`, но противоположный результат.
4. **key_type — тоже не дискриминатор** (для нашего инструмента): у decrypted-файла класса B мы заменили байты `0x04..0x0B` на «как у прошивки» (`10 01 01 32 04 00 00 00`: version=16, attrs=0x32, key_type=4) — **unwrap всё равно успешен, выходной ELF побайтово тот же** (sha256 `e851775b…8060`). Значит дело не в key_type/version/attributes, а в том, **зашифрованы ли сегменты**.
5. Настоящие критерии (две проверки unwrap_self.py):
   - **гейт 1**: `inner = data.find(b"\x7fELF")`; если нет — `Refused("no inner ELF header")` (`anyps5/unwrap_self.py:111–113`). Прошивочный SELF падает именно здесь.
   - **гейт 2**: энтропия каждого PT_LOAD-сегмента (сэмпл 64 КиБ) ≥ `ENTROPY_LIMIT = 7.5` (`:59`), и если ВСЕ load-сегменты такие — `Refused("every load segment looks encrypted: …")` (`:258–269`). Продемонстрировано на реальном decrypted prx с рандомизированным payload: «segment 0 at 0x11f0 (8.00 bits per byte), …»).
6. Воспроизводимость: развёрнутые нами файлы **побайтово совпали** с ранее полученными ELF из дампа: `libc.prx` → sha256 `e851775b…8060` (как `games/cyberpunk/anyps5-run/sce_module/libc.prx`), `eboot.bin` → `52b2ef21…51d7` (как `eboot.elf`).
7. Среди **всех доступных** PS5-файлов контейнеров с `key_type=4` ровно два — оба прошивочные (sys/rec), оба зашифрованы. Decrypted-контейнера с key_type=4 в природе нашего дампа нет, но эксперимент §4.1 показывает: если бы он был, он бы развернулся.
8. **Вывод**: класс «разворачивается на ПК» = decrypted/fSELF (plaintext inner ELF, записи читаются, энтропия < 7.5) — независимо от magic/key_type/version/attributes. Системный образ 14.22 относится к retail-encrypted классу C и в текущем виде не разворачивается; нужен расшифрованный SELF.

## 1. Откуда взяты реальные байты (без root)

`PPSA04029.exfat` (образ игры Cyberpunk 2077) не смонтирован, но `dump.exfat` (exfatprogs 1.4.3) читает его как файл.

```bash
cd /home/oleg/Документы/ps5semulator/games/cyberpunk
dump.exfat -s / PPSA04029.exfat            # записи /eboot.bin, /sce_module, /modules, /fakelib
dump.exfat -s /sce_module PPSA04029.exfat  # FirstCluster/DataLength каждого .prx
dump.exfat -s /fakelib PPSA04029.exfat     # три .sprx
```

Параметры ФС из boot sector (0x00): `bytesPerSectorShift=9` (512), `sectorsPerClusterShift=7` (кластер 0x10000), `clusterHeapOffset=34816` → heap `0x1100000`, `rootDirCluster=11`. Смещение файла: `0x1100000 + (first_cluster-2)*0x10000`. Все файлы помечены `GeneralSecondaryFlags=0x03` (NoFatChain) — данные непрерывны.

Вырезаны (полные файлы в `/tmp/self-classes/`, заголовки 1 КиБ сохранены в `ps5jb/tools/pup/output/self-samples/*.head.bin`, два небольших образца — `.real`):

| файл в дампе | FirstCluster | размер | magic байты |
|---|---|---|---|
| `/eboot.bin` | 13 | 155 273 788 | `4F 15 3D 1D` |
| `/sce_module/libc.prx` | 3 965 084 | 1 303 122 | `54 14 F5 EE` |
| `/sce_module/libSceFace.prx` | 3 965 104 | 301 852 | `54 14 F5 EE` |
| `/sce_module/libSceFaceTracker.prx` | 3 965 109 | 2 610 615 | `54 14 F5 EE` |
| `/sce_module/libSceJobManager.prx` | 3 965 149 | 68 998 | `54 14 F5 EE` |
| `/sce_module/libSceNpCppWebApi.prx` | 3 965 151 | 7 463 495 | `54 14 F5 EE` |
| `/sce_module/libScePfs.prx` | 3 965 265 | 1 343 391 | `54 14 F5 EE` |
| `/modules/libREDGalaxy64.prx` | 3 963 343 | 8 613 022 | `54 14 F5 EE` |
| `/fakelib/libSceAppContent.sprx` | 3 963 339 | 32 982 | `4F 15 3D 1D` |
| `/fakelib/libSceGameUpdate.sprx` | 3 963 340 | 9 126 | `4F 15 3D 1D` |
| `/fakelib/libSceNpEntitlementAccess.sprx` | 3 963 341 | 43 286 | `4F 15 3D 1D` |

## 2. Таблица трёх классов — по реальным байтам

Поля SELF по `sce_self_header` (etaHEN `self.h`): magic u32 @0x00, version u8 @0x04, mode @0x05, endian @0x06, attributes @0x07, key_type u32 @0x08, header_size u16 @0x0C, metadata_size u16 @0x0E, file_size u64 @0x10, segment_count u16 @0x18, flags u16 @0x1A.

| поле | **A: eboot.bin** | **A: fakelib .sprx** | **B: libc.prx** | **C: sys SELF 14.22** | **C: recovery SELF** |
|---|---|---|---|---|---|
| файл | `/eboot.bin` | `/fakelib/libSceAppContent.sprx` | `/sce_module/libc.prx` | `fw/inner/1422-PS5UPDATE1.pup` (1266089984) | `fw/inner/1422-PS5UPDATE2.pup` (157606077) |
| magic байты | `4F 15 3D 1D` | `4F 15 3D 1D` | `54 14 F5 EE` | `54 14 F5 EE` | `54 14 F5 EE` |
| magic u32 LE | `0x1D3D154F` | `0x1D3D154F` | `0xEEF51454` | `0xEEF51454` | `0xEEF51454` |
| version @0x04 | 0x00 | 0x00 | 0x00 | **0x10 (16)** | **0x10 (16)** |
| mode / endian | 1 / 1 | 1 / 1 | 1 / 1 | 1 / 1 | 1 / 1 |
| attributes @0x07 | **0x12** | **0x12** | **0x12** | **0x32** | **0x32** |
| key_type @0x08 | **0x101 (257)** | **0x101 (257)** | **0x101 (257)** | **4** | **4** |
| header_size | 1376 (0x560) | 1376 | 1376 (0x560) | 1456 (0x5B0) | 576 (0x240) |
| metadata_size | 1296 (0x510) | 1296 | 1552 (0x610) | 3552 (0xDE0) | 1440 (0x5A0) |
| file_size @0x10 | **153 905 696** (читается) | читается | **1 303 104** (читается) | `7778815604992573160` — **мусор** | `10760675977967921069` — **мусор** |
| segment_count @0x18 | **12** (читается) | 12 | **12** (читается) | `54760` — **мусор** | `24295` — **мусор** |
| flags @0x1A | **0x0022** | 0x0022 | **0x0022** | `0x5CE6` — мусор | `0x4FFF` — мусор |
| записей @0x40 | **11** | 11 | **11** | **0** | **0** |
| plaintext ELF | **@0x1A0** | @0x1A0 | **@0x1A0** | **НЕТ** | **НЕТ** |
| энтропия 64 КиБ после header_size | 0.0003 (eboot) | — | 6.3927 | 7.9974 | 7.9977 |
| энтропия хвоста заголовка | 2.77 (ожид. 7.86) | 2.77 | 2.3082 (ожид. 7.86) | 7.8826 (ожид. 7.87) | 7.6909 (ожид. 7.67) |
| энтропия metadata-области | 0.0091 | — | 0.0078 | 7.9502 (ожид. 7.95) | 7.8639 (ожид. 7.87) |
| вердикт `self_probe.py` | decrypted SELF | decrypted SELF | decrypted SELF | retail-encrypted | retail-encrypted |
| **`unwrap_self.py`** | **OK** | **OK** | **OK** | **FAIL: no inner ELF header** | **FAIL: no inner ELF header** |

Примечание: sys-SELF взят из `fw/inner/1422-PS5UPDATE1.pup` (срез sys-PUP, первые 16 байт: `5414f5ee1001013204000000b005e00d`, совпадает с образом sys-PUP на 0x400).

Пояснение к записям: decrypted SELF имеет 12 сегментов, но в таблице по 0x40 валидны 11 записей (12-я — «не записана»/PT_NOTE-подобная; unwrap_self.py такие сегменты размещает по vaddr). Для класса C таблица по 0x40 не читается вообще: там шифротекст.

Команды получения таблицы:
```bash
python3 ps5jb/tools/pup/self_probe.py header /tmp/self-classes/libc.prx
python3 ps5jb/tools/pup/self_probe.py header /tmp/self-classes/eboot.bin
python3 ps5jb/tools/pup/self_probe.py header ps5jb/fw/inner/1422-PS5UPDATE2.pup
python3 ps5jb/tools/pup/self_probe.py header ps5jb/fw/inner/1422-PS5UPDATE1.pup
# полная структура (записи + program headers) — из AnyPS5:
cd anyps5-build/anyps5-src/tools && PYTHONPATH=. python3 inspect_self.py /tmp/self-classes/libc.prx
```
Выводы: `ps5jb/tools/pup/output/self-classes/*.txt` (`game-self-headers-table.txt`, `structure-compare.txt`, `self-probe-game-vs-fw.txt`, `inspect-self-libc.txt`).

## 3. Воспроизведение разворота (наши файлы, реальные байты)

```bash
cd /home/oleg/Документы/ps5semulator
python3 anyps5/unwrap_self.py /tmp/self-classes/libc.prx /tmp/self-classes/libc.unwrap.elf
#   wrote /tmp/self-classes/libc.unwrap.elf, 1352554 bytes
python3 anyps5/unwrap_self.py /tmp/self-classes/eboot.bin /tmp/self-classes/eboot.unwrap.elf
#   wrote /tmp/self-classes/eboot.unwrap.elf, 155014364 bytes
python3 anyps5/unwrap_self.py ps5jb/fw/inner/1422-PS5UPDATE2.pup /tmp/self-classes/fw2.unwrap.elf
#   FAIL: ps5jb/fw/inner/1422-PS5UPDATE2.pup: no inner ELF header   (rc=2)
python3 anyps5/unwrap_self.py ps5jb/fw/inner/1422-PS5UPDATE1.pup /tmp/self-classes/fw1.unwrap.elf
#   FAIL: ps5jb/fw/inner/1422-PS5UPDATE1.pup: no inner ELF header   (rc=2)
```

Сверка с ранее развёрнутыми файлами дампа — **побайтово те же**:

| вход | наш выход | sha256 выхода | ранее в дампе | sha256 |
|---|---|---|---|---|
| `libc.prx` | 1 352 554 Б | `e851775ba534c2bd4ae3279d31e6a30157d3f7632dab6a1ea420af0533568060` | `games/cyberpunk/anyps5-run/sce_module/libc.prx` | **тот же** |
| `eboot.bin` | 155 014 364 Б | `52b2ef21dbaafca7373d3e942284f7db6eea7b1386d236827ff0f1262d2a51d7` | `games/cyberpunk/anyps5-run/eboot.elf` | **тот же** |
| `fakelib/libSceAppContent.sprx` | 88 914 Б | ELF 64-bit LSB x86-64 FreeBSD | — | — |

## 4. Эксперименты: что именно решает

### 4.1 key_type=4 сам по себе не мешает (главный эксперимент)

Берём **реальный decrypted** `libc.prx` (класс B) и переписываем открытые поля SELF на «как у прошивки»: bytes `0x04..0x0B = 10 01 01 32 04 00 00 00` (version=16, attrs=0x32, key_type=4).

```bash
python3 - <<'EOF'
import shutil
shutil.copyfile("/tmp/self-classes/libc.prx","/tmp/self-classes/libc-keytype4.prx")
with open("/tmp/self-classes/libc-keytype4.prx","r+b") as f:
    f.seek(0x04); f.write(bytes.fromhex("1001013204000000"))
EOF
python3 anyps5/unwrap_self.py /tmp/self-classes/libc-keytype4.prx /tmp/self-classes/libc-keytype4.elf
#   wrote /tmp/self-classes/libc-keytype4.elf, 1352554 bytes   (rc=0)
sha256sum /tmp/self-classes/libc-keytype4.elf /tmp/self-classes/libc.unwrap.elf
#   обе: e851775ba534c2bd4ae3279d31e6a30157d3f7632dab6a1ea420af0533568060
```

**Вывод:** `key_type=4`, `version=16`, `attributes=0x32` — не приговор. Разворот зависит от зашифрованности сегментов, а не от этих полей. (Более того, `unwrap_self.py` вообще не читает поля SELF-заголовка, кроме magic: см. §5.)

### 4.2 Гейт 1 — «no inner ELF header» (то, обо что упирается прошивка)

На реальном `libc.prx` затираем 4 байта `\x7fELF` по 0x1A0:

```bash
python3 - <<'EOF'
import shutil
shutil.copyfile("/tmp/self-classes/libc.prx","/tmp/self-classes/libc-noelf.prx")
with open("/tmp/self-classes/libc-noelf.prx","r+b") as f:
    f.seek(0x1A0); f.write(b"\x00"*4)
EOF
python3 anyps5/unwrap_self.py /tmp/self-classes/libc-noelf.prx /tmp/self-classes/x.elf
#   FAIL: .../libc-noelf.prx: no inner ELF header   (rc=2)
```
Тот же текст ошибки, что у обоих прошивочных SELF — т.е. прошивка падает на первой проверке.

### 4.3 Гейт 2 — «every load segment looks encrypted» (энтропия ≥7.5)

На реальном `libc.prx` рандомизируем payload с 0x1000 (заголовок ELF и таблица program headers сохранены):

```bash
python3 anyps5/unwrap_self.py /tmp/self-classes/libc-random.prx /tmp/self-classes/x2.elf
#   FAIL: .../libc-random.prx: every load segment looks encrypted:
#     segment 0 at 0x11f0 (8.00 bits per byte), segment 1 at 0xce010 (8.00),
#     segment 3 at 0x10bb50 (7.99), segment 7 at 0x10fa00 (7.99), segment 8 at 0x1136e0 (8.00)   (rc=2)
```

Оба эксперимента воспроизводят обе ветки отказа парсера на реальных байтах (результаты в `output/self-classes/gate-experiments.txt`).

## 5. Точные строки, где парсеры понимают «дальше шифр»

`anyps5/unwrap_self.py` (внешний инструмент; лежит вне write-scope этой задачи — `ps5jb/recon`, `ps5jb/tools/pup` — поэтому он **не менялся**, строки зафиксированы как ссылки на факты):

| строка | код | смысл |
|---|---|---|
| `:44–45` | `SELF_MAGIC = 0x1D3D154F` / `SELF_MAGIC_KERNEL = 0xEEF51454` | принимаются обе магии |
| `:59` | `ENTROPY_LIMIT = 7.5` | порог «сегмент зашифрован» |
| `:111–113` | `inner = data.find(b"\x7fELF")` → `raise Refused("no inner ELF header")` | **гейт 1: здесь падает прошивочный SELF** |
| `:258–269` | `def check_decrypted(...)`: сэмпл `ENTROPY_SAMPLE=0x10000` на каждый PT_LOAD; если все ≥ 7.5 → `raise Refused("every load segment looks encrypted: …")` | **гейт 2** |

Важно: **поля SELF-заголовка (version/mode/endian/attributes/key_type/header_size) `unwrap_self.py` не читает вообще** — только magic @0x00 и таблицу записей @0x40. Поэтому для него `key_type` по определению не может быть причиной отказа; причину он определяет по данным (наличие plaintext ELF и энтропия).

`ps5jb/tools/pup/self_probe.py` (наш; дополнен в этой задаче):

| строка | что делает |
|---|---|
| `:103–110` | `encryption_verdict()`: сравнивает энтропию региона с ожиданием для случайной выборки (`random_entropy_expected`), `looks_random = obs > exp - 0.25` |
| `:205` | `find_inner_elf()` — **повторяет гейт 1** unwrap (`mmap.find(b"\x7fELF")`) |
| `:227` | `read_self_records()` — таблица записей SELF @0x40 (как в unwrap) |
| `:276` | `encrypted = hdr_verdict and hdr_verdict["looks_random"]` — вердикт «хвост заголовка — шифротекст» |
| `:302` | `flags["verdict"]` — итог: `decrypted SELF (fSELF) … can unwrap` / `retail-encrypted SELF … unwrap_self.py refuses` |

Пример вывода (реальные файлы):
```
libc.prx:  header_tail_verdict entropy 2.3082 (random_expected 7.8647) looks_random False
           self_records_count 11, inner_elf_offset 416
           verdict: decrypted SELF (fSELF) … can unwrap
rec SELF:  header_tail_verdict entropy 7.6909 (random_expected 7.6715) looks_random True
           self_records_count 0, inner_elf_offset -1
           verdict: retail-encrypted SELF … refuses
```

Отдельно: `ps5jb/tools/pup/parse.py:272` (`plaintext = bool(flags & 1)`) со строкой-пояснением на `:588` — это **PUP-эвристика** (флаги u16 @0x0A), а не SELF-классификатор: в SELF байты 0x0A–0x0B — часть `key_type`/ключа, и проверка неверна для decrypted SELF. Для SELF используем `self_probe.py` / `unwrap_self.py`. Это зафиксировано как ограничение, а не как факт о контейнере.

## 6. Ответы на вопросы задачи

1. **Что отличает разворачиваемый SELF от неразворачиваемого.** Не магия, не key_type/version/attributes, а **состояние полезной нагрузки**: decrypted/fSELF содержит plaintext inner ELF (@0x1A0), читаемую таблицу записей @0x40 и сегменты с энтропией 6.4–6.6 (<7.5); retail-encrypted SELF не содержит plaintext ELF, его записи @0x40 не парсятся, энтропия 7.99. Открытые поля классов всё же различаются (A/B: version=0, attrs=0x12, key_type=0x101; C: version=16, attrs=0x32, key_type=4), но эксперимент §4.1 показывает, что эти поля не являются причиной.
2. **Есть ли контейнеры с key_type=4, которые разворачиваются?** В наших данных — только два key_type=4 контейнера, оба прошивочные (sys/rec), оба не разворачиваются. Decrypted-экземпляра с key_type=4 нет. Но **искусственно** (реальный decrypted файл + поля key_type=4/attrs=0x32/version=16) разворот проходит без изменений → `key_type=4` сам по себе не приговор; дело в шифровании.
3. **На каком шаге парсер понимает «дальше шифр».** `unwrap_self.py:111–113` — отсутствие `\x7fELF` (это и есть отказ прошивки); `unwrap_self.py:258–269` — энтропийный гейт, если ELF найден, но сегменты шумные. Наш `self_probe.py` фиксирует то же: `find_inner_elf()` + `encryption_verdict()`/`verdict` (§5).
4. **Существует ли класс PS5 SELF, разворачиваемый на ПК, и может ли системный образ к нему относиться.** Да, класс существует — decrypted/fSELF (в дампе: `eboot.bin` с PS4-магией и 7 PS5-`.prx`+3 `.sprx`); системный образ 14.22 — retail-encrypted SELF класса C, к разворачиваемому классу **не относится**: в нём нет plaintext ELF. Если получить его расшифрованный эквивалент (дамп после консольной расшифровки) — по формату он должен относиться к тому же классу, что B, и тогда `unwrap_self.py` его возьмёт (тот же magic, те же поля записи).

## 7. Артефакты

| файл | что внутри |
|---|---|
| `ps5jb/tools/pup/output/self-samples/*.head.bin` | первые 1 КиБ всех 8 игровых SELF из образа (реальные байты — доказательство таблицы) |
| `ps5jb/tools/pup/output/self-samples/sce_module_libc.prx.real` | полный реальный decrypted SELF (1 303 122 Б) |
| `ps5jb/tools/pup/output/self-samples/fakelib_libSceAppContent.sprx.real` | полный реальный decrypted SELF (32 982 Б) |
| `ps5jb/tools/pup/output/self-classes/structure-compare.txt` | поля/записи/ELF/энтропия по 5 файлам |
| `ps5jb/tools/pup/output/self-classes/game-self-headers-table.txt` | таблица заголовков 8 игровых SELF |
| `ps5jb/tools/pup/output/self-classes/self-probe-game-vs-fw.txt` | self_probe: decrypted vs firmware |
| `ps5jb/tools/pup/output/self-classes/unwrap-runs.txt` | прогоны unwrap_self.py (OK/FAIL + коды) |
| `ps5jb/tools/pup/output/self-classes/unwrap-compare.txt` | sha256 наших выходов vs ранее развёрнутых ELF |
| `ps5jb/tools/pup/output/self-classes/keytype-patch.txt` | эксперимент key_type=4 на decrypted SELF |
| `ps5jb/tools/pup/output/self-classes/gate-experiments.txt` | воспроизведение обоих гейтов отказа |
| `ps5jb/tools/pup/output/self-classes/inspect-self-libc.txt` | `inspect_self.py`: 11 записей, 14 program headers, ELF @0x1A0 |
| `ps5jb/tools/pup/output/self-classes/fakelib-headers.txt` | заголовки fakelib `.sprx` |

## 8. Проверено / не проверено

| утверждение | статус |
|---|---|
| реальные SELF игры вырезаны из exfat-образа и разворачиваются | проверено (sha256 выхода = ранее развёрнутым ELF) |
| классы A/B: plaintext ELF @0x1A0, 11 записей, энтропия <7.5 | проверено (`structure-compare.txt`, `inspect_self.py`) |
| класс C: нет plaintext ELF, 0 записей, энтропия 7.99, поля @0x10 мусор | проверено (`self_probe.py`, `unwrap_self.py`) |
| magic 0xEEF51454 встречается и в разворачиваемом (B), и в неразворачиваемом (C) | проверено (реальные байты) |
| key_type=4 не мешает развороту | проверено экспериментом §4.1 |
| оба гейта отказа воспроизводятся | проверено §4.2–4.3 |
| «есть decrypted key_type=4 SELF в природе» | **не проверено/не найдено**; в доступных данных нет |
| могут ли системные образы быть decrypted где-то ещё | неизвестно; нужен дамп с консоли |

## 9. Воспроизведение (кратко)

```bash
cd /home/oleg/Документы/ps5semulator
# 1) извлечение реальных SELF из образа (без root)
dump.exfat -s /sce_module games/cyberpunk/PPSA04029.exfat
python3 - <<'EOF'
img="games/cyberpunk/PPSA04029.exfat"; H=0x1100000; C=0x10000
with open(img,"rb") as f:
    f.seek(H+(3965084-2)*C); open("/tmp/libc.prx","wb").write(f.read(1303122))
EOF
# 2) классификация и разворот
python3 ps5jb/tools/pup/self_probe.py header /tmp/libc.prx
python3 anyps5/unwrap_self.py /tmp/libc.prx /tmp/libc.elf
python3 ps5jb/tools/pup/self_probe.py header ps5jb/fw/inner/1422-PS5UPDATE2.pup
python3 anyps5/unwrap_self.py ps5jb/fw/inner/1422-PS5UPDATE2.pup /tmp/fw.elf   # FAIL: no inner ELF header
```