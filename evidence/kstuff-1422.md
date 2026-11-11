# Payload-экосистема PS5: есть ли признаки доступа к ядру 14.20 / 14.22

**Вопрос (task-20, вторая половина):** появились ли где-нибудь в публичной экосистеме
kstuff / elfldr / offsets / payload'ов ветка, релиз или офсеты под **14.2x**? Если да — значит у кого-то
есть kernel R/W на 14.20/14.22, и это надо вытащить и проверить.
**Метод:** GitHub API (`repos`, `branches`, `releases`, `forks`, `git/trees`), `releases.atom`,
`raw.githubusercontent`, `git ls-remote`, плюс **анализ самих бинарей** (`strings`, поиск FW-таблиц).
**Дата:** 2026-11-11. Машина: Linux, сеть через `socks5h://127.0.0.1:10810`.
**Артефакт-сосед:** `recon/emulator-fw-assets.md` — первая половина task-20 (эмуляторы), здесь только payload-экосистема.

---

## 0. TL;DR

**Признаков доступа к ядру 14.20/14.22 в публичной payload-экосистеме НЕТ.**
Максимум поддержки везде — **13.60**; ни одного офсета, ветки, релиза или бинаря с 14.2x не найдено.
Единственные публичные артефакты про 14.22 — **не-ядерные**: WebKit-пробы, исследовательские заметки,
пустой скаффолд-репозиторий и пустые репозитории с громкими именами. Прямое письменное подтверждение
от разработчика: *«there is no public 14.00 kernel exploit anyways»* (Byepervisor-Reborn, README).

Три независимых «потолка» зафиксированы письменно:
* `itsPLK/ps5-webkit-remote-loader` — «Supports firmwares **7.00–13.60**» (README);
* `EchoStretch/kstuff-lite` v1.11 Beta — в release notes FW до **13.60**;
* `EchoStretch/Byepervisor-Reborn` — «hypervisor exploit for 6.xx – **13.60**», 14.00 «could work with
  modifications, but this is not provided here».

---

## 1. Сводная таблица

| Проект / репозиторий | Что поставляет | Заявленный max FW | Признаки 14.2x | Что даёт нам |
|---|---|---|---|---|
| [drakmor/kstuff-lite](https://github.com/drakmor/kstuff-lite) | kernel-модуль (fpkg/FSELF loader) | 12.70 (в notes); ветки `1.11-opt`, `1.12`, `feature/self-elevation`, `pathlog`; push **2026-09-21** | **нет** | ничего: 14.x не заявлен |
| [EchoStretch/kstuff-lite](https://github.com/EchoStretch/kstuff-lite) (upstream форка) | то же | **13.60** (v1.11 Beta, 2026-09-23; notes упоминают 10.60/11.40/11.60/12.00/12.70/13.60) | **нет** | ничего нового |
| [bsk193/drakmor-kstuff-mirror](https://github.com/bsk193/drakmor-kstuff-mirror) | зеркало релизов kstuff-lite, включая Discord-only | теги: `1.13-fpkg-dr-test8-rest`, `…-rest-fast`, `1.2-dr-test2`, `1.1-dr`… ; push **2026-11-05** | **нет** (в теге/имени/описании 14.x нет) | подтверждает: даже «слитые с Discord» сборки — без 14.x |
| [ps5-payload-dev/kstuff](https://github.com/ps5-payload-dev/kstuff) | kernel-модуль | ветка `elfldr-compatability`, push **2025-01-25** | **нет** | заброшен, не про 14.x |
| [etaHEN/etaHEN](https://github.com/etaHEN/etaHEN) | AIO HEN payload | upstream последний **2.5B** (2025-12-25); FW в notes нет | **нет** | ничего |
| [bsk193/etaHEN-mirror](https://github.com/bsk193/etaHEN-mirror) | зеркало etaHEN + неофициальные сборки | **2.6B** (2026-11-04) — сборка, которой нет в upstream-фиде | **нет**: скачал `etaHEN_2.6B.bin` (4 690 760 Б, ELF64 PIE), `strings` → ни «14.2», ни FW-таблицы | ничего: 2.6B не про 14.2x |
| [ps5-payload-dev/elfldr](https://github.com/ps5-payload-dev/elfldr) | ELF-loader, порт 9021 | **v0.27** (2026-10-21), далее v0.26/v0.25 | **нет** | нужен нам, но FW-независим |
| [LightningMods/Itemzflow](https://github.com/LightningMods/Itemzflow) | game manager / home menu | **1.08** (2026-05-31), Fuse-офсеты до **13.02** | **нет** | ничего |
| [itsPLK/ps5-webkit-remote-loader](https://github.com/itsPLK/ps5-webkit-remote-loader) | база webkit-хостов/автозагрузчиков | v0.2.2 (2026-11-08); README: **«7.00–13.60»** | **нет** | потолок экосистемы = 13.60 |
| [bsk193/ps5-webkit-autoloader-x](https://github.com/bsk193/ps5-webkit-autoloader-x) и др. `*-x` | хосты/автозагрузчики | CHANGELOG: добавляли 11.40/11.60; «Relapse remains unsupported on 9.05 and 11.40» | **нет** | ничего |
| [bsk193/console-homebrew-hub](https://github.com/bsk193/console-homebrew-hub) | каталог payload'ов + хост | таблица «PS5 Exploit Support»: 1.00–5.50 UMTX, 3.00–4.51 IPV6, 9.00–12.00 Slopkit; push **2026-11-11** | **нет**: по всему README ни одного `14.xx` | ничего |
| [itsPLK/ps5-payloads-mirror](https://github.com/itsPLK/ps5-payloads-mirror) | каталог 34 payload'ов (`payloads_v2.json`) | `last_update` до 2026-11-11; kstuff-lite v1.11, etaHEN 2.5B | **нет**: `grep 14.xx` по JSON → 0 совпадений | подтверждает: в каталоге нет 14.x-сборок |
| [m2k7m/Relapse-Exploit](https://github.com/m2k7m/Relapse-Exploit), [arg0WAK/WAK1360-Relapse](https://github.com/arg0WAK/WAK1360-Relapse), [soniciso1/relapse](https://github.com/soniciso1/relapse) | эксплойт-цепочка 7.00–13.60 | файлов `offsets/*.js`: **33** (m2k7m), **34** (WAK, +11.40), **32** (soniciso1); максимум везде **13.60** | **нет** | эталон для нашей работы |
| Форки Relapse (проверено 7: `tidewell/relapse`, `Danid1Games/relapse`, `CarShyne/Lab-relapse`, `RDX-Sci01/PS5-Relapse`, `ThatRetiredDude/WAK1360-Relapse`, `Ali-SAS/SAS`, `Nikolas-78/Relapse`) | форки цепочки | у **каждого** — ровно **33** файла `offsets/`, среди них **нет** `14.*` | **нет** (проверено деревом каждого форка: `grep -E 'offsets/14\.|1422|14\.2'` → пусто) | ничего |
| [EchoStretch/Byepervisor-Reborn](https://github.com/EchoStretch/Byepervisor-Reborn), [drakmor/Byepervisor-Reborn](https://github.com/drakmor/Byepervisor-Reborn) | **hypervisor**-эксплойт (S3 resume, `startup_mp`) | 6.xx–**13.60** (полностью: 13.60, 13.20, 13.00 untested), push **2026-11-08** | **нет**, и прямая цитата: «With modifications, it could work on 14.00 as well, but this is not provided here, **especially since there is no public 14.00 kernel exploit anyways**» | важное доказательство: у знающих людей на 2026-11-08 публичного 14.x-ядра нет |
| [EchoStretch/BD-JB-Relapse](https://github.com/EchoStretch/BD-JB-Relapse) | BD-J порт Relapse | «up to and including **13.42**»; таблицы офсетов в `RelapseOffsets.java` — **7.00–13.60** | **нет** | ещё один порт без 14.x |
| [1nk1/PS5-Prolapse](https://github.com/1nk1/PS5-Prolapse) | хост p2jb/poopsploit + «Bagagwa-on-13.60» | **11.60–13.60**; в `docs/PROJECT_HANDOFF.md` подробно про 13.60 и `aio_multi_wait` (syscall 663) | **нет** | полезный контекст по AIO-пути (та же уязвимость, что V6 у Relapse), но не 14.x |
| [Gezine/Y2JB](https://github.com/Gezine/Y2JB) | userland code exec через YouTube | FW не ограничен явно; к ядру доступа не даёт | **нет** (ядерной части нет) | userland-вектор, не ядро |

---

## 2. Новые репозитории с «14.22» в имени — что внутри

Поиск по GitHub (`search/repositories?q=ps5+14.22`, сортировка по обновлению) дал четыре свежих проекта.
Проверены все:

| Репозиторий | Создан / push | Что внутри | Вывод |
|---|---|---|---|
| [qraillife/PS5-14.22-JB](https://github.com/qraillife/PS5-14.22-JB) | 2026-11-11 (сегодня) | `README.md`, `index.html`, `modules.json`, `exploits/module-template.js`. README: *«This package provides a website launcher, **not a jailbreak**»*; `modules.json` = `[]`; шаблон: `window.ps5ExploitResult = {success:false, reason:'No exploit implemented'}` | **скаффолд, эксплойта нет** |
| [qraillife/PS5-14.22-Jailbreak](https://github.com/qraillife/PS5-14.22-Jailbreak) | 2026-11-11 | пустой git-репозиторий (`409 Git Repository is empty`) | **пусто** |
| [larpingvibecoder/rockstar](https://github.com/larpingvibecoder/rockstar) | 2026-11-09 | пустой репозиторий, описание «rockstar ps5 jailbreak 14.22» | **пусто** |
| [karter-captain/ps5-14.22-browser-probes](https://github.com/karter-captain/ps5-14.22-browser-probes) | 2026-11-06 | 10 статических страниц-проб для браузера 14.22 (Slim + disc): `alloc-pressure`, `atomics-probe`, `chain`, `iframe-sandbox`, `slow-chain`, `typedarray-edge`, `wasm-basic`, `webkit-sniff`… README: «Diagnostic probes only» | **WebKit-пробы, к ядру отношения нет** |

Плюс профильные 14.x-исследования, тоже **без эксплойт-кода**:
[Khal0da/PS5-14.20-WebKit-Research](https://github.com/Khal0da/PS5-14.20-WebKit-Research) («No exploit code»),
`ZigZagBoi1/PS5-14.10-Research` (набор документов/статус-репортов).

**Итог по разделу:** имена репозиториев — не доказательство. Внутри — либо пусто, либо скаффолд,
либо браузерные пробы. Ни одного файла с kernel-офсетами 14.2x.

---

## 3. Что проверялось в бинарях (не только по описаниям)

| Бинарь | Проверка | Результат |
|---|---|---|
| `etaHEN_2.6B.bin` (bsk193/etaHEN-mirror → release `2.6B`) | скачан: 4 690 760 Б, `file` = ELF 64-bit LSB pie x86-64, stripped, sha256 `8ce5ab4eaff10679920bf7397bb081ca9c18aa159d134cae8f1af3a4290b91b6`; `strings` на `1x.xx`, `14.2` | ни FW-таблицы, ни «14.2» — **0 совпадений** |
| `kstuff-1.13-fpkg-dr-test8-rest.elf` (bsk193 mirror) | `strings -t x` поиск FW-строк и `14.2/1422/1420` в сырых байтах | внутри есть FW-строки только **10.00, 10.01, 10.20, 10.40, 10.60, 11.00, 11.20, 11.40, 11.60** (9 шт., offsets `0x134242…0x13e70e`); `14.2`/`1422`/`1420` — **0** |
| `kstuff-lite-1.2-dr-test2.elf`, `1.1-dr`, `1.2-dr-test1` | `strings` на FW-строки | FW-строк нет |
| `elfldr-ps5-v0.25/v0.27.elf`, `kstuff1.13…rest-fast.elf` | проверены ранее (`tools/payload/RELAPSE-PAYLOADS-VERIFY.txt`) | валидные ELF64 PIE, к FW не привязаны |

Т.е. даже «неофициальные»/«Discord-only» сборки, гуляющие по зеркалам, **не содержат** ни FW-таблиц
с 14.x, ни строк 14.2x.

---

## 4. Что считается доказательством (критерий, чтобы не обмануться)

Признаком реального kernel-доступа к 14.2x было бы одно из:
1. файл `offsets/14.20.js` / `14.22.js` (или `1422`) в любом форке Relapse/WAK/Prolapse;
2. новый тег/релиз kstuff/etaHEN с текстом «14.20/14.22 supported» **и** непустыми ассетами;
3. таблица FW внутри бинаря (как 9 FW-строк в kstuff 1.13), где есть 14.x;
4. ветка `14.x`/`1422` в kstuff-lite/elfldr с коммитами;
5. payload, который на 14.22 реально что-то пишет в ядро (например, Byepervisor с поддержкой 14.00+).

**Ни один из пяти признаков не найден.**

Обратные (негативные) свидетельства, найденные письменно:
* Byepervisor-Reborn: *«no public 14.00 kernel exploit anyways»* (README, push 2026-11-08);
* хост cyber-forge помечает 14.00–14.22 как `PATCHED`, «aio_multi_delete Blocked», «Sony sealed kernel
  R/W on 14.20/14.22» (см. `recon/relapse-anatomy.md` §7.1);
* 14.22-именованные репозитории — скаффолд/пусто/WebKit-пробы (см. §2);
* каталоги payload'ов (`ps5-payloads-mirror` 34 записи, `console-homebrew-hub`) не содержат 14.x.

---

## 5. Watchlist: где смотреть, когда что-то появится

Практический список (проверять при следующем заходе; всё — публичное, без консоли):

```bash
# 1) релизы (atom, без API-лимита): ищем в notes "14.2" / "1422"
for r in EchoStretch/kstuff-lite drakmor/kstuff-lite ps5-payload-dev/elfldr \
         etaHEN/etaHEN bsk193/drakmor-kstuff-mirror bsk193/etaHEN-mirror \
         LightningMods/Itemzflow itsPLK/ps5-webkit-remote-loader; do
  curl -sS -x socks5h://127.0.0.1:10810 "https://github.com/$r/releases.atom" \
    | grep -oE "1[0-9]\.[0-9]{2}" | sort -u | tail -3 | sed "s|^|$r: |"
done

# 2) ветки kstuff-lite (появится ветка 14.x — сигнал)
for r in drakmor/kstuff-lite EchoStretch/kstuff-lite; do
  git -c http.proxy=socks5h://127.0.0.1:10810 ls-remote --heads https://github.com/$r
done

# 3) форки Relapse: ищем offsets/14.*
gh api "repos/m2k7m/Relapse-Exploit/forks?per_page=100" --jq '.[].full_name' \
  | while read f; do gh api "repos/$f/git/trees/main?recursive=1" --jq '.tree[].path' \
      | grep -E "offsets/14\." && echo ">>> $f"; done

# 4) поиск по коду/репозиториям
gh api "search/repositories?q=ps5+14.20&sort=updated"
gh api "search/code?q=%22supportedFirmware%22+%2214.2%22"
```

Дополнительно держать в поле зрения: `soniciso1/relapse` (первоисточник Relapse),
`1nk1/PS5-Prolapse` («Bagagwa» — новый AIO-баг, пока только 13.60), `Gezine/Y2JB`,
`Khal0da/PS5-14.20-WebKit-Research` (WebKit-поверхность 14.20), `bsk193/console-homebrew-hub`.

---

## 6. Вывод

1. **Публичного kernel R/W на 14.20/14.22 нет** — по состоянию на 2026-11-11 ни один payload-проект
   не заявляет и не содержит 14.2x-офсетов, FW-таблиц или релизов.
2. Потолок экосистемы — **13.60**, и он держится согласованно у независимых авторов
   (Relapse/WAK 7.00–13.60, Byepervisor 6.xx–13.60, BD-JB-Relapse ≤13.42, loader 7.00–13.60,
   kstuff-lite 13.60, itemzflow 13.02).
3. Всё, что есть про 14.2x публично — **не ядро**: WebKit-пробы (`karter-captain/ps5-14.22-browser-probes`),
   исследовательские заметки (`Khal0da`, `ZigZagBoi1`), пустой скаффолд (`qraillife`) и пустые репозитории.
4. Из этого следует практический вывод для нашей задачи: **добывать константы 14.22 придётся самим**
   (конвейер `tools/payload/scan_1322.py` + `docs/KERNEL-INGEST.md`), а не «подобрать» из чужого релиза.
   Единственный реалистичный внешний источник — приватные цепочки, о которых пишет cyber-forge
   («wait for private WebKit/hypervisor chains to become public»).

---

### Приложение: команды, которыми проверялось

```bash
export ALL_PROXY=socks5h://127.0.0.1:10810 HTTPS_PROXY=socks5h://127.0.0.1:10810
gh api repos/<r> --jq '[.full_name,.default_branch,.pushed_at,.size,(.description//"")]|@tsv'
gh api repos/<r>/branches  --jq '.[].name'
gh api repos/<r>/releases  --jq '.[]|[.tag_name,.published_at,(.assets|map(.name)|join(","))]|@tsv'
gh api repos/<r>/git/trees/<br>?recursive=1 --jq '.tree[]?.path' | grep -E 'offsets/14|1422|14\.2'
gh api "search/repositories?q=ps5+14.22&sort=updated"
curl -sS -x socks5h://127.0.0.1:10810 https://github.com/<r>/releases.atom
curl -sS -x socks5h://127.0.0.1:10810 https://raw.githubusercontent.com/<r>/<br>/README.md
curl -sSL -x socks5h://127.0.0.1:10810 -o etaHEN_2.6B.bin \
  https://github.com/bsk193/etaHEN-mirror/releases/download/2.6B/etaHEN_2.6B.bin
strings -n 4 -t x <elf> | grep -E '^\s*[0-9a-f]+ 1[0-9]\.[0-9]{2}$'
grep -ac '14\.2' <elf>; grep -ac '1422' <elf>
```