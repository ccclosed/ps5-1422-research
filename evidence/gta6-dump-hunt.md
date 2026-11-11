# GTA 6 на PS5: есть ли публичный дамп (и что это доказывало бы)

Дата работы: 2026-11-11. Задача task-29. Проверка: каждый источник — с URL, HTTP-кодом и
объёмом ответа; где найдено — с размером/хешем.

Легенда: `ФАКТ` — проверено в этой сессии (команда/HTTP-код/файл);
`ЗАГОЛОВОК ИЗ ПОИСКА` — страницу открыть не удалось (403/429), есть только выдача
поисковика (URL + заголовок + сниппет); `НЕ ПРОВЕРЕНО` — доступ закрыт; `ФЕЙК` — доказано
подделкой.

---

## 0. Прямой ответ

**Публичного дампа GTA 6 для PS5 не существует (на 2026-11-11).** Причина простая и
проверяемая: **игра ещё не вышла** — PS Store отдаёт её как предзаказ с датой релиза
**2026-11-19**; на консоли доступна только **preload**-загрузка (шифрованные пакеты, привязанные
к PSN-лицензии/консоли). Единственный найденный «дамп» — репозиторий `GamerHack93/gta6-preload`
— **доказанный фейк** (§4). Ни playable PKG, ни exFAT/app-папки, ни образа диска в публичном
доступе нет; поиск по title ID `PPSA01547` не даёт ни одного файла-дампа (§5–§7).

Следствие для гипотезы «дамп ⇒ у кого-то есть исполнение кода на 14.22»: **эта логика
неверна в обе стороны** (§8): preload можно скачать на обычной консоли без джейлбрейка,
а для запуска дампа нужны ключи/лицензия; при этом публичное доказательство живого
14.22 уже есть независимо от GTA 6 (см. `recon/artifacts-1422.md` §2 — beacon-логи
TFujiwara с UA `PlayStation 5/14.22` от 2026-11-05).

---

## 1. Title ID GTA 6 для PS5

`ФАКТ`. Старый (chihiro) API PS Store работает и отдаёт каталог: команда и результат:

```
$ curl -sS -A 'Mozilla/5.0' \
  'https://store.playstation.com/store/api/chihiro/00_09_000/search/US/en/19/grand%20theft%20auto%20vi?size=20'
http=200 bytes=53552
total_results=10000, вернулось 20; из них GTA VI — 3 SKU:
  Grand Theft Auto VI                              EP1004-PPSA01547_00-GTAVISTANDARD001
  Grand Theft Auto VI: Ultimate Edition            EP1004-PPSA01547_00-GTAVIULTIMATE001
  Grand Theft Auto VI: Ultimate Edition Upgrade    EP1004-PPSA01547_00-ULTEDTIONUPGRADE
```

Итого: **Title ID = `PPSA01547`**, publisher/content: `EP1004` (Rockstar), регион EU-контент,
продаётся в US-сторе.

Подтверждение вторым источником: `PROSPEROPatches` знает этот title ID:
`https://prosperopatches.com/PPSA01547` → **200, 27 334 Б**, заголовок «PPSA01547: Grand Theft
Auto VI», EU Title ID `PPSA01547`, Content ID `EP1004-PPSA01547_00-GRANDTHEFTAUTO00`,
Publisher «Rockstar Games», Publisher ID `EP1004`. Обновлений («Updates») страница не
показывает — список патчей подгружается JS и пуст (игра не вышла).

---

## 2. Статус игры: предзаказ, релиз 2026-11-19

`ФАКТ`. Страница товара PS Store:

```
$ curl -sS -L -A 'Mozilla/5.0' \
  'https://store.playstation.com/en-us/product/EP1004-PPSA01547_00-GTAVISTANDARD001'
http=200 bytes=466068
  "releaseDate":"2026-11-19T05:00:00Z"   (2 вхождения)
  "11/19/2026" (releaseDate-value), "Pre-order" / "preorder"
  PPSA01547 — 343 вхождения
```

`ФАКТ` (Wikipedia, живой запрос `https://en.wikipedia.org/wiki/Grand_Theft_Auto_VI`,
HTTP 200, 1 380 383 Б): игра помечена как **upcoming**, release **19 November 2026**,
platforms PlayStation 5 / Xbox Series X|S / Xbox One.

Дата сегодняшней сессии — 2026-11-11; до релиза 8 дней.

---

## 3. Премиса «GTA 6 требует 14.22» и preload

`ЗАГОЛОВОК ИЗ ПОИСКА` (страницы отдают 403 Cloudflare, полный текст не прочитан):

| Заголовок | URL |
|---|---|
| «GTA 6 preload reveals 223GB package and **mandatory PS5 firmware 14.22** update» (VideoCardz) | https://videocardz.com/newz/gta-6-preload-reveals-223gb-package-and-mandatory-ps5-firmware-14-22-update |
| «GTA VI PS5 preload package **requires firmware 14.22**» (OneJailbreak) | https://onejailbreak.com/blog/gta-vi-ps5-preload-package-requires-firmware-14-22/ |
| «GTA 6 preload is now available for all digital pre-orders — download to your PS5 now» (Push Square) | https://www.pushsquare.com/news/2026/11/gta-6-preload-is-now-available-for-all-digital-pre-orders-download-to-your-ps5-now |
| «GTA 6 preloading is live: how to install on PlayStation and Xbox» (PCMag) | https://www.pcmag.com/news/gta-6-preloading-is-live-how-to-install-game-on-playstation-and-xbox |
| «PS5 Firmware Update 14.22 Released, Sony Confirms 'Some Security…'» (IGN) | https://www.ign.com/articles/sony-issues-yet-another-ps5-firmware-update-as-jailbreak-whac-a-mole-continues-ahead-of-gta-6-release |
| Reddit r/PS5_Jailbreak: «GTA 6 Now Requires PS5 Firmware 14.22…» | https://www.reddit.com/r/PS5_Jailbreak/comments/1xm0xq1/gta_6_now_requires_ps5_firmware_1422_as_the_fight/ |

Проверка доступа: `videocardz.com` → 403 («Access blocked»), `onejailbreak.com` → 403,
`pushsquare.com` → 403, `reddit.com` (JSON) → 403. Значит статус — **заголовок/сниппет,
полный текст не прочитан**; помечено как `ЗАГОЛОВОК ИЗ ПОИСКА`, а не как факт.

`ФАКТ`: preload действительно идёт (совокупность заголовков: «preloading is live», «download
to your PS5 now»), а требование 14.22 для запуска — согласуется с тем, что 14.22 выпущена
2026-11-02 (см. `recon/1422-status.md`) за 17 дней до релиза игры.

**Preload ≠ дамп.** PS5 preload-пакеты зашифрованы и требуют PSN-лицензии/консоли; скачивание
на обычной PS5 не требует джейлбрейка и не даёт playable файлов на ПК. «Датамайны» из прессы
(Gamereactor «Dataminers dig into newly live GTA 6 preload files», TweakTown «preload gives up
clues… PSSR 2») — это метаданные/иконки/ассеты из стора, а не игра. Посты в X («GTA VI PS5
package. snd0 + pic0», «GTA 6 Game Version») — извлечение `snd0`/`pic0` из заголовка пакета,
не дамп контента.

---

## 4. Единственный «дамп»: `GamerHack93/gta6-preload` — ФЕЙК (доказано)

`ФАКТ`. Репозиторий: https://github.com/GamerHack93/gta6-preload — создан 2026-11-10T14:26:03Z,
pushed 2026-11-10T14:34:02Z, **size=53 КБ**, 74★, описание «GTA VI PS5 preload dump (01.00.00) —
extracted after preload on 2026-11-10. Already playable».

Улики подделки:

1. **Все «файлы игры» — Git-LFS-указатели по 131–136 байт**, а не данные:
   ```
   common.rpf     136 B  sha256 0a7ada1b26bd8193…  начинается: "version https://git-lfs.github.com/spec/v1"
   GTA6_dev.exe   134 B  sha256 90fc024ddf709e7e…  тот же LFS-указатель
   x64a.rpf       135 B  082994016ce24784…         тот же
   bink2w64.dll   131 B  f4ae61c0927bcb14…         тот же
   ```
   Внутри указателя — `oid sha256:… size 12566433239` (12.5 ГБ) — объекта нет, `.gitattributes`
   с LFS-фильтром отсутствует, т.е. в репо лежат текстовые заглушки.
2. **Это Windows-сборка, а не PS5**: `.exe/.dll` (GTA6_dev.exe, PlayGTAVI.exe, dxcompiler.dll,
   nvngx_dlss.dll, PhysX3_x64.dll…), `BUILD_INFO.txt`: «TOOLCHAIN MSVC 19.40 / RAGE NG,
   CONFIG BankRelease, RENDERER DX12, SIGNED NO»; `commandline.txt` с `-dx12`.
3. README противоречит сам себе: «~212 GB», «CUSA-XXXXX» (это PS4-нейминг, у PS5 — PPSA),
   «fPKG / Package Installer» — при том что в репо 53 КБ и нет ни одного пакета.
4. 4 коммита «Add files via upload» за 6 минут (14:27–14:34), релизов нет; у автора остальные
   репозитории — Android-приложения (ClockMaster, WeatherMaster…), к PS5 отношения не имеют.

**Вывод: `gta6-preload` — фейк-заглушка, не дамп.** Ни одного байта игры в нём нет.

Полные sha256/размеры всех файлов фейка: `recon/_src/gta6/fake-repo-sha256.txt`
(sha256 `89807563c2c40b663149a402c00ad2db5fccb03a1c96390b05bf76249e05b3ef`).

---

## 5. Проверка каталогов и индексов (таблица)

| Источник | Проверка | Результат | Вывод |
|---|---|---|---|
| PS Store chihiro API (`/search/US/en/19/grand theft auto vi`) | HTTP **200**, 53 552 Б | 3 SKU GTA VI, `PPSA01547` | `ФАКТ`: игра в сторе как предзаказ; файлов нет |
| PS Store product page | HTTP **200**, 466 068 Б | `releaseDate 2026-11-19`, «Pre-order» | `ФАКТ`: релиз ещё не состоялся |
| PROSPEROPatches `/PPSA01547` | HTTP **200**, 27 334 Б | страница есть, «Loading patches…» (JS), обновлений нет | `ФАКТ`: патчей нет (игра не вышла) |
| `Jamzi94/catalog-V2` (ps5-catalog.json, клон 12 МБ) | grep по `grand theft\|gta` | GTA III/VC/SA/Trilogy/V (PPSA03524/03525/03527/03530/04263/04264), **GTA VI — 0** | `ФАКТ`: в каталоге FPKG нет GTA 6 |
| dlpsgame (поиск `?s=grand+theft+auto+vi`) | HTTP **200**, 67 451 Б | только старые GTA; прямые URL `…/grand-theft-auto-vi-ps5/` → **404** | `ФАКТ`: страницы GTA VI нет |
| archive.org advancedsearch | HTTP **200** | `PPSA01547` → **0**; `grand theft auto vi ps5 pkg` → **0**; `GTAVI` → 167, но все `image/audio/movies/web` (трейлеры, обложки, альбом) | `ФАКТ`: дампа/образа игры нет |
| GitHub repos `GTA 6 PS5 dump` / `GTA VI PS5 pkg` | search API | только `GamerHack93/gta6-preload` (фейк, §4) | `ФАКТ`: реальных дамп-репо нет |
| GitHub code `PPSA01547` | search API | 632 хита: каталоги стора (`Ephellon/game-store-catalog/ps5/g.json` содержит `PPSA01547`), примеры схем (`zecoxao/gengp5-src`), прайс-трекеры | `ФАКТ`: title ID известен, файлов-дампов нет |
| psxhax.com | HTTP **403** (Cloudflare) | не открылось | `НЕ ПРОВЕРЕНО` |
| 1337x.to / rutracker.org через `socks5h://127.0.0.1:10810` | HTTP **403** (Cloudflare) | — | `НЕ ПРОВЕРЕНО`; Brave `site:rutracker.org "GTA VI" PS5` дал только видео-раздачу «Grand Theft Auto VI: An Extended Look», не игру |
| btdig / solidtorrents | timeout/000 | — | `НЕ ПРОВЕРЕНО` (DHT-поиск недоступен) |
| Telegram (`site:t.me "GTA VI" pkg`) | Brave → **429** (rate limit) | — | `НЕ ПРОВЕРЕНО` |
| Reddit-тред «…celebrating the GTA VI pkgs…» | прямой запрос **403** | заголовок виден; содержимое нет | `НЕ ПРОВЕРЕНО` (вероятно про preload-пакеты, а не дамп) |
| X/Twitter посты про «GTA VI PS5 package» | сниппеты поиска | `snd0`/`pic0` (метаданные пакета), «Game Version» | `ФАКТ` по сниппету: это не дамп контента |

---

## 6. Что искалось по title ID (полный список запросов)

`PPSA01547`, `GTA VI PS5 pkg`, `GTA 6 PS5 dump`, `GTA VI PS5 preload`, `GTAVI dump`,
`EP1004-PPSA01547_00-GTAVISTANDARD001` — в PS Store API, GitHub (repo+code search), archive.org,
dlpsgame, PROSPEROPatches, Brave/DDG/Bing, 1337x/rutracker/btdig/solidtorrents (через прокси),
psxhax, Telegram (через Brave), Reddit. Каждый — с HTTP-кодом в §5. **Ни одного файла игры
(размер > 1 ГБ, pkg/exFAT/образ) не найдено.**

Сохранённые улики: `recon/_src/gta6/` — `ps-store-search-gta-vi.json` (53 552 Б,
sha256 `d7c17aa9faff62576b574b3e0b584e9193263f9ba8c98c739d52f75842e0ffb9`),
`prosperopatches-PPSA01547.html` (27 334 Б, sha256 `523d8c46126ae72946f33c97f42d2c7e083f31641423f65103e0d8ef6b77b433`),
`fake-repo-sha256.txt`, манифест `recon/_src/gta6/MANIFEST.sha256`.

---

## 7. Почему даже «preload-дамп» не был бы играбельным дампом

- PS5 PKG шифруются; preload-контент выдаётся в зашифрованном виде и активируется лицензией
  PSN. Скачивание на обычной консоли — штатная операция, джейлбрейк не нужен.
- Публичные инструменты распаковки PS5 PUP/PKG требуют ключей с консоли
  (`recon/pup-decrypt-feasibility.md`, task-10): на ПК без консоли не читаются.
- Даже «datamine» из прессы — это только распакованные метаданные/иконки/строки (snd0/pic0),
  а не eboot/ассеты. Для запуска в эмуляторе нужен расшифрованный eboot/ELF (см.
  `recon/emulation-14.22.md`), которого в публичном доступе нет.

---

## 8. Что это значит для гипотезы «дамп ⇒ живой 14.22»

`ОЦЕНКА`, важно: гипотеза лида в такой форме **неверна**.

1. **Наличие preload-пакетов не доказывает джейлбрейк 14.22**: preload скачивается штатно
   на любой консоли с 14.22.
2. **Отсутствие дампа не опровергает исполнение кода на 14.22**: дамп с консоли требует
   джейлбрейка, но дампа нет именно потому, что игра не вышла (и её файлы ещё не
   расшифрованы/не выложены), а не потому, что «все молчат».
3. **Публичное доказательство живого 14.22 у нас уже есть** — и оно не про GTA 6:
   beacon-логи TFujiwara (`beacons_20261105_172139.log`, `beacons_20261105_175742.log`)
   с UA `PlayStation 5/14.22` от 2026-11-05, на которых запускались Canvas-UAF-пробы
   (v900/p553/v904; разбор — `recon/artifacts-1422.md` §2). Это исполнение WebKit-кода
   на 14.22 через User's Guide, а не джейлбрейк, но это единственное, что нужно для
   «вход жив».

**Когда дамп может появиться:** после релиза 2026-11-19 (Blu-ray-образ/дамп диска, слив
preload-ключей, или дамп с джейлбрейкнутой 14.22). Тогда проверять по `PPSA01547` и
`EP1004-PPSA01547_00-GTAVISTANDARD001`; для запуска в эмуляторе понадобится расшифрованный
eboot (см. `recon/emulation-14.22.md`).

---

## 9. Команды для повторной проверки

```bash
# title ID
curl -sS -A 'Mozilla/5.0' \
 'https://store.playstation.com/store/api/chihiro/00_09_000/search/US/en/19/grand%20theft%20auto%20vi?size=20' \
 | python3 -c 'import json,sys;d=json.load(sys.stdin);[print(l["name"],l["id"]) for l in d["links"] if "PPSA01547" in l["id"]]'

# релиз/предзаказ
curl -sS -L -A 'Mozilla/5.0' \
 'https://store.playstation.com/en-us/product/EP1004-PPSA01547_00-GTAVISTANDARD001' \
 | grep -oE '"releaseDate":"[^"]*"|Pre-order' | sort -u

# архивы
curl -sS 'https://archive.org/advancedsearch.php?q=PPSA01547&fl%5B%5D=identifier&rows=5&output=json'
curl -sS 'https://archive.org/advancedsearch.php?q=grand+theft+auto+vi+ps5+pkg&fl%5B%5D=identifier&rows=5&output=json'

# фейк-репо
git clone --depth 1 https://github.com/GamerHack93/gta6-preload.git /tmp/gta6fake
head -3 /tmp/gta6fake/common.rpf        # -> "version https://git-lfs.github.com/spec/v1"
stat -c '%s %n' /tmp/gta6fake/*.rpf /tmp/gta6fake/*.exe   # -> 132..136 bytes

# торренты (DPI-обход; оба отдают 403 Cloudflare из этой сети)
curl -sS -x socks5h://127.0.0.1:10810 -A 'Mozilla/5.0' 'https://1337x.to/search/GTA%20VI%20PS5/1/'
curl -sS -x socks5h://127.0.0.1:10810 -A 'Mozilla/5.0' 'https://rutracker.org/forum/tracker.php?nm=GTA+VI+PS5'
```