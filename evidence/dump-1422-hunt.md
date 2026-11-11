# Охота за публичным дампом 14.20/14.22 (ядро / userland / модули / WebKit)

> Задача: task-19. Дата проверок: 2026-11-11. Сеть: `socks5h://127.0.0.1:10810`.
> Всё проверено HTTP-кодом; скачанное — с размером и хешем, файлы в `ps5jb/fw/`.
> Исходная гипотеза: kernel-дамп 14.2x невозможен (консоль не взломана), но userland-дамп (модули, WebKit, память процесса) реалистичен, если у кого-то работает вход через браузер.

## 1. Итог (TL;DR)

**Публичного дампа 14.20/14.22 не найдено — ни ядра, ни userland, ни модулей, ни WebKit.**
Проверено 10 запросов GitHub-поиска репозиториев + 2 кодовых, gist-поиск, 4 поисковых среза archive.org, два Telegram-канала через `t.me/s/`, psxhax, профильные репозитории людей, у которых подтверждён userland на 14.2x.
Единственный найденный публичный дамп модулей PS5 — **`ps5_prx_dump_403` (прошивка 4.03)**, скачан и проверен (п. 3.3), к 14.2x не относится, но доказывает: PRX-дампы с консоли в принципе публикуются.
Единственное «свежее» про 14.22 — **анонс-тизер в Telegram** («jailbreak with full fPKG support incoming»), без файлов и ссылок (п. 3.5).

## 2. GitHub: репозитории и код

Все запросы — `gh api "search/repositories?q=<q>"` / `search/code`, HTTP 200:

| Запрос | Что нашлось | Вывод |
|---|---|---|
| `kernel_1420` | `avonderg/cs1420-svm-kernels` (280 КБ, 2022), `LearningOS/oscomp-kernel-training-xyyy1420` (4 КБ, 2022) | не PS5 |
| `kernel_1422` | `UQJRlex/android_kernel_vivo_PD1422L_A` (209 МБ, 2025) | Android-ядро vivo, не PS5 |
| `14.22 dump` | 1 репозиторий FTP-over-UDP (160 КБ) | не относится |
| `memory.dmp PS5` | 0 | — |
| `PS5_1420`, `PS5_1422` | 0 | — |
| `ps5 sprx dump` | 0 | — |
| `webkit 14.22` | `karter-captain/ps5-14.22-browser-probes` (50 КБ) | только probe-страницы, не бинарь |
| `kdump ps5` | `earthonion/kdump_ps5` (31 КБ) | только инструмент («dumps ps5 kernel after hv defeat»), дампов нет |
| `PS5 14.20` | devravik/… (3,3 МБ), Khal0da/… (16,7 МБ), kevinisgoated24-spec/… (23 КБ), qraillife/PS5-WebKit-14.20 (153 КБ) | в деревьях только payload-ELF **13.60** и JS/HTML; файлов >1 МБ, кроме payload'ов, нет |
| `PS5 14.22` | karter-captain/…probes (50 КБ), qraillife/PS5-14.22-Jailbreak (0 КБ), qraillife/PS5-14.22-JB (7 КБ) | заглушки/probes, дампов нет |
| code: `"PS5UPDATE2"` | 23 совпадения: `uvatoc/…`, `ZigZagBoi1/PS5-14.10-Research` (`tools/pup14`, `docs/PUP_14_10_KERNEL_IMAGE_FEASIBILITY.md`), `zecoxao/ps5-pup-decrypt` | это инструменты/доки про **расшифровку PUP**, а не дампы |
| code: `14.22 extension:bin PS5` | 4 совпадения — модели ИИ и тестовые фикстуры | не относится |

Команды воспроизведения:
```bash
export HTTPS_PROXY=socks5h://127.0.0.1:10810
gh api "search/repositories?q=kernel_1422&per_page=5" --jq '.items[]? | "\(.full_name)|\(.size)KB"'
gh api "search/code?q=%22PS5UPDATE2%22&per_page=10" --jq '.total_count'
```

## 3. Остальные каналы

### 3.1 Gists
`https://gist.github.com/search?q=PS5+14.22` (**HTTP 200, 184 763 байт**) — один результат: gist `Amoenus/87d6c1bdbfac4dca23171afd7ce59602` (**HTTP 200**). Содержимое — логи проекта AnyPS5 (native depth, Vulkan loader), 5,2 МБ HTML, к дампам 14.2x отношения не имеет.
(Вариант с POST возвращает 422 — поиск gist'ов работает только GET-строкой.)

### 3.2 archive.org
| Запрос | HTTP | Результат |
|---|---|---|
| `PS5UPDATE` | 200 | `numFound: 0` |
| `PS5 kernel dump` | 200 | 4 записи: зеркала Byepervisor (2024), EglantinePS5 (2026-11-08), youtube, wichforks — **14.2x нет** |
| `"PS5" AND (dump OR "14.22" OR "14.20")` | 200 | 42 записи; релевантные: `ps5_prx_dump_403`, `ps5-kioskmode-idu-featgt7`, `KytyPS5` — **14.2x нет** |
| `"prx" AND "ps5" AND (dump OR dumped)` | 200 | 3 записи: `sharpemu` (×2), `ps5_prx_dump_403` |

### 3.3 Найденный и скачанный дамп: `ps5_prx_dump_403` (это НЕ 14.2x)
```bash
curl -x socks5h://127.0.0.1:10810 -L -o prx403.zip \
  https://archive.org/download/ps5_prx_dump_403/ps5_prx_dump_403.zip
# http=200 size=30058218
md5sum prx403.zip      # 1bfaa025c9d9756ab6c5fdaa38679738
sha256sum prx403.zip   # 3928e1d2d78b0488d64b1d468893bbf87df0fab6efab6c78e43f17e031069072
unzip -l prx403.zip | tail -3
# 261 файл, 97 371 972 байт распакованного: libkernel.sprx, libkernel_sys.sprx,
# libkernel_web.sprx, libSceAbstract*.sprx, libSceAgc*.sprx, libSceAcm.sprx …
```
Метаданные item'а: `title: ps5_prx_dump_403`, `description: 4.03 ps5 sprx`. Файл положен в `ps5jb/fw/ps5_prx_dump_403.zip`.
**Значение:** это ровно тот тип артефакта, который мы ищем (userland-модули `.sprx` с живой консоли), но прошивка **4.03**, а не 14.2x.

### 3.4 Профильные репозитории: что реально выложено
| Репозиторий | Проверка | Что внутри | Вывод |
|---|---|---|---|
| `ZigZagBoi1/PS5-14.10-Research` (`tools/pup14/README.md`, HTTP 200, 8 435 байт) | — | 14.10 recovery PUP скачан официально (1 418 890 240 байт, sha256 `9f3a0b88…`), **внешний слой расшифрован на джейлбрейкнутой 13.60 через `/dev/pup_update0`**; `kernel.bin` «complete and hash-matched», но **opaque, не plaintext-ядро**; 40 компонентов распаковано, один вложенный образ уронил распаковщик | дампов 14.2x нет; но есть метод и честная граница «outer decryption ≠ kernel» |
| `zecoxao/ps5-pup-decrypt` | code-search hits | инструмент расшифровки PUP (SDK/ELF), не дамп | инструмент |
| `elanonimo832/ps5-webkit-remote-loader` (README HTTP 200, 5 197 байт) | — | «Supports firmwares **7.00–13.60**»; в дереве только `poops.js`, `elfldr-ps5-v0.26.elf`, `selftest.js` | у человека с подтверждённым canvas-входом на 14.20 **нет** публичного дампа/тула под 14.2x |
| `karter-captain/ps5-14.22-browser-probes` (README HTTP 200, 1 012 байт) | 11 файлов HTML/JS | «Target: Firmware 14.22 (Slim + disc). Purpose: Observe browser behavior only. **No public exploit chain for 14.22 exists**» | probes, не дамп |
| `rohbatista18-sys/ps5-jb-tracker` | 491 КБ, 1 файл >100 КБ = `package-lock.json` | трекер новостей | дампов нет |

### 3.5 Telegram (доступно через `t.me/s/…`)
| Канал | HTTP / размер | Что найдено |
|---|---|---|
| `t.me/s/JAILBROKEN_PS4_PS5_UNIVERSAL` | 200, 127 826 байт | 3 упоминания «14.22»: пост **«PS5 firmware 14.22 jailbreak with full fPKG support incoming. KIMUNAKI and the Black Coat team just teased a release for tomorrow night. 14.22 is the firmware GTA 6 requires»** и подпись к фото «Hello 14.22 PS5». Ссылок на файлы/дампы в этих постах нет |
| `t.me/s/playstationjailbreakinfos` | 200, 98 708 байт | упоминаний 14.2x нет |

### 3.6 Форумы
- `https://www.psxhax.com/` — **HTTP 200**, 96 092 байта (жив).
- `https://www.psxhax.com/search/?q=14.22` — **HTTP 403** (Cloudflare) → поиск по форуму недоступен.
- `psdevwiki.com/ps5/Official_Firmware` — **HTTP 403** (Cloudflare), проверено ранее.

## 4. Сводная таблица «источник | что | проверка | вывод»

| Источник | Что искали | Проверка | Вывод |
|---|---|---|---|
| GitHub repos (10 запросов) | дампы/дамп-репозитории 14.2x | 200, деревья просмотрены | нет |
| GitHub code (2 запроса) | имена/пути дампов | 200 | нет (только PUP-инструменты) |
| Gists | ссылки/base64 на дамп | 200, 1 результат | не относится |
| archive.org (4 среза) | образы/дампы PS5 | 200 | 14.2x нет; есть 4.03 PRX (скачан) |
| Telegram (2 канала) | файлы/ссылки 14.2x | 200 | только анонс-тизер, файлов нет |
| psxhax | форум/поиск | 200 / 403 | поиск закрыт |
| psdevwiki | списки прошивок | 403 | закрыт |
| Репозитории людей с 14.2x userland | дампы/логи | 200 | probes/заглушки, дампов нет |
| `tools/pup14` (14.10 research) | дамп ядра из PUP | 200 | внешний слой расшифрован, ядро opaque; не 14.2x |

## 5. Честный вывод

1. **Публичного дампа 14.20/14.22 не существует** (ни kernel, ни userland, ни модулей, ни WebKit) по состоянию на 2026-11-11. Это не «не нашли» — проверены все каналы из задания, и отрицательный результат зафиксирован списком проверенного (раздел 4).
2. Косвенно это подтверждает нашу оценку: **код-исполнения на 14.2x публично ни у кого нет** (иначе ожидались бы хотя бы PRX/WebKit-дампы, как для 4.03). Тизер про «14.22 jailbreak incoming» в Telegram — бездоказательный анонс: ни файлов, ни адресов, ни логов.
3. Реалистичный путь к userland-дампу 14.2x: (а) самим получить вход через браузер (canvas/WebKit) и снять `libSce*.sprx` из процесса; (б) дождаться, пока кто-то из подтверждённых владельцев 14.20 (например, автор canvas-цепочки) выложит артефакт; (в) использовать наш 14.10-дамп (13.60) как эталон структуры для диффа, когда появится 14.2x.
4. По ядру 14.2x ожидание прежнее: пока нет jailbreak — нет и kernel-дампа; единственный публичный kernel-дамп — 13.60 (`ps5jb/fw/ps5-kernel-13.60-live.bin`, 103 546 880 байт, sha256 `c3f745e2…`).

## 6. Что мониторить (готовые команды)

```bash
export HTTPS_PROXY=socks5h://127.0.0.1:10810
# новые репозитории про 14.2x
gh api "search/repositories?q=PS5+14.22&sort=updated&per_page=20" --jq '.items[] | "\(.full_name)|\(.updated_at)"'
# новые gist'ы
curl -sS -A "Mozilla/5.0" "https://gist.github.com/search?q=PS5+14.22" | grep -oE 'gist.github.com/[^"]+' | head
# новые items archive.org
curl -sS "https://archive.org/advancedsearch.php?q=%22ps5%22+AND+%22prx%22&fl%5B%5D=identifier&fl%5B%5D=publicdate&sort%5B%5D=publicdate+desc&rows=10&output=json" | jq -r '.response.docs[] | "\(.identifier) \(.publicdate)"'
# телеграм-канал (обновления)
curl -sS -A "Mozilla/5.0" "https://t.me/s/JAILBROKEN_PS4_PS5_UNIVERSAL" | grep -oE "14\.2[02][^<]{0,80}" | head
```

---

# Часть 2. Соцканалы (вторая половина task-19)

Автор раздела: recon-1422-status, 2026-11-11 17:50–18:25, через `socks5h://127.0.0.1:10810`.
Дополняет разделы 1–6 выше (не переписывает их): здесь **форумы как канон**, YouTube, расширенный срез Telegram,
и честная фиксация того, что часть каналов оказалась недоступна.

## 7. ГЛАВНОЕ: канонический справочник сцены говорит про 14.XX то, чего нет в наших отчётах

**GBAtemp, «PS5 Exploit Guide»**, тред `threads/ps5-exploit-guide.613891/`, первый пост автора **KiiWii**,
**последняя правка — 2 ноября 2026** (день релиза 14.22). HTTP **200**, 573 479 б.

Дословные цитаты:

> `14.XX = No public KEX, HV/A53 patched in 14.20, UL ONLY (LUA/YARPE)`

> Hypervisor (HV):
> Highest released HV: **13.60**
> Highest unreleased HV: **14.00**
> *unreleased/unimplemented

> Kernel (KEX):
> Highest released KEX: **13.60 (ReLapse)**
> Highest unreleased KEX: **14.10 (Gezine)**

> Latest OFW: **14.22 (2/11/26)**

### 7.1 Сверка канона с нашими отчётами

| Утверждение GBAtemp (правка 2.11.2026) | Наши данные | Расхождение |
|---|---|---|
| «No public KEX» на 14.XX | публичного kernel-эксплойта нет | **совпадает** (task-3, task-9) |
| **«HV/A53 patched in 14.20»** | у нас записано «HV закрыт в **14.10**» по Sonic_Iso (task-3 §3.4, task-15 §2) | **КОНФЛИКТ ПО ДАТЕ** — см. 7.2 |
| «Highest unreleased HV: 14.00» | не было | новое |
| **«Highest unreleased KEX: 14.10 (Gezine)»** | было «статус на 14.x неизвестен» | **НОВОЕ**: у Gezine невыпущенный kernel-эксплойт именно для 14.10 |
| «Latest OFW: 14.22 (2/11/26)» | 14.22 = 2 ноября | **совпадает** |
| **«UL ONLY (LUA/YARPE)»** | наша рабочая гипотеза — вход через **WebKit/canvas** | **КОНФЛИКТ ПО ВЕКТОРУ**: WebKit в списке рабочих входов на 14.XX **отсутствует** |

### 7.2 Расхождение по дате закрытия гипервизора (требует решения)

- **Наши отчёты:** Sonic_Iso ~3–4 октября подтвердил, что HV-баг закрыт в **14.10**; спор с Jordy
  (который утверждал, что HV выжил) разрешён в пользу «патчено в 14.10» (task-3 §3.4, task-15 §2).
- **Канон GBAtemp (правка 2 ноября):** HV/A53 закрыт в **14.20**.

Возможные объяснения: (а) канон прав, и Sonic_Iso говорил о другом HV-пути; (б) канон упростил и
«14.20» означает «начиная с 14.20 точно закрыт»; (в) канон содержит ошибку. **Разрешить по нашим
источникам не удалось** — psdevwiki недоступен (403), первоисточник Sonic_Iso я не открывал.
**Помечаю как конфликт, а не как факт.** Если канон прав, то запись «HV закрыт в 14.10» в
[patch-history.md](patch-history.md) §2 требует исправления.

### 7.3 Расхождение по вектору входа (важнее для проекта)

Канон перечисляет для 14.XX только **LUA** (Lua-лоадер) и **YARPE**, а **WebKit не упоминает**.
Это не опровергает canvas-вектор напрямую (канон может не учитывать свежие исследования), но означает:
**сцена в целом не считает WebKit рабочим входом на 14.xx.** Наша ставка на canvas — это ставка
против консенсуса, и её надо либо подтвердить экспериментом, либо пересмотреть в пользу LUA/YARPE.

## 8. YouTube — контента много, но это новости и скам, не дампы

Поиск: `youtube.com/results?search_query=…` через socks (**HTTP 200**). Метаданные — через **oEmbed**
(`youtube.com/oembed`, работает без JS).

| Видео | Канал | Возраст | Заявка |
|---|---|---|---|
| `youtu.be/9Zz29tcsLhg` «Jailbreak News: 14.22 Released, GoldHEN on 14.00, CivSwitch, BD-JB Relapse, FPKG Update & More!» | **MODDED WARFARE** | 9 дн | самый релевантный: разбор 14.22 + «GoldHEN на 14.00» |
| `youtu.be/lV84a3trc-k` «PS5 Jailbreak News: 14.20 Update Released, FPKGS patched, PC games without Linux & More!» | MODDED WARFARE | 2 нед | 14.20 «FPKGS patched» |
| `youtu.be/VRb6KO1MOl0` «PS5 Jailbreak 14.22 Is A Scam.» | AGN | 5 дн | **прямо: «14.22 джейлбрейк — скам»** |
| `youtu.be/5WYpsc3u4B4` «PS5 Jailbreak 14.22 Is Fake.» | AGN | 1 дн | **то же, свежее** |
| `youtu.be/_sYYE8Qk17I` «PS5 Blackout Day 80 — 14.22 Jailbreak Cancelled?» | Blaze2K | 16 ч | «отменён?» |
| `youtu.be/ZuYFxr7adDU` «PS5 FW 14.22 Jailbreak Status 2026｜WebKit & Kernel Exploit Truth» | Lost Signal | 1 дн | «правда о WebKit/kernel» |
| `youtu.be/ZjgtEZjhVvE` «PS5 14.22/14.20 Jailbreak with GoldHEN｜How to Jailbreak PS5 14.22» | Ominis Gaming | **24 мин** | скам-туториал |
| `youtu.be/a9R_Ca8Gkc8` «14.20 FW Jailbreak PS5 HUGE NEWS! (Userland Exploit)» | Respawned | 2 нед | заявлен userland 14.20 |
| `youtu.be/y0Mjr9UbdoY` «Sony Made PS5 14.20+ IMPOSSIBLE To Jailbreak» | [after_dark] | 6 дн | драматизация |

**Описания прочитать не удалось — `ПРОБЕЛ`.** Причины проверены:
- `youtube.com/watch?v=…` через прокси отдаёт **consent-заглушку**: `shortDescription` в HTML — **0 совпадений**;
- `m.youtube.com` — только 50-символьный meta-description («Делитесь видео с близкими…»);
- Invidious/Piped (`inv.nadeko.net`, `invidious.nerdvpn.de`, `yewtu.be`) — **403**;
- `r.jina.ai` — **401** «blocked from anonymous queries due to bad network reputation (AS30058)».

**Вывод по YouTube:** по 14.22 идёт плотный поток роликов, но **ни один не заявляет публикацию дампа**.
Два независимых канала (AGN дважды) прямо называют «джейлбрейк 14.22» скамом/фейком. Это **аргумент
против** существования артефактов 14.2x в публичном доступе.

## 9. Telegram — расширенный срез (15 каналов)

Проверял через `t.me/s/<channel>`; **напрямую не работает (HTTP 000, DPI)**, только через socks.
Подсчёт вёлся **по тексту сообщений** (а не по всему HTML — иначе ловятся SVG-координаты иконок).

| Канал | HTTP | Размер | Сообщений / с 14.2x | Что это |
|---|---|---|---|---|
| `ps5_jailbreak` | 200 | 138 452 | 20 / **0** | персидский канал про GTA и эмуляторы Xbox 360; последние посты 26–31 окт |
| `ps5homebrew` | 200 | 21 910 | 1 / **0** | мёртв: единственный пост от **2022-11-11** |
| `etaHEN` | 200 | 46 127 | 6 / **0** | про payload'ы, 14.2x нет |
| `ps5linux` | 200 | 33 241 | 5 / **0** | Linux на PS5, 14.2x нет |
| `psxhax` | 200 | 31 330 | 3 / **0** | новости PSXHAX, 14.2x нет |
| `ps5jailbreaknews`, `PS5Jailbreak`, `ps5homebrewofficial`, `onejailbreakcom`, `ps4ps5jailbreak`, `ps5jailbreaking`, `PS5Modding` | 200 | 9,6–9,8 КБ | **0 / 0** | пустое веб-превью (канал закрыт либо без публичного превью) |
| `ps5jailbreak`, `PS5JailbreakNews` | **000** | — | — | не существуют |

**Замечание о методике:** первичная регулярка по всему HTML дала «1 упоминание» в двух каналах —
это оказались **координаты SVG-иконки Telegram** (`…14.549,15.965…14.068,15.748…`), а не текст постов.
После извлечения именно текста сообщений — **0 упоминаний 14.2x**. Урок: считать только по тексту.

**Расхождение с частью 1 (§3.5):** там найден канал `JAILBROKEN_PS4_PS5_UNIVERSAL` с тизером про
«14.22 jailbreak with full fPKG support incoming». В моём срезе его нет — я проверял другие каналы.
Оба результата верны и дополняют друг друга: **тизер есть, файлов/ссылок нет.**

## 10. archive.org — с контрольным опытом

| Запрос | numFound | Что нашлось |
|---|---|---|
| `PS5 14.22` | **0** | — |
| `PS5UPDATE 14.22` | **0** | — |
| `ps5 14.20` | **0** | — |
| `ps5 14.10` | **0** | — |
| `ps5 kernel dump 14` | 1 | нерелевантное зеркало `github.com-riyadhHDA-wichforks` |
| **`PS5 firmware dump` (контроль)** | **10** | только 2024–2025: `ps4-nor-validator`, `ps5-nor-tool`, `Byepervisor` |
| **`ps5 13.60 kernel dump` (контроль)** | **1** | зеркало GitHub, не сам дамп |

**Зачем контроль:** он доказывает, что метод рабочий — по общим строкам archive.org отдаёт 10 записей.
Значит `0` по 14.2x — это **реальное отсутствие**, а не сломанный запрос. Согласуется с частью 1 (§3.2),
где похожим образом найден `ps5_prx_dump_403` (4.03) и не найдено ничего по 14.2x.

## 11. Что оказалось недоступно (влияет на полноту охвата)

| Канал | Что произошло |
|---|---|
| DuckDuckGo HTML | после ~15 запросов — **captcha** («Select all squares containing a duck», HTTP 202) |
| Mojeek | **403 / captcha** |
| Bing | **200, но гео-мусор**: на «PS5 14.22 kernel dump» выдал санаторий «Мыс Видный» и фильм «14+» |
| Встроенный веб-поиск | тоже русскоязычный мусор (товары, статья про число 14) |
| pastebin / hastebin | **нет публичного поиска**; веб-поиск (которым ищут ссылки) заблокирован → `ПРОБЕЛ` |
| mega / 1fichier / торренты | нет открытого поиска по содержимому, а веб-поиск заблокирован → `ПРОБЕЛ` |
| Приватные Telegram / Discord | требуют аккаунт → `НЕДОСТУПНО` |

**Честно:** охват «длинного хвоста» (pastebin, файлопомойки, торренты, приватные каналы) **неполный**.
Всё найденное получено через каналы с детерминированным доступом: GitHub API, archive.org API,
прямые URL (GBAtemp, PSXHAX, Telegram, YouTube) и oEmbed.

## 12. Вывод части 2

1. **Дамп 14.2x не найден** — подтверждаю вывод части 1 независимым проходом по другим каналам
   (форумы, YouTube, 15 Telegram-каналов, archive.org с контролем).
2. **Ценнее дампа оказался канон GBAtemp** (правка 2.11.2026): он даёт три вещи, которых у нас не было —
   (а) дату закрытия HV как **14.20** (конфликт с нашим 14.10), (б) **невыпущенный KEX для 14.10 у Gezine**,
   (в) **невыпущенный HV для 14.00**, — и одну вещь, которая бьёт по нашей страте:
   (г) на 14.XX канон считает рабочим входом только **LUA/YARPE, не WebKit**.
3. **YouTube по 14.22 = шум и скам**: два канала прямо называют «14.22 jailbreak» фейком; ни одного
   заявления о дампе. Описания прочитать не удалось (consent-заглушка, Invidious 403, jina 401).
4. Искать дамп дальше в открытых каналах **бесперспективно**. Реальные пути к артефактам 14.2x —
   свой PUP (`fw/`, см. [pup-diff.md](pup-diff.md)) и своя консоль; либо ждать публикации от владельца
   невыпущенного эксплойта (Gezine — 14.10).
5. **Два пункта на перепроверку перед продолжением:** дата закрытия HV (14.10 vs 14.20) и
   работает ли WebKit на 14.xx вообще (канон говорит, что нет).

### 12.1 Честные пробелы части 2

1. **Описания YouTube** — не прочитаны; ссылки оттуда не извлечены.
2. **Файлопомойки, торренты, pastebin** — не проверены (нет поиска + веб-поиск заблокирован).
3. **Приватные Telegram/Discord** — недоступны.
4. **PSXHAX поиск** — 403, треды по 14.22 не перебирал.
5. **Конфликт HV 14.10 / 14.20 не разрешён** — нужен первоисточник Sonic_Iso или второй канон
   (psdevwiki 403).
6. **Канал `JAILBROKEN_PS4_PS5_UNIVERSAL`** из части 1 я не проверял — не пересекались.