# Служебные каналы 14.2x: devkit / testkit / service / kiosk / диски

**Задача:** task-18 · **Агент:** recon-fw-exists
**Начато:** 2026-11-11 17:50 MSK · **Срез:** 18:00 MSK
**Машина:** Linux Nobara, root НЕТ, сеть через `socks5h://127.0.0.1:10810`

**Базовая линия (что уже есть на диске):**
- `fw/PS5UPDATE-sys-2026_1027.PUP` — retail **sys 14.22**, 1 266 091 008 байт, sha256 `b0d5818d…a810b`
- `fw/PS5UPDATE-rec-2026_1027.PUP` — **rec (recovery) 14.22**, 1 423 697 408 байт, sha256 `42ea0e5aad1361e098837d40157863c4c519f0bbc66eb03c04dbaaf339b063fb`

> Правило: каждое утверждение — с HTTP-кодом/размером/хешем. Отсутствие подтверждено перечнем проверенного.

---

## ГЛАВНЫЙ ВЫВОД

**Служебного канала с образом 14.2x найти не удалось — ни одного.** Проверены devkit/testkit-хосты (в DNS
не существуют), подмена сегмента канала в URL (все → 404), портал partners (catch-all заглушка), зеркало
апдейт-листов (только retail), живой `/list/`-эндпоинт (закрыт с сентября), поиск SDK/диск-утечек на GitHub
(прошивок нет), kiosk/IDU (это режим, а не отдельная прошивка).

**Что реально доступно сверх retail sys — это только recovery-образ, и он уже у нас.**
Более того, доказано, что rec **не содержит другой сборки ядра**: его `PS5UPDATE1.PUP` **побайтово совпадает**
с sys-файлом (один и тот же sha256), а разница — только добавленный `PS5UPDATE2.PUP` (157 606 077 байт).
Значит «служебность» recovery — это не другая защита ядра, а дополнительный сервисный сегмент.

---

## Итоговая таблица каналов

| канал | что проверял | результат (код/размер/хеш) | даёт ли что-то сверх retail sys 14.22 |
|---|---|---|---|
| **devkit / testkit хосты** | DNS + HTTPS для `ps5-devkit / ps5dekit / ps5-testkit / ps5testkit / ps5-service / ps5-dev / devkit / testkit .update.playstation.net` | **все 8 — NXDOMAIN**, `http=000` (не резолвятся); резолвятся только `pc.ps5…` (2.22.50.145), `dus01.ps5…`, `gs-sec…`, `partners.playstation.net` (62.115.253.130) | **НЕТ** — хостов не существует |
| **подмена сегмента канала в URL** | `dus01…/update/ps5/<channel>/<token>/image/2026_1027/sys_<hash>/PS5UPDATE.PUP?dest=us` для channel = official, devkit, testkit, service, kiosk, retail, prospero, manufacturing, beta | `official` → **200**; все остальные 8 → **404** | **НЕТ** — существует ровно один канал `official` |
| **partners.playstation.net** (портал SDK/devkit) | `/`, `/ps5/`, `/ps5/devkit/`, `/prospero/`, `/sdk/`, `/zzz-nonexistent-12345/` | все → **200**, тело **4514 байт**, sha256 у всех **одинаковый** (`7e5bf90f20787481…`) ⇒ **catch-all заглушка входа** | **НЕТ** — 200 здесь ничего не доказывает, PUP нет |
| **зеркало апдейт-листов (MewX)** | 53 файла `updatelist.*`, 14 регионов, 6 файлов investigations | в `README` **0** упоминаний devkit/testkit/service/kiosk/idu/manufacturing/channel/token/partner; в XML 14.22 **ровно один** `<system_pup>` и **один** `<image>` (sys) | **НЕТ** — зеркало чисто retail |
| **живой `/list/` эндпоинт** | `fus01…/update/ps5/official/<token>/list/us/` и `dus01…` (по данным investigations от сентября 2026 там был 200 XML) | сейчас **404** на обоих хостах ⇒ эндпоинт закрыли | **НЕТ** (и раньше отдавал только retail-список) |
| **подбор токена** | `tJMRE80IbXnE9YuG0jzTXgKEjIMoabr6` vs `TJMRE…`, `…abrf`, `aaaa…`, `x`, пустой | 200 только у точного; остальные **404** | **НЕТ** — токен канала не подбирается |
| **SDK-утечки / devkit-прошивки (GitHub)** | поиск `PS5 devkit firmware`, `PS5 testkit`, `prospero sdk ps5` | `PS5-Devkit-Testkit-Console-Manager` (клиент-менеджер консолей, не прошивка), `SharpProspero`/`Prospero-Explorer` (homebrew SDK), `ESP32-S3-Hosts` (офлайн WebKit-хост) | **НЕТ** — ни одного PUP/образа |
| **kiosk / IDU** | локальные recon-материалы, поиск по словам с границами | найдено только: «PS5 system registry stores console settings including **IDU mode** and debug flags» (syscall 532 `regmgr`) ⇒ IDU — **режим/флаг в реестре**, а не отдельная прошивка | **НЕТ** — образа IDU 14.2x не существует в доступе |
| **service / manufacturing** | хосты + путь + токен (см. выше) | публичных хостов/путей нет; ближайший реальный артефакт — **recovery PUP**, он у нас есть | **НЕТ** сверх rec (см. ниже) |
| **диски (Blu-ray)** | логика + доступные артефакты | дисковый апдейт нёс бы **тот же** подписанный retail `PS5UPDATE.PUP` того же формата; проверить эмпирически нельзя (нет консоли/привода/диска) | **НЕТ** — по построению это тот же retail-артефакт; **не проверено эмпирически** |

---

## 1. Почему rec 14.22 — не «другой канал», а тот же sys + один сегмент

Разбор BLS-заголовков обоих файлов:
```
  sys 14.22: magic=0x32424C53 ver=3 flags=0x00010000 file_count=1 block_count=2472834  bc*512=1266091008
     entry[0] block_offset=2 (0x400) size=1266089597 name='PS5UPDATE1.PUP'
  rec 14.22: magic=0x32424C53 ver=3 flags=0x01010000 file_count=2 block_count=2780659  bc*512=1423697408
     entry[0] block_offset=2 (0x400) size=1266089597 name='PS5UPDATE1.PUP'
     entry[1] block_offset=2472834 (0x4B770400) size=157606077 name='PS5UPDATE2.PUP'
```
Обратите внимание: `size` у `PS5UPDATE1.PUP` в sys и rec **совпадает до байта** (1266089597).

Побайтовая проверка общего региона (с контролем, что `cmp` вообще видит различия):
```
$ cmp -n 4096 -i 1024:2048 A B
A B differ: byte 1, line 1        <- контроль: cmp различает, exit=1

$ cmp -n 1266089597 -i 1024:1024 sys rec ; echo exit=$?
exit=0                            <- общий регион идентичен

$ sha256 региона (skip=1024, count_bytes=1266089597)
  sys region sha256 = 7056fe13f5242b146d4941a277ca758a91c885c7aef5f3db0ffdee84b7f668b1
  rec region sha256 = 7056fe13f5242b146d4941a277ca758a91c885c7aef5f3db0ffdee84b7f668b1
  РАВНЫ -> PS5UPDATE1.PUP общий для sys и rec
```
*Примечание честности:* первая попытка посчитать эти хеши была испорчена — я передал `dd count` в блоках
вместо байт и получил разные хеши; после исправления (`iflag=skip_bytes,count_bytes`) значения совпали,
что подтверждается независимо через `cmp` с exit=0.

**Вывод:** recovery-образ = sys-образ (тот же `PS5UPDATE1.PUP`, sha256 региона `7056fe13…`) **плюс**
`PS5UPDATE2.PUP` на 157 606 077 байт (+710 байт хвоста). Другой сборки ядра, другой подписи или другой
схемы защиты там нет — значит recovery не даёт обхода защиты и не является «другим каналом».

---

## 2. Перечень всего проверенного (для подтверждения отсутствия)

**DNS (getent hosts) — 13 хостов:**
```
ps5.update.playstation.net            НЕ РЕЗОЛВИТСЯ
ps5-devkit.update.playstation.net     НЕ РЕЗОЛВИТСЯ
ps5dekit.update.playstation.net       НЕ РЕЗОЛВИТСЯ
ps5-testkit.update.playstation.net    НЕ РЕЗОЛВИТСЯ
ps5testkit.update.playstation.net     НЕ РЕЗОЛВИТСЯ
ps5-service.update.playstation.net    НЕ РЕЗОЛВИТСЯ
ps5-dev.update.playstation.net        НЕ РЕЗОЛВИТСЯ
devkit.update.playstation.net         НЕ РЕЗОЛВИТСЯ
testkit.update.playstation.net        НЕ РЕЗОЛВИТСЯ
partners.playstation.net              62.115.253.130      (200, catch-all)
pc.ps5.update.playstation.net         2.22.50.145         (403 на корне)
dus01.ps5.update.playstation.net      резолвится          (403 на корне)
gs-sec.ww.np.dl.playstation.net       96.17.7.202         (404 на корне)
```

**Прочее:** `gs-sec…/plo/np/PPSA01284_00/PS5UPDATE.PUP` → 404 (проверено ранее в этой сессии).

---

## 3. Что из этого следует практически

1. **Скачивать больше нечего.** Максимум, что даёт официальный мир для 14.22 — это sys и rec, оба уже в `fw/`.
2. **Обход защиты через служебный канал не подтверждается.** Даже recovery-образ содержит тот же
   зашифрованный `PS5UPDATE1.PUP` (идентичный retail), т.е. та же схема, что мы разбирали в
   `recon/pup-decrypt-feasibility.md`.
3. **Единственный известный «лишний» артефакт** — `PS5UPDATE2.PUP` (157.6 МБ) внутри rec. Это кандидат
   на отдельный разбор (другой сегмент, возможно иные записи), но он с той же защитой.
4. **Не проверено эмпирически (честно):** диск-апдейт (нет консоли/привода/диска), devkit-канал
   (требует партнёрской авторизации Sony — доступ закрыт), IDU-образ (публично не существует).

## 4. ВЕРДИКТ

Ни один служебный канал (devkit, testkit, service, manufacturing, kiosk/IDU, диски, SDK-утечки) **не даёт
образа 14.2x, отличного от retail sys/rec**, которые у нас уже есть. Все проверяемые точки входа либо не
существуют в DNS, либо отдают 404, либо являются catch-all заглушкой. Единственное отличие recovery от
retail — дополнительный сегмент `PS5UPDATE2.PUP`, при идентичном (побайтово) основном payload.