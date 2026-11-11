# OOB-read каналы WebKit 7617 (Sony-порт 14.22) → утечка байтов в JS

Источники зафиксированы на теге **WebKit-7617.1.11** = commit `7779ac11f20e70a21d82dedd3ba0334fba850f06`
(скачаны `raw.githubusercontent.com`; ссылки ниже — permalink на этот commit). Всё, что не проверено по коду, помечено **[не проверено]**.

## A. Механизмы OOB-read и возврата данных в JS (проверено по исходникам 7617)

| механизм | можно ли прочитать за границей | данные возвращаются в JS? | PoC | применимость к 14.22 |
|---|---|---|---|---|
| **APNG: кадр больше canvas** (`fcTL` width/height/xOffset/yOffset) | **Нет — закрыто в 7617**: проверка `m_xOffset + m_width > width` / `m_yOffset + m_height > height` ([PNGImageDecoder.cpp#L645-L649](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/png/PNGImageDecoder.cpp#L645-L649)) + clamp frameRect ([#L815-L821](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/png/PNGImageDecoder.cpp#L815-L821)) | был бы через canvas→getImageData | см. `probes/v918_apng_overread2.html` | **закрыто**, канал не наш |
| **GIF: кадр со смещением за пределы экрана** | **Да, кандидат**: `setSize` растёт по `max(width,height)`, но **не по xOffset/yOffset** ([GIFImageReader.cpp#L645-L700](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/gif/GIFImageReader.cpp#L645-L700)); clamp считает `size().width() - xOffset` → **отрицательная ширина** ([GIFImageDecoder.cpp#L812-L821](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/gif/GIFImageDecoder.cpp#L812-L821)) и `setFrameRect` сохраняет её в release ([ImageBackingStore.h#L77-L81](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/graphics/ImageBackingStore.h#L77-L81) — только `ASSERT`) | да, если отрисовка/`pixelAt` прочитает пиксели → canvas→getImageData | нет публичного PoC | **высокая** (нужен PoC) |
| **`ImageBackingStore` как усилитель** | `setFrameRect` и `pixelAt` проверяют границы только `ASSERT` ([ImageBackingStore.h#L77-L81](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/graphics/ImageBackingStore.h#L77-L81), [#L133-L137](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/graphics/ImageBackingStore.h#L133-L137)) — release не проверяет | да (через пиксели) | — | **высокая** (общий множитель для любого декодера с кривым rect) |
| **`getImageData(sx,sy,sw,sh)` с отрицательными/огромными аргументами** | отрицательные `sw/sh` нормализуются, дальше `ImageBuffer::getPixelBuffer` клипует | да (ImageData) | — | **закрыто** в 7617 ([CanvasRenderingContext2DBase.cpp#L2425-L2473](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/html/canvas/CanvasRenderingContext2DBase.cpp#L2425-L2473)) |
| **JSC: подделка длины массива** (Butterfly `IndexingHeader`) | да: `publicLength`/`vectorLength` — обычные `uint32` в butterfly ([IndexingHeader.h#L47-L65](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/JavaScriptCore/runtime/IndexingHeader.h#L47-L65), [Butterfly.h#L166-L169](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/JavaScriptCore/runtime/Butterfly.h#L166-L169)) | да, если есть запись в butterfly | нужна запись; сам JSArray — 16 байт без полей ([JSArray.h#L36-L47](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/JavaScriptCore/runtime/JSArray.h#L36-L47)), длина живёт только в butterfly | **второй этап** (усилитель) |
| **Fonts (CSSFontFace/WOFF2), RopeBuilder, DOMParser/XML, MediaSource** | [не проверено] | как правило **нет** прямого возврата сырых байтов в JS | — | низкая |
| **WebCodecs `VideoFrame.copyTo`/`AudioData.copyTo`** | [не проверено] | да, если фича включена на 14.22 | — | проверить флаги |

## B. История CVE (7617-эпоха и позже)

| CVE | что | исправлено в 7617? | вывод |
|---|---|---|---|
| **CVE-2025-13502** (NVD, 2025-11-25, CWE-125) | WebKitGTK/WPE: OOB read + integer underflow, **только DoS** (крэш UIProcess) через GLib remote inspector ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-13502), [webkit bug 302218](https://bugs.webkit.org/show_bug.cgi?id=302218)) | позже 7617 → в порте Sony вероятно есть | **не наш канал**: инспектор не доступен из web content, данные не возвращаются в JS |
| CVE-2023-42916 (Safari 17.1.2, OOB read) | «processing web content may disclose sensitive information» | 7617 новее → исправлено | не применимо; проверить, что Sony не откатила патч **[не проверено]** |

## C. Два самых перспективных канала (конкретно)

### 1. GIF frame-rect OOB → пиксели в canvas → `getImageData`
* Объект-носитель: `GIFFrameContext` (xOffset/yOffset/width/height) + `ImageBackingStore` (frameRect).
* Что подделать: соотношение «размер экрана ↔ смещение кадра». `GIFImageReader` расширяет экран только до `max(width,height)` ([#L699-L700](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/gif/GIFImageReader.cpp#L699-L700)), смещения не учитывает; clamp даёт отрицательную ширину ([GIFImageDecoder.cpp#L818-L821](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/gif/GIFImageDecoder.cpp#L818-L821)); `setFrameRect` не проверяет в release ([ImageBackingStore.h#L77-L81](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/graphics/ImageBackingStore.h#L77-L81)).
* Что читаем: пиксели за границей буфера `ImageBackingStore` через `pixelAt` (ASSERT-only) при отрисовке/`frameRect`-операциях → в canvas → `getImageData`/`toDataURL` отдаёт их в JS.
* Риск: `haveDecodedRow` рано выходит при `xEnd <= xBegin` ([#L204-L212](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/gif/GIFImageDecoder.cpp#L204-L212)) — строки вне буфера не пишутся; нужно подтвердить именно **чтение** на пути отрисовки (PoC).

### 2. Усилитель: подделка `IndexingHeader` у Butterfly (JSArray length)
* Объект: `JSArray` (16 байт: `JSCell` 8 + `m_butterfly` 8, [JSCell.h#L286-L289](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/JavaScriptCore/runtime/JSCell.h#L286-L289), [JSObject.h#L1246](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/JavaScriptCore/runtime/JSObject.h#L1246)); длина — `publicLength`/`vectorLength` в `Butterfly`+`IndexingHeader` ([IndexingHeader.h#L47-L65](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/JavaScriptCore/runtime/IndexingHeader.h#L47-L65)).
* Техника: записать в `publicLength`/`vectorLength` больше реального → `arr[i]` читает соседние `EncodedJSValue` → утечка указателей через `Float64Array`/арифметику.
* Блокер: нужна запись; canvas-UAF зануляется при free (`zero-at-free`, v931=100%), поэтому канал — вторая ступень после любой записи/порчи.

## D. Что проверить дальше (локально, WebKitGTK 2.52.5 post-fix)
1. `probes/v918_apng_overread2.html` — ожидаемо 0 (APNG закрыт, §A) — это контроль, что стенд не врёт.
2. GIF-кандидат: сгенерировать GIF: screen 1×1, image descriptor с xOffset=65000/width=2 → в release-frameRect отрицательный; смотреть, доходят ли пиксели до `getImageData` (в 2.52.5 может быть уже исправлено — тогда проверить на эмуляции 7617).
3. ICO/BMP/TGA: прогнать те же «frameRect > size» идеи (декодеры не проверял — [#L133-L137] ASSERT-only общий).

## E. Другие декодеры того же класса (ASSERT-only границы) — проверено по 7617.1.11

Важно: `ASSERT_WITH_SECURITY_IMPLICATION` — no-op, если не включён `ENABLE(SECURITY_ASSERTIONS)`
([Assertions.h#L351-L362](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WTF/wtf/Assertions.h#L351-L362)) — в релизной сборке PS5 почти наверняка выключен, т.е. это «ASSERT-only».

| формат | механизм | read/write | ASSERT-only? | строки | приоритет |
|---|---|---|---|---|---|
| **WebP (animated)** | буфер декодера выделяется по размерам кадра **из контейнера** (demux), а libwebp декодирует по размерам **из битстрима**; при расхождении — запись мимо external-буфера; затем `applyPostProcessing` читает со stride `frameRect.width()`, но x до `decodedWidth` → чтение мимо буфера | **write + read** | да (#L271-L272) | [WEBPImageDecoder.cpp#L184-L196](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/webp/WEBPImageDecoder.cpp#L184-L196), [#L265-L285](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/webp/WEBPImageDecoder.cpp#L265-L285) | **P0** |
| **AVIF (animated)** | `rowBytes = imageSize.width()*4`, `pixels = pixelAt(0,0)`, затем `avifImageYUVToRGB` пишет `image->height` строк по `image->width`; `imageSize` — от первого изображения (`setSize`), размеры кадра — из битстрима | write (+ чтение через canvas) | явных проверок нет | [AVIFImageReader.cpp#L58](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/avif/AVIFImageReader.cpp#L58), [#L87-L101](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/avif/AVIFImageReader.cpp#L87-L101) | P1 |
| **GIF** (уже в §C) | отрицательная ширина frameRect → `setFrameRect` без проверки; чтение на пути отрисовки | read (write заблокирован) | да | [ImageBackingStore.h#L77-L81](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/graphics/ImageBackingStore.h#L77-L81) | P1 |
| **ICO** | `setSize` требует `size == m_frameSize`, иначе fail; размеры ≤256 | нет | — | [ICOImageDecoder.cpp#L80-L84](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/ico/ICOImageDecoder.cpp#L80-L84) | P3 (закрыто) |
| **BMP** | размеры из info-header проходят `isInfoHeaderValid()` до `setSize`; запись строк в пределах объявленного размера | нет (консистентно) | нет | [BMPImageReader.cpp#L139-L170](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/bmp/BMPImageReader.cpp#L139-L170) | P3 |
| **JPEG** | размеры из libjpeg; scaled-путь читает `pixelAt(0, sourceY)`; расхождение возможно только при ошибке масштабирования | read? | [не проверено] | [JPEGImageDecoder.cpp#L621](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/jpeg/JPEGImageDecoder.cpp#L621), #L644-L660 | P2 |
| **PNG/APNG** | закрыто (проверка fcTL + clamp), см. §A | — | — | [PNGImageDecoder.cpp#L645-L649](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/png/PNGImageDecoder.cpp#L645-L649) | P3 |
| **TGA** | в 7617 декодера нет (`tga/TGAImageDecoder.cpp` → 404 в теге) | — | — | — | — |

### Два лучших PoC-сценария (для webkit-1422)

**PoC-1: animated WebP, расхождение «контейнер ↔ битстрим» (write + read).**
Собрать RIFF/WEBP: `VP8X` canvas 32×32; `ANMF` кадр с полями x=0,y=0,**w=8,h=1**, payload = VP8-битстрим с заголовком **16×1**.
* WebKit выделит external-буфер `8*4*1 = 32 Б` ([#L186-L189](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/webp/WEBPImageDecoder.cpp#L184-L196)), а libwebp запишет 16 px = 64 Б → **32 Б OOB-write** (класс «порча памяти», без знания адреса);
* затем цикл `applyPostProcessing` идёт `x < decodedWidth(16)` со stride 8 ([#L270-L285](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/webp/WEBPImageDecoder.cpp#L270-L285)) → читает смещения 32..63 мимо буфера; эти байты пишутся в canvas (`pixelAt(canvasX=0..15)` внутри canvas 32) → `getImageData` отдаёт их в JS = **утечка**.
* Калибровка: начать с w=8/h=1 ↔ битстрим 9×1 (8 Б OOB), затем расширять `decodedWidth` до 16–24, наблюдая крэши (окно утечки и размер OOB-write растут вместе).

**PoC-2: AVIF, кадр больше canvas (write→возможная утечка).**
Собрать AVIF: primary image (canvas) 32×32, но кадр (`iloc`/`ispe` кадра) объявить 64×64. `avifImageYUVToRGB` получит `image->width/height` кадра, а `rowBytes` — от canvas ([AVIFImageReader.cpp#L100-L101](https://github.com/WebKit/WebKit/blob/7779ac11f20e70a21d82dedd3ba0334fba850f06/Source/WebCore/platform/image-decoders/avif/AVIFImageReader.cpp#L100-L101)): строки пойдут с шагом canvas-ширины → и переполнение backing store, и «диагональное» искажение; читать результат через `getImageData`. Требует проверить, что libavif не режет кадр по canvas (в 7617 проверки в AVIFImageReader нет).