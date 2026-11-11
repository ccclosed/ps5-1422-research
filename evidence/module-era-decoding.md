# Как датировать системные модули из игровых дампов (проверено на реальных файлах)

## Декодер версии из param.json (взят из KytyPS5)

`src/launcher/src/configurationListWidget.cpp:525-545`:

```cpp
static QString GetFirmwareVersion(const QJsonObject& root) {
    const auto encoded = GetJsonString(root, QStringLiteral("requiredSystemSoftwareVersion"));
    static const QRegularExpression version_pattern(
        QStringLiteral("^0[xX]([0-9]{6})[0-9A-Fa-f]{10}$"));
    const auto match = version_pattern.match(encoded);
    if (!match.hasMatch()) return {};
    const auto digits = match.captured(1);          // 6 ДЕСЯТИЧНЫХ цифр
    const int  major  = digits.left(2).toInt(&valid, 10);
    QString    version = QStringLiteral("%1.%2").arg(major).arg(digits.mid(2, 2));
    const auto patch   = digits.mid(4, 2);
    if (patch != QStringLiteral("00")) version += QStringLiteral(".") + patch;
    ...
```

То есть `0x` + 6 десятичных цифр = `MMmmpp` + 10 произвольных hex-цифр.

## Калибровка на реальных файлах

| Игра | param.json | requiredSystemSoftwareVersion | sdkVersion | вердикт | build-путь модуля | размер libc.prx |
|---|---|---|---|---|---|---|
| Code Violet PPSA26528 v01.028 | есть | `0x1270000000000000` | `0x1100000000000000` | **FW 12.70, SDK 11.00** | `W:/Build/J03547016` | 1 911 850 |
| Cyberpunk 2077 PPSA04029 v02.120 | нет (в образе) | — | — | эпоха ~08.60 (по локальному research) | `W:/Build/J01625764` | 1 352 554 |

**Следствие:** Code Violet, несмотря на дату загрузки 2026-11-10, мастерился под **SDK 11.00 / FW 12.70** —
это НЕ 14.x-эпоха. Дата загрузки на archive.org ≠ дата мастеринга.

## Что нужно, чтобы получить модули 14.x-эпохи

Игра должна иметь `requiredSystemSoftwareVersion` ≥ `0x1260...`−`0x1422...`, то есть быть смастеренной
на SDK 13.x–14.x. Такие игры — релизы конца 2026 (в том числе GTA 6, которому нужен 14.22).
Проверять надо именно `param.json` из дампа, а не дату загрузки.

## Обозначение сборок Sony (build-путь)

`W:/Build/J<8 цифр>/...` — номер сборочного дерева Sony, растёт со временем:
`J01625764` (эпоха 8.x) → `J03547016` (эпоха 11.00). Значит по номеру можно грубо датировать модуль,
если известна калибровка. Нужны ещё точки: модули из дампов с известным `requiredSystemSoftwareVersion`.
