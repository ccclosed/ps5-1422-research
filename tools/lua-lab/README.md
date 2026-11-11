# Lua-lab (вектор PS5 Lua 5.1 / TCP 9026) — ПК-проверки без консоли

Лаборатория воспроизводит **всё, что можно проверить на ПК** по второму вектору входа
(сохранение Hamidashi Creative Demo → `remote_lua_loader` → TCP 9026). Консоль не нужна.

Источник протокола — опубликованный загрузчик `n0llptr/remote_lua_loader`
(`savedata/main.lua`): кадр `<u64 LE size><Lua source>`, команда
`<u64 LE 0xFFFFFFFF><u8 cmd>` (0 — выключить signal handler, 1 — включить), кадр краха
`<u64 LE 0x13371337><u64 signal><u64 fault_addr><0x100 bytes mcontext>`, `maxsize = 500 KiB`.

## Быстрый старт

```bash
cd ps5jb/tools/lua-lab
./run.sh                 # все проверки одной командой, итог в конце
./run.sh --install-deps  # если lupa не установлена (pip --user, root не нужен)
./run.sh --repo /path/to/PS5-14.10-Research --port 9026
```

Код возврата 0 — только если прошли **все** шаги. Полный лог: `output/run.log`.

## Что внутри

| Файл | Назначение |
|---|---|
| `mock_loader.py` | mock-сервер порта 9026: разбирает кадры, отвечает баннером и синтетическим кадром краха. Запуск вручную: `python3 mock_loader.py --port 9026`, `--once`, `--no-crash` |
| `lab_client.py` | клиент: шлёт payload/command/oversized кадры и **разбирает** ответ, включая `mcontext` (29 полей). `python3 lab_client.py HOST PORT` |
| `protocol_selftest.py` | поднимает mock на свободном порту (по умолчанию 9026), гоняет 6 проверок, печатает PASS/FAIL |
| `syntax_lua51.py` | компилирует корпус `probes/**/*.lua` настоящим Lua 5.1 (lupa), без исполнения |
| `offline_suite.py` | обёртка над `tools/verify_offline.py` исследовательского чекаута (356 тестов, stdlib) |
| `run.sh` | прогоняет шаги 0–3 и печатает сводную таблицу |

## Зависимости

- `python3` ≥ 3.10 (проверено на 3.14.7);
- `lupa==2.6` — только для шага 2: `python3 -m pip install --user lupa==2.6`;
  если PyPI недоступен напрямую, wheel качается через прокси:
  `curl -x socks5h://127.0.0.1:10810 -O <wheel-url>` и `pip install --user --no-index --find-links=. lupa==2.6`;
- исследовательский чекаут для шагов 2–3:
  `git clone --depth 1 https://github.com/ZigZagBoi1/PS5-14.10-Research ps5jb/recon/_src/lua/zz`
  (путь можно переопределить `--repo`).

## Что это доказывает и чего не доказывает

Доказывает: кадрирование и длины, командный канал, разбор кадра краха и `mcontext`,
совместимость корпуса проб с Lua 5.1, зелёный offline-набор исследователей.

**Не доказывает:** работу на реальной консоли вообще и на 14.2x в частности — `memory.*`,
`make_syscall`, `thr_create`, GPU mmap, CClosure/native-вызовы и kernel R/W существуют только
в PS5-ELF и требуют консоли. Ограничение зафиксировано в `recon/lua-vector.md` §4.5.