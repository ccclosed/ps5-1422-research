#!/usr/bin/env python3
"""Offline self-test for bundle-1422: run probe_14xx_entry.lua under Lua 5.1 with a stub loader.

Proves the probe's *logic* on a PC (no console, no network):
  * the source compiles as Lua 5.1 (lupa);
  * with a stub `memory`/`syscall` that mimics the loader API, every STAGE reports OK
    and the completion marker is printed.

Requires lupa (optional dependency, same as the lab's Lua 5.1 gate):
    python3 -m pip install --user lupa==2.6

    python3 selftest.py
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROBE = HERE / "probe_14xx_entry.lua"

STUB_PRELUDE = r"""
-- minimal stand-in for the parts of the loader the probe touches
_emit = print
_out = {}
print = function(s) _out[#_out + 1] = tostring(s) end

STORE = {}
NEXT = 0x100000

function _alloc(size)
  local a = NEXT
  NEXT = NEXT + size + 0x10
  for i = 0, size - 1 do STORE[a + i] = 0 end
  return a
end

memory = {
  alloc = function(size) return _alloc(size) end,
  read_dword = function(addr)
    return (STORE[addr] or 0) + (STORE[addr+1] or 0) * 0x100
         + (STORE[addr+2] or 0) * 0x10000 + (STORE[addr+3] or 0) * 0x1000000
  end,
  read_byte = function(addr) return STORE[addr] or 0 end,
  read_qword = function(addr) return memory.read_dword(addr) end,
  write_dword = function(addr, v)
    STORE[addr]   = v % 0x100
    STORE[addr+1] = math.floor(v / 0x100) % 0x100
    STORE[addr+2] = math.floor(v / 0x10000) % 0x100
    STORE[addr+3] = math.floor(v / 0x1000000) % 0x100
  end,
  write_qword = function(addr, v) memory.write_dword(addr, v) end,
  write_byte = function(addr, v) STORE[addr] = v % 0x100 end,
  read_buffer = function(addr, size)
    local t = {}
    for i = 0, size - 1 do t[#t + 1] = string.char(STORE[addr + i] or 0) end
    return table.concat(t)
  end,
}

syscall = {
  resolve = function(t)
    for name, number in pairs(t) do syscall[name] = function() return 4242 end end
  end,
  getuid = function() return 0 end,
}

PLATFORM = "ps5"
FW_VERSION = "14.22"
game_name = "HamidashiCreative"
native = {}
native_invoke = function() end
thr_self = function() return 1 end
kernel_offset = {}
"""

STUB_EPILOGUE = r"""
return table.concat(_out, "\n")
"""


def main() -> int:
    if not PROBE.is_file():
        print(f"[FAIL] probe not found: {PROBE}")
        return 2
    try:
        from lupa.lua51 import LuaRuntime
    except ImportError:
        print("[SKIP] lupa is not installed: python3 -m pip install --user lupa==2.6")
        return 0

    source = PROBE.read_text(encoding="utf-8")
    runtime = LuaRuntime(unpack_returned_tuples=True)

    # 1) compile as Lua 5.1
    compiler = runtime.eval("loadstring")
    compiled = compiler(source, str(PROBE))
    if isinstance(compiled, tuple) and compiled[0] is None:
        print(f"[FAIL] Lua 5.1 compile: {compiled[1]}")
        return 1
    print("[PASS] probe compiles as Lua 5.1")

    # 2) execute with the stub loader and collect what the probe printed
    runner = runtime.eval("function(src, prelude, epilogue) "
                          "assert(loadstring(prelude))(); "
                          "local fn = assert(loadstring(src)); "
                          "fn(); "
                          "return assert(loadstring(epilogue))() end")
    output = runner(source, STUB_PRELUDE, STUB_EPILOGUE)
    text = str(output)
    print(text)

    ok = True
    for stage_no in range(1, 6):
        marker = f"STAGE {stage_no}: OK"
        if marker not in text:
            print(f"[FAIL] missing '{marker}'")
            ok = False
    if "=== PROBE 14XX COMPLETE ===" not in text:
        print("[FAIL] missing completion marker")
        ok = False
    print("RESULT: PASS" if ok else "RESULT: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())