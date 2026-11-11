-- bundle-1422 / probe_14xx_entry.lua
-- CRASH_CLASS: LOW  (read-only checks + one small alloc/self-test; no ROP, no kernel paths)
--
-- Purpose: prove that the Lua 5.1 userland entry works on a 14.2x console and report
-- what the loader exposes there. Every stage prints "STAGE n: OK/FAIL <detail>" so a
-- stage that dies is visible in the capture; the last line is a completion marker.
--
-- Run from PC:  python3 send_lua.py --host <PS5_IP> probe_14xx_entry.lua
-- Expected on console: black screen with the loader banner; here: STAGE lines.

local function num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end

local function hex(v)
    if type(v) == "table" and v.h then return string.format("0x%X%08X", v.h, v.l) end
    return string.format("0x%X", num(v))
end

local function global_str(name)
    local ok, value = pcall(function() return _G[name] end)
    if not ok or value == nil then return "nil" end
    if type(value) == "table" and value.h then return hex(value) end
    return tostring(value)
end

local function stage(n, ok, detail)
    print(string.format("STAGE %d: %s %s", n, ok and "OK" or "FAIL", detail or ""))
    return ok
end

print("=== PROBE 14XX ENTRY (bundle-1422) ===")
print("lua=" .. tostring(_VERSION))
print("platform=" .. global_str("PLATFORM"))
print("fw=" .. global_str("FW_VERSION"))
print("game=" .. global_str("game_name"))
print("pid_self=" .. tostring(global_str("PID")))

-- STAGE 1: loader context / primitives are present ---------------------------
local ok1 = pcall(function()
    assert(type(memory) == "table", "memory table missing")
    assert(type(memory.alloc) == "function", "memory.alloc missing")
    assert(type(memory.read_qword) == "function", "memory.read_qword missing")
    assert(type(memory.write_qword) == "function", "memory.write_qword missing")
end)
stage(1, ok1, "loader memory API present")

-- STAGE 2: userland memory read/write self-test -----------------------------
local ok2, detail2 = pcall(function()
    local buf = memory.alloc(0x100)
    assert(buf, "alloc returned nil")

    memory.write_dword(buf + 0x00, 0x11223344)
    memory.write_dword(buf + 0x04, 0x55667788)
    memory.write_byte(buf + 0x08, 0xAB)

    local a = num(memory.read_dword(buf + 0x00))
    local b = num(memory.read_dword(buf + 0x04))
    local c = num(memory.read_byte(buf + 0x08))
    assert(a == 0x11223344, string.format("dword0 mismatch %s", hex(a)))
    assert(b == 0x55667788, string.format("dword1 mismatch %s", hex(b)))
    assert(c == 0xAB, string.format("byte mismatch %s", hex(c)))

    local chunk = memory.read_buffer(buf, 0x10)
    assert(chunk and #chunk == 0x10, "read_buffer size mismatch")
    return string.format("buf=%s dword0=%s byte=%s", hex(buf), hex(a), hex(c))
end)
stage(2, ok2, ok2 and detail2 or tostring(detail2))

-- STAGE 3: module bases the loader resolved ---------------------------------
local ok3, detail3 = pcall(function()
    return string.format("exec=%s libc=%s libkernel=%s",
        global_str("eboot_base"), global_str("libc_base"), global_str("libkernel_base"))
end)
stage(3, ok3, ok3 and detail3 or tostring(detail3))

-- STAGE 4: syscall channel ---------------------------------------------------
local ok4, detail4 = pcall(function()
    assert(type(syscall) == "table", "syscall table missing")
    syscall.resolve({ probe_getpid = 20 })  -- FreeBSD getpid
    local pid = num(syscall.probe_getpid())
    local uid = -1
    if type(syscall.getuid) == "function" then uid = num(syscall.getuid()) end
    assert(pid > 0, "getpid returned " .. tostring(pid))
    return string.format("getpid=%d getuid=%d", pid, uid)
end)
stage(4, ok4, ok4 and detail4 or tostring(detail4))

-- STAGE 5: what else exists on this firmware (report only, never fatal) -----
local ok5 = pcall(function()
    print(string.format("native=%s native_invoke=%s thr=%s kernel_offset=%s",
        tostring(type(native)), tostring(type(native_invoke)),
        tostring(type(thr_self)), tostring(type(kernel_offset))))
end)
stage(5, ok5, "capability report printed")

print("=== PROBE 14XX COMPLETE ===")