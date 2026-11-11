-- bundle-1422 / agent_lua.lua — пассивный агент в Lua-loader (TCP 9026) для моста.
--
-- Запускается на консоли скриптом-кадром по 9026 (см. send_lua.py / bridge_server.attach_lua).
-- Работает ПОВЕРХ того же TCP-соединения, по которому пришёл: берёт fd клиента из
-- signal.fd_addr (loader: signal.set_sink_fd(client_fd) -> memory.write_qword(fd_addr, fd))
-- и обслуживает бинарный протокол kernel-runner.py:
--
--   0x01 READ   [addr u64][len u64]                -> [0][data]
--   0x02 WRITE  [addr u64][len u64][data]          -> [0]
--   0x03 MALLOC [size u64][align u64]              -> [0][addr u64]   (memory.alloc)
--   0x04 SYSCALL[num u64][argc u8][args u64*argc]  -> [0][ret i64]    (make_syscall-style)
--   0x05 READY                                     -> [0][1]
--   0x06 REASON                                    -> [0]["lua-loader"]
--   0x07 PING                                      -> [0]["PONG"]
--
-- ВАЖНО (честно): этот файл НЕ проверен на консоли (в этой сессии консоли нет). Он
-- проверяется на ПК только на компиляцию Lua 5.1; протокол 1:1 совпадает с проверенным
-- kernel-runner.py --mock/--selftest (20 операций) и bridge_server --self-test.

local fd_addr = signal and signal.fd_addr or nil
local client_fd = nil

if fd_addr then
    local ok, fd = pcall(function() return memory.read_qword(fd_addr) end)
    if ok and fd then client_fd = fd:tonumber() end
end

if not client_fd or client_fd < 0 then
    print("ERR no client fd (signal.fd_addr missing) — enable signal handler first")
    return
end

print("HELLO lua-loader 1.0")

local function read_exact(n)
    local buf = memory.alloc(n)
    local got = 0
    while got < n do
        local r = syscall.read(client_fd, buf + got, n - got)
        r = r:tonumber()
        if r <= 0 then return nil end
        got = got + r
    end
    return memory.read_buffer(buf, n)
end

local function send(data)
    local sent = 0
    while sent < #data do
        local w = syscall.write(client_fd, data:sub(sent + 1), #data - sent):tonumber()
        if w <= 0 then return false end
        sent = sent + w
    end
    return true
end

local function u64(b, off)  -- little-endian u64 from string
    local t = {}
    for i = 0, 7 do t[#t + 1] = string.char(b:byte(off + i + 1) or 0) end
    return uint64.unpack(table.concat(t)):tonumber()
end

local function p64(v)
    local out = {}
    for i = 0, 7 do
        out[#out + 1] = string.char(v % 256)
        v = math.floor(v / 256)
    end
    return table.concat(out)
end

while true do
    local head = read_exact(1)
    if not head then break end
    local cmd = head:byte(1)

    if cmd == 0x01 then                       -- READ
        local tail = read_exact(16)
        if not tail then break end
        local addr, len = u64(tail, 0), u64(tail, 8)
        local data = memory.read_buffer(addr, len)
        send("\0" .. data)
    elseif cmd == 0x02 then                   -- WRITE
        local tail = read_exact(16)
        if not tail then break end
        local addr, len = u64(tail, 0), u64(tail, 8)
        local data = read_exact(len)
        if not data then break end
        memory.write_buffer(addr, data)
        send("\0")
    elseif cmd == 0x03 then                   -- MALLOC
        local tail = read_exact(16)
        if not tail then break end
        local size = u64(tail, 0)
        send("\0" .. p64(memory.alloc(size):tonumber()))
    elseif cmd == 0x04 then                   -- SYSCALL
        local num = read_exact(8)
        if not num then break end
        local argc_s = read_exact(1)
        if not argc_s then break end
        local argc = argc_s:byte(1)
        local args = {}
        if argc > 0 then
            local raw = read_exact(8 * argc)
            if not raw then break end
            for i = 0, argc - 1 do args[i + 1] = u64(raw, i * 8) end
        end
        local n = u64(num, 0)
        local t = {}
        for k, v in pairs(syscall.pipe) do t[k] = v end
        t.syscall_no = n
        setmetatable(t, getmetatable(syscall.pipe))
        local okc, ret = pcall(function() return t(args[1] or 0, args[2] or 0, args[3] or 0, args[4] or 0, args[5] or 0, args[6] or 0):tonumber() end)
        send("\0" .. p64(okc and ret or 0))
    elseif cmd == 0x05 then                   -- READY
        send("\0\1")
    elseif cmd == 0x06 then                   -- REASON
        send("\0lua-loader")
    elseif cmd == 0x07 then                   -- PING
        send("\0PONG")
    else
        send("\1unknown command")
        break
    end
end

syscall.close(client_fd)
