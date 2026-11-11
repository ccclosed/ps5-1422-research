# bundle-1422 / yarpe_hello_9025.py
# Custom payload for YARPE (Yet another Ren'Py PlayStation exploit).
#
# Target runtime: Ren'Py 7.4 / Python 2.7 (the game builds yarpe supports).
# Keep this file Python-2.7 compatible: no f-strings, no nonlocal, % formatting only.
#
# Protocol of YARPE stage 2 (src/main.py of Helloyunho/yarpe): the console listens on
# TCP :9025, reads the whole client stream as UTF-8 Python source, exec()s it in a scope
# where yarpe modules are importable (`sc`, `utils.*`, `offsets`, `structure`), then
# writes the payload log back to the client.
#
# From PC (raw text, no length prefix):
#     python3 -c "import socket,sys; s=socket.create_connection((sys.argv[1],9025),timeout=10); \
#                  s.sendall(open(sys.argv[2],'rb').read()); print(s.recv(65536).decode('utf-8','replace'))" \
#                  <PS5_IP> yarpe_hello_9025.py
#
# Expected: "STAGE 0..3: OK", "stages_ok=4" and "=== YARPE PROBE 14XX COMPLETE ===".

from __future__ import print_function
import traceback

STAGES = []
_imports_ok = False


def emit(line):
    STAGES.append(line)
    try:
        log(line)                      # noqa: F821 - injected by yarpe (utils.rp.log)
    except Exception:
        print(line)


def stage(number, ok, detail):
    emit("STAGE %d: %s %s" % (number, "OK" if ok else "FAIL", detail or ""))


def _err():
    return traceback.format_exc().replace("\n", " | ")


emit("=== YARPE PROBE 14XX ENTRY (bundle-1422) ===")

# STAGE 0: runtime + yarpe modules -------------------------------------------
try:
    from sc import sc
    from utils.rp import log                       # noqa: F811 - real logging target
    from utils.unsafe import readuint, writeuint
    from utils.etc import alloc, addrof
    _imports_ok = True
    stage(0, True, "yarpe modules imported")
except Exception:
    stage(0, False, _err())

if _imports_ok:
    # STAGE 1: console/process context ---------------------------------------
    try:
        platform = getattr(sc, "platform", None)
        version = getattr(sc, "version", None)
        jailbroken = getattr(sc, "is_jailbroken", None)
        stage(1, platform is not None,
              "platform=%s version=%s is_jailbroken=%s" % (platform, version, jailbroken))
    except Exception:
        stage(1, False, _err())

    # STAGE 2: userland memory read/write self-test --------------------------
    try:
        buf = alloc(0x100)
        addr = addrof(buf)
        writeuint(addr + 0x08, 0x11223344, 4)
        writeuint(addr + 0x0C, 0x55667788, 4)
        a = readuint(addr + 0x08, 4)
        b = readuint(addr + 0x0C, 4)
        stage(2, (a == 0x11223344) and (b == 0x55667788),
              "addr=0x%x a=0x%x b=0x%x" % (addr, a, b))
    except Exception:
        stage(2, False, _err())

    # STAGE 3: what the process can call (report only) -----------------------
    try:
        has_functions = hasattr(sc, "functions")
        has_syscalls = hasattr(sc, "syscalls")
        stage(3, has_functions and has_syscalls,
              "sc.functions=%s sc.syscalls=%s exec=0x%x libc=0x%x"
              % (has_functions, has_syscalls,
                 getattr(sc, "exec_addr", 0), getattr(sc, "libc_addr", 0)))
    except Exception:
        stage(3, False, _err())

emit("stages_ok=%d stages_total=%d" % (len([s for s in STAGES if ": OK" in s]), 4))
emit("=== YARPE PROBE 14XX COMPLETE ===")