#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""x86len.py -- dependency free x86-64 instruction length decoder.

Only the *length* of an instruction is computed (plus a coarse opcode class),
which is all a ROP scanner needs to validate that a candidate byte string is a
usable instruction sequence.  The module exists so scan.py keeps working when
capstone is missing; when capstone is present scan.py prefers it for operand
text and uses this decoder only as a cross-check.

Scope: 64-bit mode (the PS5 userland is x86-64), legacy prefixes, REX,
one/two/three byte opcodes, VEX2/VEX3 and EVEX prefixes, ModRM/SIB/disp and
immediate fields.

decode_len(buf, pos) -> int (0 == invalid/unsupported)
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# tables
# ---------------------------------------------------------------------------

LEGACY_PREFIX = {
    0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0xF0, 0xF2, 0xF3, 0x66, 0x67,
}

# operand kind markers
NONE = 0        # no modrm, no immediate
MODRM = 1       # modrm only
M_I8 = 2        # modrm + imm8
M_IZ = 3        # modrm + imm16/32
I8 = 4          # imm8
IZ = 5          # imm16/32
I16 = 6         # imm16
ENTER = 7       # imm16 + imm8
MOFFS = 8       # address sized displacement
REL8 = 9        # rel8
RELZ = 10       # rel16/32
GROUP3_8 = 11   # F6: imm8 if reg in {0,1}
GROUP3_Z = 12   # F7: immz if reg in {0,1}
MOV_IMM_R = 13  # B8..BF: imm64 when REX.W else immz
X87 = 14        # x87, modrm
INVALID = 0xFF  # opcode illegal in 64-bit mode

ONE_BYTE = [0] * 256         # 0 == invalid until filled
TWO_BYTE = [0] * 256
THREE_38 = [MODRM] * 256
THREE_3A = [M_I8] * 256


def _fill(table, entries):
    for kinds, ops in entries:
        for op in ops:
            table[op] = kinds


# 00..3F: ALU group, +0..+5 patterns
for base in (0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38):
    ONE_BYTE[base + 0] = MODRM
    ONE_BYTE[base + 1] = MODRM
    ONE_BYTE[base + 2] = MODRM
    ONE_BYTE[base + 3] = MODRM
    ONE_BYTE[base + 4] = I8
    ONE_BYTE[base + 5] = IZ

_fill(ONE_BYTE, [
    (NONE, range(0x50, 0x60)),          # push/pop r64
    (MODRM, [0x63]),                    # movsxd
    (IZ, [0x68]),
    (M_IZ, [0x69]),
    (I8, [0x6A]),
    (M_I8, [0x6B]),
    (NONE, range(0x6C, 0x70)),          # ins/outs
    (REL8, range(0x70, 0x80)),          # jcc rel8
    (M_I8, [0x80]),
    (M_IZ, [0x81]),
    (M_I8, [0x83]),
    (MODRM, [0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F]),
    (NONE, range(0x90, 0xA0)),          # nop/xchg/cbw/cwd/sahf/lahf
    (MOFFS, [0xA0, 0xA1, 0xA2, 0xA3]),
    (NONE, [0xA4, 0xA5, 0xA6, 0xA7]),
    (I8, [0xA8]),
    (IZ, [0xA9]),
    (NONE, [0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF]),
    (MOV_IMM_R, range(0xB0, 0xC0)),
    (M_I8, [0xC0, 0xC1]),
    (I16, [0xC2]),
    (NONE, [0xC3]),
    (M_I8, [0xC6]),
    (M_IZ, [0xC7]),
    (ENTER, [0xC8]),
    (NONE, [0xC9]),
    (I16, [0xCA]),
    (NONE, [0xCB, 0xCC]),
    (I8, [0xCD]),
    (NONE, [0xCE, 0xCF]),
    (MODRM, range(0xD0, 0xD4)),
    (NONE, [0xD7]),
    (MODRM, range(0xD8, 0xE0)),         # x87
    (REL8, range(0xE0, 0xE4)),
    (I8, [0xE4, 0xE5, 0xE6, 0xE7]),
    (RELZ, [0xE8, 0xE9]),
    (REL8, [0xEB]),
    (NONE, range(0xEC, 0xF0)),
    (NONE, [0xF1]),
    (NONE, [0xF4, 0xF5]),
    (GROUP3_8, [0xF6]),
    (GROUP3_Z, [0xF7]),
    (NONE, range(0xF8, 0xFE)),
    (MODRM, [0xFE, 0xFF]),
])

THREE_38[0x00] = MODRM  # keep the table explicit for readability

# opcodes that are illegal in 64-bit mode
for _bad in (0x06, 0x07, 0x0E, 0x16, 0x17, 0x1E, 0x1F, 0x27, 0x2F, 0x37, 0x3F,
             0x60, 0x61, 0x82, 0x9A, 0xCE, 0xD4, 0xD5, 0xD6, 0xEA):
    ONE_BYTE[_bad] = INVALID
for _bad in (0x04, 0x0A, 0x0C, 0x24, 0x25, 0x26, 0x27, 0x36, 0x39, 0x3B, 0x3C,
             0x3D, 0x3E, 0x3F, 0x7A, 0xA6, 0xA7):
    TWO_BYTE[_bad] = INVALID

# 0F map: anything not listed is treated as MODRM (SSE) - the common case.
for _i in range(256):
    TWO_BYTE[_i] = MODRM

_fill(TWO_BYTE, [
    (MODRM, range(0x00, 0x04)),
    (NONE, [0x05, 0x06, 0x07, 0x08, 0x09, 0x0B, 0x0E]),
    (MODRM, [0x0D]),
    (M_I8, [0x0F]),                     # 3DNow!
    (MODRM, range(0x10, 0x18)),
    (MODRM, range(0x18, 0x20)),
    (MODRM, range(0x20, 0x24)),
    (MODRM, range(0x28, 0x30)),
    (NONE, range(0x30, 0x38)),          # wrmsr/rdtsc/rdmsr/rdpmc/sysenter/sysexit/getsec
    (M_I8, [0x70]),
    (M_I8, [0x71, 0x72, 0x73]),
    (MODRM, [0x74, 0x75, 0x76]),
    (NONE, [0x77]),                     # emms
    (MODRM, [0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F]),
    (RELZ, range(0x80, 0x90)),          # jcc rel32
    (MODRM, range(0x90, 0xA0)),         # setcc
    (NONE, [0xA0, 0xA1, 0xA2]),
    (MODRM, [0xA3]),
    (M_I8, [0xA4, 0xA5]),
    (NONE, [0xA8, 0xA9, 0xAA]),
    (MODRM, [0xAB]),
    (M_I8, [0xAC, 0xAD]),
    (MODRM, [0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
             0xB8, 0xB9, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF]),
    (M_I8, [0xBA]),
    (MODRM, [0xC0, 0xC1]),
    (M_I8, [0xC2, 0xC4, 0xC5, 0xC6]),
    (MODRM, [0xC3, 0xC7]),
    (NONE, range(0xC8, 0xD0)),          # bswap
    (MODRM, range(0xD0, 0x100)),
])

VEX_IMM8 = {0x70, 0x71, 0x72, 0x73, 0xC2, 0xC4, 0xC5, 0xC6}


def _modrm_len(buf, pos, limit, addr16=False):
    """Length of ModRM(+SIB+disp) starting at pos; 0 if it runs past limit."""
    if pos >= limit:
        return 0
    m = buf[pos]
    mod, rm = m >> 6, m & 7
    n = 1
    if mod == 3:
        return n
    if rm == 4:                       # SIB follows
        if pos + 1 >= limit:
            return 0
        n += 1
        base = buf[pos + 1] & 7
        if mod == 0:
            if base == 5:
                n += 4
        elif mod == 1:
            n += 1
        else:
            n += 4
        return n
    if mod == 0 and rm == 5:          # RIP relative
        return n + 4
    if mod == 1:
        return n + 1
    if mod == 2:
        return n + 4
    return n


# opcode -> set of illegal ModRM.reg values (group encodings)
BAD_REG = {
    0xFF: {7},            # /7 undefined
    0xFE: {2, 3, 4, 5, 6, 7},
    0xF6: {7},
    0xF7: {7},
    0x8F: {1, 2, 3, 4, 5, 6, 7},   # only /0 = pop r/m
    0xC6: {1, 2, 3, 4, 5, 6, 7},   # only /0 = mov r/m8, imm8
    0xC7: {1, 2, 3, 4, 5, 6, 7},   # only /0 = mov r/m, imm
}


def decode_len(buf, pos, limit=None):
    """Return the length in bytes of the instruction at buf[pos], or 0."""
    if limit is None:
        limit = len(buf)
    if pos >= limit:
        return 0
    start = pos
    opsize16 = False
    addr32 = False
    rex = 0
    seen_rex = False
    while pos < limit:
        b = buf[pos]
        if 0x40 <= b <= 0x4F:
            # several REX bytes are legal; the last one before the opcode wins
            rex = b
            seen_rex = True
            pos += 1
            continue
        if b in LEGACY_PREFIX:
            if b == 0x66:
                opsize16 = True
            elif b == 0x67:
                addr32 = True
            pos += 1
            continue
        break
    if pos >= limit:
        return 0
    op = buf[pos]
    pos += 1
    rexw = bool(rex & 8)

    def immz():
        return 2 if opsize16 else 4

    kind = None
    table = ONE_BYTE
    if op in (0xC4, 0xC5, 0x62):                      # VEX / EVEX
        if op == 0xC5:
            if pos >= limit:
                return 0
            pos += 1                                  # VEX2 payload
            vmap = 1
        elif op == 0xC4:
            if pos + 1 >= limit:
                return 0
            vmap = buf[pos] & 0x1F
            pos += 2                                  # VEX3 payload
        else:                                          # EVEX
            if pos + 2 >= limit:
                return 0
            vmap = buf[pos] & 0x3
            pos += 3
        if pos >= limit:
            return 0
        vop = buf[pos]
        pos += 1
        ml = _modrm_len(buf, pos, limit)
        if not ml:
            return 0
        pos += ml
        if vmap == 3:
            pos += 1
        elif vmap == 1 and vop in VEX_IMM8:
            pos += 1
        if pos > limit:
            return 0
        return pos - start

    if op == 0x0F:
        if pos >= limit:
            return 0
        op2 = buf[pos]
        pos += 1
        if op2 == 0x38:
            if pos >= limit:
                return 0
            op3 = buf[pos]
            pos += 1
            kind = THREE_38[op3]
        elif op2 == 0x3A:
            if pos >= limit:
                return 0
            op3 = buf[pos]
            pos += 1
            kind = THREE_3A[op3]
        else:
            kind = TWO_BYTE[op2]
    else:
        kind = ONE_BYTE[op]

    if kind == INVALID:
        return 0
    if kind == NONE:
        return pos - start
    if kind in (MOV_IMM_R,):
        # B0..B7 mov r8, imm8 ; B8..BF mov r64, imm
        if 0xB0 <= op <= 0xB7:
            pos += 1
        else:
            pos += 8 if rexw else immz()
        return pos - start
    if kind == MOFFS:
        pos += 4 if addr32 else 8
        return pos - start if pos <= limit else 0

    # immediate-only forms have no ModRM at all
    if kind == I8:
        pos += 1
        return pos - start if pos <= limit else 0
    if kind == IZ:
        pos += immz()
        return pos - start if pos <= limit else 0
    if kind == I16:
        pos += 2
        return pos - start if pos <= limit else 0
    if kind == ENTER:
        pos += 3
        return pos - start if pos <= limit else 0
    if kind == REL8:
        pos += 1
        return pos - start if pos <= limit else 0
    if kind == RELZ:
        pos += 2 if opsize16 else 4
        return pos - start if pos <= limit else 0

    # everything below begins with a ModRM byte
    ml = _modrm_len(buf, pos, limit)
    if not ml:
        return 0
    modrm = buf[pos]
    reg = (modrm >> 3) & 7
    if op in BAD_REG and reg in BAD_REG[op]:
        return 0
    pos += ml

    if kind == MODRM:
        pass
    elif kind == M_I8:
        pos += 1
    elif kind == M_IZ:
        pos += immz()
    elif kind == GROUP3_8:
        if reg in (0, 1):
            pos += 1
    elif kind == GROUP3_Z:
        if reg in (0, 1):
            pos += immz()
    else:
        return 0
    return pos - start if pos <= limit else 0


def is_terminator(buf, pos, length):
    """True when the instruction occupies buf[pos:pos+length] ends in ret/jmp/call."""
    end = pos + length
    last = buf[end - 1]
    if last in (0xC3, 0xCB):
        return True
    if last == 0xC2 or last == 0xCA:          # ret imm16
        return length >= 3
    # ff /2|/3|/4|/5 (call/jmp indirect) or 0f 05 (syscall)
    if length >= 2 and buf[end - 2] == 0xFF and (buf[end - 1] >> 3) & 7 in (2, 3, 4, 5):
        return True
    if length >= 2 and buf[end - 2] == 0x0F and last == 0x05:
        return True
    return False


if __name__ == "__main__":
    import sys
    data = open(sys.argv[1], "rb").read()
    base = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0
    pos, n = base, 0
    while pos < len(data) and n < 40:
        ln = decode_len(data, pos)
        print("0x%08x  len=%d  %s" % (pos, ln, data[pos:pos + ln].hex()))
        if not ln:
            pos += 1
        else:
            pos += ln
        n += 1