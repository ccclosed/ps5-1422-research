#!/usr/bin/env python3
"""
dump.py - dump a located sysent table to JSON and/or CSV.

The table can be selected from scanner.py's results (default: highest scored
table) or given explicitly with --offset/--layout.  When the image is an ELF
with a symbol table, sy_call is optionally resolved to the nearest symbol.

Examples:
    ./dump.py kernel.elf --json sysent.json --csv sysent.csv
    ./dump.py kernel.elf --table 1 --csv table1.csv
    ./dump.py kernel.raw --offset 0x40000 --layout ps5 --base 0xffffffff80000000
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

import scanner


def _fmt_ptr(value: Optional[int]) -> Optional[str]:
    return None if value is None else f"0x{value:x}"


def _table_from_candidate(cand: dict, image: scanner.Image) -> dict:
    layout = scanner.LAYOUTS[cand["layout"]]
    table = dict(cand)
    table["layout_description"] = layout.description
    table["vaddr_hex"] = _fmt_ptr(table.get("vaddr"))
    table["offset_hex"] = f"0x{table['offset']:x}"
    return table


def _table_explicit(
    image: scanner.Image,
    offset: int,
    layout: scanner.Layout,
    count: Optional[int],
    cfg: scanner.ScanConfig,
) -> tuple[dict, list[tuple]]:
    buf = image.data
    stride = layout.stride
    if offset < 0 or offset + stride > len(buf):
        raise ValueError(f"offset 0x{offset:x} is outside the image")
    if count is not None and count < 1:
        raise ValueError("--count must be >= 1")

    rows: list[tuple] = []
    pos = offset
    while pos + stride <= len(buf):
        values = layout.unpack(buf, pos)
        if not scanner._entry_is_valid(
            layout,
            values,
            cfg,
            auevent_is_ptr=(
                "auevent" in layout.index
                and layout.field_by_name["auevent"].kind == "ptr"
            ),
            has_systrace="systrace" in layout.index,
        ):
            break
        rows.append(values)
        pos += stride
        if count is not None and len(rows) >= count:
            break
        if len(rows) >= 65536:
            raise ValueError("table did not end within 65536 entries")

    if not rows:
        raise ValueError(
            f"no valid {layout.name} record at file offset 0x{offset:x}"
        )
    if count is not None and len(rows) != count:
        raise ValueError(
            f"requested {count} entries, but only {len(rows)} validated "
            f"(record {len(rows)} at file offset "
            f"0x{offset + len(rows) * stride:x} is invalid)"
        )

    table = {
        "index": 0,
        "offset": offset,
        "offset_hex": f"0x{offset:x}",
        "vaddr": image.vaddr_for_offset(offset),
        "vaddr_hex": _fmt_ptr(image.vaddr_for_offset(offset)),
        "layout": layout.name,
        "layout_description": layout.description,
        "stride": stride,
        "entries": len(rows),
        "first_syscall": 0,
        "last_syscall": len(rows) - 1,
        "score": None,
        "padding_zero_ratio": scanner._padding_zero_ratio(
            buf, offset, layout, len(rows)
        ),
        "null_calls": sum(
            1 for v in rows if v[layout.index["call"]] == 0
        ),
        "fields": {
            f.name: {"offset": f.offset, "size": f.size, "kind": f.kind}
            for f in layout.fields
        },
    }
    return table, rows


def _entry_records(
    rows: Sequence[tuple],
    table: dict,
    layout: scanner.Layout,
    symbols: scanner.SymbolTable,
    resolve_symbols: bool,
) -> list[dict]:
    entries: list[dict] = []
    offset = table["offset"]
    stride = layout.stride
    first = table["first_syscall"]
    index = layout.index
    has_flags = "flags" in index
    has_auevent = "auevent" in index
    auevent_is_ptr = (
        has_auevent and layout.field_by_name["auevent"].kind == "ptr"
    )

    for number, values in enumerate(rows):
        call = values[index["call"]]
        rec = {
            "nr": first + number,
            "narg": values[index["narg"]],
            "sy_call": f"0x{call:x}",
            "sy_call_int": call,
            "sy_auevent": None,
            "sy_auevent_kind": None,
            "sy_sysflags": values[index["flags"]] if has_flags else None,
            "file_offset": offset + number * stride,
            "symbol": None,
        }
        if has_auevent:
            auevent = values[index["auevent"]]
            rec["sy_auevent"] = (
                f"0x{auevent:x}" if auevent_is_ptr else auevent
            )
            rec["sy_auevent_kind"] = "ptr" if auevent_is_ptr else "int"
        extra = {}
        for name in ("systrace", "entry", "return", "thrcnt"):
            if name in index:
                value = values[index[name]]
                extra[name] = (
                    f"0x{value:x}"
                    if layout.field_by_name[name].kind == "ptr"
                    else value
                )
        rec["extra"] = extra
        if resolve_symbols and len(symbols):
            rec["symbol"] = symbols.lookup(call)
        entries.append(rec)
    return entries


def _write_csv(path: str, entries: Sequence[dict]) -> None:
    if path == "-":
        _write_csv_stream(sys.stdout, entries)
        return
    with Path(path).open("w", encoding="utf-8", newline="") as fh:
        _write_csv_stream(fh, entries)


def _write_csv_stream(fh, entries: Sequence[dict]) -> None:
    writer = csv.writer(fh)
    writer.writerow(
        [
            "nr",
            "narg",
            "sy_call_hex",
            "sy_call_dec",
            "sy_auevent",
            "sy_auevent_kind",
            "sy_sysflags",
            "symbol",
            "file_offset",
        ]
    )
    for e in entries:
        writer.writerow(
            [
                e["nr"],
                e["narg"],
                e["sy_call"],
                e["sy_call_int"],
                e["sy_auevent"] if e["sy_auevent"] is not None else "",
                e["sy_auevent_kind"] or "",
                e["sy_sysflags"] if e["sy_sysflags"] is not None else "",
                e["symbol"] or "",
                f"0x{e['file_offset']:x}",
            ]
        )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Dump a sysent table found by scanner.py to JSON/CSV.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("image", help="raw kernel image or ELF64 kernel")
    p.add_argument("--table", type=int, default=0,
                   help="index of the scanner result to dump")
    p.add_argument("--offset", type=lambda s: int(s, 0), default=None,
                   help="explicit table file offset (requires --layout)")
    p.add_argument("--layout", default="auto",
                   help="layout name used with --offset, or a comma separated "
                        "list of layouts for scanning")
    p.add_argument("--count", type=int, default=None,
                   help="number of entries for --offset (default: until an "
                        "invalid record)")
    p.add_argument("--base", type=lambda s: int(s, 0), default=None,
                   help="load address of a raw image")
    p.add_argument("--min-entries", type=int, default=24,
                   help="minimum run length when scanning for the table")
    p.add_argument("--max-narg", type=int, default=24)
    p.add_argument("--max-flags", type=lambda s: int(s, 0), default=0xFFFF)
    p.add_argument("--ptr-min", type=lambda s: int(s, 0),
                   default=scanner.PTR_LO_DEFAULT)
    p.add_argument("--ptr-max", type=lambda s: int(s, 0),
                   default=scanner.PTR_HI_DEFAULT)
    p.add_argument("--auevent-any", action="store_true")
    p.add_argument("--allow-null-call", action="store_true")
    p.add_argument("--json", dest="json_path", default=None,
                   help="write JSON to this path")
    p.add_argument("--csv", dest="csv_path", default=None,
                   help="write CSV to this path")
    p.add_argument("--symbols", dest="symbols", action="store_true",
                   default=True, help="resolve sy_call names (ELF only)")
    p.add_argument("--no-symbols", dest="symbols", action="store_false",
                   help="disable symbol resolution")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        cfg = scanner.ScanConfig(
            min_entries=args.min_entries,
            max_narg=args.max_narg,
            max_flags=args.max_flags,
            ptr_min=args.ptr_min,
            ptr_max=args.ptr_max,
            allow_null_call=args.allow_null_call,
            auevent_any=args.auevent_any,
        )
        cfg.validate()
        image = scanner.Image(args.image, base=args.base)
    except (OSError, ValueError) as exc:
        print(f"dump: error: {exc}", file=sys.stderr)
        return 2

    try:
        if args.offset is not None:
            if args.layout == "auto" or "," in args.layout:
                raise ValueError(
                    "--offset requires exactly one --layout "
                    f"({', '.join(scanner.LAYOUTS)})"
                )
            if args.layout not in scanner.LAYOUTS:
                raise ValueError(f"unknown layout {args.layout!r}")
            table, rows = _table_explicit(
                image, args.offset, scanner.LAYOUTS[args.layout],
                args.count, cfg,
            )
        else:
            layouts = scanner.resolve_layouts(args.layout)
            tables = scanner.scan_image(image, cfg, layouts)
            if not tables:
                print(
                    "dump: error: scanner found no sysent table; use "
                    "--offset/--layout to specify one explicitly",
                    file=sys.stderr,
                )
                return 2
            if args.table < 0 or args.table >= len(tables):
                raise ValueError(
                    f"--table {args.table} out of range: scanner found "
                    f"{len(tables)} table(s); use 0..{len(tables) - 1}"
                )
            table = _table_from_candidate(tables[args.table], image)
            layout = scanner.LAYOUTS[table["layout"]]
            stride = layout.stride
            if table["offset"] + table["entries"] * stride > len(image.data):
                raise ValueError("table range exceeds image size")
            rows = [
                layout.unpack(
                    image.data, table["offset"] + i * stride
                )
                for i in range(table["entries"])
            ]
    except ValueError as exc:
        print(f"dump: error: {exc}", file=sys.stderr)
        return 2

    layout = scanner.LAYOUTS[table["layout"]]
    resolve_symbols = bool(args.symbols and image.elf is not None)
    symbols = image.symbols if resolve_symbols else scanner.SymbolTable(())
    entries = _entry_records(rows, table, layout, symbols, resolve_symbols)

    if table.get("vaddr") is not None and len(symbols):
        table["symbol"] = symbols.lookup(table["vaddr"])
    else:
        table["symbol"] = None

    resolved = sum(1 for e in entries if e["symbol"])
    answer = {
        "tool": "sysent-dump",
        "version": 1,
        "image": image.metadata(),
        "table": table,
        "entries": entries,
        "summary": {
            "entries": len(entries),
            "first_nr": table["first_syscall"],
            "last_nr": table["last_syscall"],
            "symbols_resolved": resolved,
            "symbols_available": len(symbols),
        },
    }

    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(answer, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    if args.csv_path:
        _write_csv(args.csv_path, entries)

    if not args.json_path and not args.csv_path:
        _write_csv("-", entries)

    print(f"table   : #{table['index']} layout={table['layout']} "
          f"stride={table['stride']} entries={table['entries']}")
    print(f"offset  : 0x{table['offset']:x}  vaddr: {table['vaddr_hex']}")
    if table.get("symbol"):
        print(f"symbol  : {table['symbol']}")
    print(f"syscalls: {table['first_syscall']}..{table['last_syscall']}")
    if resolve_symbols:
        print(f"symbols : {resolved}/{len(entries)} handlers resolved")
    if args.json_path:
        print(f"wrote JSON: {args.json_path}")
    if args.csv_path:
        print(f"wrote CSV : {args.csv_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())