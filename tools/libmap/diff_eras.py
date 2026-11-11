#!/usr/bin/env python3
"""diff_eras.py — дельта интерфейсов между двумя наборами профилей модулей.

Сравнивает профили по именам модулей (libc.prx ↔ libc.prx) и печатает:
  * по каждому совпавшему модулю: сколько NID общих / только в A / только в B;
  * списки исчезших и появившихся NID (для маленьких модулей — целиком);
  * дельту списков импортируемых библиотек;
  * дельту trampoline-стабов (импортных переходников) по количеству.

Только по «плотным» NID (из настоящих таблиц) — изолированные совпадения
отбрасываются, иначе дельта утонет в шуме.
"""
from __future__ import annotations
import argparse, json, os
from collections import Counter

def load(p):
    return {os.path.basename(m["path"]): m for m in json.load(open(p, encoding="utf-8"))}

def main(a, b, max_list=40, quiet=False):
    A, B = load(a), load(b)
    common = sorted(set(A) & set(B))
    only_a = sorted(set(A) - set(B))
    only_b = sorted(set(B) - set(A))
    report = {
        "a_path": a, "b_path": b,
        "modules_only_a": only_a, "modules_only_b": only_b,
        "modules": [],
        "libs_union_only_a": sorted(set().union(*[set(A[m].get("libs", [])) for m in A]) -
                                    set().union(*[set(B[m].get("libs", [])) for m in B])),
        "libs_union_only_b": sorted(set().union(*[set(B[m].get("libs", [])) for m in B]) -
                                    set().union(*[set(A[m].get("libs", [])) for m in A])),
    }
    for m in common:
        na, nb = set(A[m].get("nids", [])), set(B[m].get("nids", []))
        ta = len(A[m].get("syscall_stubs", []))
        tb = len(B[m].get("syscall_stubs", []))
        la, lb = set(A[m].get("libs", [])), set(B[m].get("libs", []))
        row = {
            "module": m,
            "build_a": A[m].get("build_id"), "build_b": B[m].get("build_id"),
            "nids_a": len(na), "nids_b": len(nb),
            "common": len(na & nb),
            "only_a": len(na - nb), "only_b": len(nb - na),
            "removed": sorted(na - nb)[:max_list],
            "added": sorted(nb - na)[:max_list],
            "libs_only_a": sorted(la - lb), "libs_only_b": sorted(lb - la),
            "tramp_a": ta, "tramp_b": tb, "tramp_delta": tb - ta,
        }
        report["modules"].append(row)
        if not quiet:
            print(f"\n=== {m}  (build {row['build_a'] or '-'} -> {row['build_b'] or '-'})")
            print(f"    NID: {row['nids_a']} -> {row['nids_b']}  общих={row['common']}  "
                  f"исчезло={row['only_a']}  появилось={row['only_b']}")
            print(f"    tramp: {ta} -> {tb} ({tb-ta:+d})")
            if row["libs_only_a"]: print(f"    библиотеки только в A: {', '.join(row['libs_only_a'])}")
            if row["libs_only_b"]: print(f"    библиотеки только в B: {', '.join(row['libs_only_b'])}")
            if row["removed"]: print(f"    исчезли NID (до {max_list}): {', '.join(row['removed'])}")
            if row["added"]:   print(f"    появились NID (до {max_list}): {', '.join(row['added'])}")
    if not quiet:
        print(f"\nмодули только в A: {only_a or '—'}")
        print(f"модули только в B: {only_b or '—'}")
        print(f"библиотеки только в A: {report['libs_union_only_a'] or '—'}")
        print(f"библиотеки только в B: {report['libs_union_only_b'] or '—'}")
    return report

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("a"); ap.add_argument("b")
    ap.add_argument("--json-out", default="")
    ap.add_argument("--max-list", type=int, default=40)
    ap.add_argument("--quiet", action="store_true")
    r = a = None
    args = ap.parse_args()
    r = main(args.a, args.b, args.max_list, args.quiet)
    if args.json_out:
        json.dump(r, open(args.json_out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print(f"\nдельта: {args.json_out}")
