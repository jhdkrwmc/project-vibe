#!/usr/bin/env python3
# make_osd_variants_v3.py — NOP-only patches at post-boot OSD sites (SN9C292B)
# Leaves A and DPTR untouched; only skips MOVX @DPTR,A (byte F0 -> 00).
# Do NOT touch 0x4522. Do NOT write footer. 128KiB expected.

import sys, hashlib
from pathlib import Path

FW_SIZE = 0x20000
SITES = {
    0x04D0: {"dptr": 0x0B77, "label": "site_04D0"},
    0x0AC4: {"dptr": 0x0B76, "label": "site_0AC4"},
    0x0AFE: {"dptr": 0x0B77, "label": "site_0AFE"},
    0x4522: {"dptr": 0x0B75, "label": "site_4522_init"},  # do not touch
}

def sha256_hex(b): return hashlib.sha256(b).hexdigest()
def read_fw(p):
    b = bytearray(Path(p).read_bytes())
    if len(b)!=FW_SIZE: print(f"[!] size={len(b)} (expected {FW_SIZE}); continuing")
    return b
def write_file(p,b): Path(p).write_bytes(b)
def write_diff(a,b,p):
    lines=[]
    for i,(x,y) in enumerate(zip(a,b)):
        if x!=y: lines.append(f"{i:06X}: {x:02X} -> {y:02X}")
    Path(p).write_text("\n".join(lines)+"\n")
def sums_meta(path,b,extra=None):
    rows=[f"file: {Path(path).name}", f"size: {len(b)}", f"sha256: {sha256_hex(b)}"]
    if extra: rows+=extra
    Path(Path(path).with_suffix(".sum.txt")).write_text("\n".join(rows)+"\n")

def expect_seq(buf, off, dptr):
    exp = bytes([0x90,0x0B,dptr&0xFF,0x74,0x01,0xF0])
    got = bytes(buf[off:off+6])
    return got==exp, exp, got

def nop_movx(buf, off):
    # 90 0B xx 74 01 F0  -> at off+5 change F0 -> 00 (8051 NOP)
    if buf[off+5] != 0xF0: return False, f"{off+5:06X}: not MOVX (F0)"
    buf[off+5] = 0x00
    return True, f"{off+5:06X}: F0->00 (NOP MOVX)"

def make_variant(tag, ops, base, outdir):
    buf = bytearray(base); before = bytes(buf); log=[]
    for off in [x for x,_ in ops]:
        ok,exp,got = expect_seq(before, off, SITES[off]["dptr"])
        if not ok:
            log.append(f"[WARN] {off:06X}: expected {' '.join(f'{x:02X}' for x in exp)}, got {' '.join(f'{x:02X}' for x in got)}")
    for off, fn in ops:
        ok,msg = fn(buf, off); log.append(("[OK] " if ok else "[ERR] ")+msg)
    out_bin = Path(outdir)/f"fw_osd_{tag}.bin"
    write_file(out_bin, buf)
    write_diff(before, buf, out_bin.with_suffix(".diff.txt"))
    sums_meta(out_bin, buf, extra=log)

def main():
    if len(sys.argv)!=3:
        print(f"Usage: {Path(sys.argv[0]).name} <input.bin> <out_dir>"); sys.exit(1)
    inp=sys.argv[1]; outd=Path(sys.argv[2]); outd.mkdir(parents=True, exist_ok=True)
    base=read_fw(inp)
    make_variant("v11_nop_04d0", [(0x04D0, nop_movx)], base, outd)
    make_variant("v12_nop_0ac4", [(0x0AC4, nop_movx)], base, outd)
    make_variant("v13_nop_0afe", [(0x0AFE, nop_movx)], base, outd)
    make_variant("v14_nop_all3", [(0x04D0, nop_movx),(0x0AC4, nop_movx),(0x0AFE, nop_movx)], base, outd)

if __name__=="__main__": main()
