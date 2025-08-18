#!/usr/bin/env python3
# make_osd_variants_v2.py — post-boot-only patches for SN9C292B
# Inputs: baseline 128 KiB bin; Outputs: five variants + diffs + sums.
# Uses OSD sites confirmed in repo: 0x04D0 (0x0B77), 0x0AC4 (0x0B76), 0x0AFE (0x0B77), 0x4522 (0x0B75).
# We DO NOT touch 0x4522, and we DO NOT edit footer 0x1FFE..0x1FFF.
# References: osd_sites.md / Untitled-1.md. (init-path true only for 0x4522)
# https://github.com/jhdkrwmc/project-vibe  (files: osd_sites.md/json)
import sys, os, hashlib
from pathlib import Path

FW_SIZE = 0x20000

# Canonical OSD sequences (from your dumps): ea/file offsets are identical here.
SITES = {
    0x04D0: {"dptr": 0x0B77, "label": "site_04D0"},
    0x0AC4: {"dptr": 0x0B76, "label": "site_0AC4"},
    0x0AFE: {"dptr": 0x0B77, "label": "site_0AFE"},
    0x4522: {"dptr": 0x0B75, "label": "site_4522_init"},  # DO NOT TOUCH
}

def sha256_hex(b): return hashlib.sha256(b).hexdigest()

def read_fw(p):
    b = bytearray(Path(p).read_bytes())
    if len(b) != FW_SIZE:
        print(f"[!] size={len(b)} (expected {FW_SIZE}); proceeding anyway")
    return b

def expect_seq(buf, off, dptr):
    exp = bytes([0x90, 0x0B, dptr & 0xFF, 0x74, 0x01, 0xF0])
    got = bytes(buf[off:off+6])
    return got == exp, exp, got

def write_file(p, b): Path(p).write_bytes(b)

def write_diff(before, after, p):
    lines=[]
    for i,(a,c) in enumerate(zip(before,after)):
        if a!=c: lines.append(f"{i:06X}: {a:02X} -> {c:02X}")
    if len(after)>len(before):
        for i in range(len(before), len(after)):
            lines.append(f"{i:06X}: -- -> {after[i]:02X}")
    Path(p).write_text("\n".join(lines)+"\n")

def sums_meta(path, b, extra=None):
    rows = [
        f"file: {Path(path).name}",
        f"size: {len(b)}",
        f"sha256: {sha256_hex(b)}",
    ]
    if extra: rows += extra
    Path(Path(path).with_suffix(".sum.txt")).write_text("\n".join(rows)+"\n")

def patch_imm01_to00(buf, off):
    # 90 0B xx 74 01 F0  ->  set byte at off+4 from 01 to 00
    if buf[off+4] != 0x01: return False, f"imm at {off+4:06X} not 01"
    buf[off+4] = 0x00
    return True, f"{off+4:06X}: 01->00"

def patch_redirect_to_b75_clear(buf, off):
    # 90 0B (76|77) 74 01 F0  ->  90 0B 75 74 00 F0
    if buf[off]   != 0x90: return False, f"{off:06X}: not MOV DPTR"
    if buf[off+1] != 0x0B: return False, f"{off+1:06X}: not 0x0B"
    if buf[off+5] != 0xF0: return False, f"{off+5:06X}: not MOVX"
    orig_dptr = buf[off+2]
    buf[off+2] = 0x75  # DPTR -> 0x0B75
    if buf[off+3] != 0x74: return False, f"{off+3:06X}: not MOV A,#imm"
    buf[off+4] = 0x00     # A <- 0x00
    return True, f"{off:06X}: dptr {orig_dptr:02X}->75; {off+4:06X}: 01->00"

def make_variant(tag, ops, base, outdir):
    buf = bytearray(base)
    before = bytes(buf)
    log=[]
    # verify canonical bytes first (only for the sites we will touch)
    for off,_fn in ops:
        dptr = SITES[off]["dptr"]
        ok, exp, got = expect_seq(before, off, dptr)
        if not ok and off != 0x4522: # we never touch 0x4522
            log.append(f"[WARN] {off:06X}: expected {' '.join(f'{x:02X}' for x in exp)}, got {' '.join(f'{x:02X}' for x in got)}")
    # apply ops
    for off, fn in ops:
        ok,msg = fn(buf, off)
        log.append(("[OK] " if ok else "[ERR] ")+msg)
    # write artifacts
    out_bin = Path(outdir)/f"fw_osd_{tag}.bin"
    write_file(out_bin, buf)
    write_diff(before, buf, out_bin.with_suffix(".diff.txt"))
    sums_meta(out_bin, buf, extra=log)

def main():
    if len(sys.argv)!=3:
        print(f"Usage: {Path(sys.argv[0]).name} <input.bin> <out_dir>")
        sys.exit(1)
    inp = sys.argv[1]; outd = Path(sys.argv[2]); outd.mkdir(parents=True, exist_ok=True)
    base = read_fw(inp)

    # V6: IMM 01->00 at 0x04D0
    make_variant("v6_pb_04d0_imm00", [(0x04D0, patch_imm01_to00)], base, outd)
    # V7: IMM 01->00 at 0x0AC4
    make_variant("v7_pb_0ac4_imm00", [(0x0AC4, patch_imm01_to00)], base, outd)
    # V8: IMM 01->00 at 0x0AFE
    make_variant("v8_pb_0afe_imm00", [(0x0AFE, patch_imm01_to00)], base, outd)
    # V9: redirect 0x0AC4 to write 0x00 -> 0x0B75 (late master clear)
    make_variant("v9_pb_0ac4_to_b75_clear", [(0x0AC4, patch_redirect_to_b75_clear)], base, outd)
    # V10: redirect 0x0AFE to write 0x00 -> 0x0B75 (late master clear)
    make_variant("v10_pb_0afe_to_b75_clear", [(0x0AFE, patch_redirect_to_b75_clear)], base, outd)

if __name__=="__main__":
    main()
