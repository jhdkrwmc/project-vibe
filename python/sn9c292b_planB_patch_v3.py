#!/usr/bin/env python3
"""
SN9C292B Plan B Patcher (v3) — dynamic tail checksum fix (corrected)
- Late-clear stub in cave
- LJMP from padding window → stub → LJMP back
- Correct 16‑bit little‑endian zero‑sum written to *last two bytes* of file

This version fixes a bug from the previous variant that wrote the checksum
to 0x1FFE/0x1FFF (64 KiB footer). Here we always write to len(file)-2..-1.
"""

import argparse, json, sys, hashlib
from pathlib import Path

def sum16(buf: bytes) -> int:
    s = 0
    for b in buf:
        s = (s + b) & 0xFFFF
    return s

def hexdump_slice(data: bytes, off: int, length: int) -> str:
    s = data[off:off+length]
    return " ".join(f"{b:02x}" for b in s)

def parse_int(s):
    if isinstance(s,int): return s
    return int(str(s), 0)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--inject-addr", default="0x0A516")
    ap.add_argument("--inject-run-len", default="4")
    ap.add_argument("--inject-pad-byte", default="0x00")
    ap.add_argument("--cave-addr", default="0x00BFA8")
    ap.add_argument("--return-addr", default="0x0A51A")
    ap.add_argument("--clear-count", default="2")
    ap.add_argument("--dry-run", default="no", choices=["yes","no"])
    ap.add_argument("--force", default="no", choices=["yes","no"])
    args = ap.parse_args()

    inj = parse_int(args.inject_addr)
    run_len = parse_int(args.inject_run_len)
    pad_b = parse_int(args.inject_pad_byte)
    cave = parse_int(args.cave_addr)
    ret  = parse_int(args.return_addr)
    nclr = parse_int(args.clear_count)
    dry  = (args.dry_run=="yes")
    force= (args.force=="yes")

    data = bytearray(Path(args.input).read_bytes())
    size = len(data)
    if size % 2:
        print(f"[WARN] odd file size {size}; sum16 still computed over all bytes", file=sys.stderr)

    # sanity ranges
    if inj+run_len > size or cave >= size or ret >= size:
        print("[FAIL] address out of range", file=sys.stderr); sys.exit(2)

    # verify injection window is padding (unless --force)
    win = data[inj:inj+run_len]
    if not all(b==pad_b for b in win) and not force:
        print(f"[FAIL] inj window not all {pad_b:02x}: {hexdump_slice(win,0,len(win))}", file=sys.stderr); sys.exit(2)

    # build stub
    if nclr not in (1,2,3,4):
        print("[FAIL] clear-count must be 1..4", file=sys.stderr); sys.exit(2)
    stub = bytearray()
    stub += bytes.fromhex("c0e0 c082 c083".replace(" ",""))  # push acc,dpl,dph
    stub += bytes.fromhex("90 0e 24")                        # mov dptr,#0x0E24
    stub += b"\xE4"                                          # clr a
    for i in range(nclr):
        if i>0: stub += b"\xA3"                              # inc dptr
        stub += b"\xF0"                                      # movx @dptr,a
    stub += bytes.fromhex("d083 d082 d0e0".replace(" ",""))  # pop dph,dpl,acc
    stub += bytes([0x02, (ret>>8)&0xFF, ret&0xFF])           # ljmp ret
    stub_len = len(stub)

    # cave must be padding (00/FF) before we write (unless --force)
    cave_span = data[cave:cave+stub_len]
    if len(cave_span) != stub_len:
        print("[FAIL] cave truncated", file=sys.stderr); sys.exit(2)
    if not all(b in (0x00,0xFF) for b in cave_span) and not force:
        print(f"[FAIL] cave not clean padding: {hexdump_slice(cave_span,0,min(32,stub_len))}", file=sys.stderr); sys.exit(2)

    sha_before = hashlib.sha256(data).hexdigest()
    pre_all = sum16(data)

    # apply
    data[cave:cave+stub_len] = stub
    data[inj:inj+3] = bytes([0x02, (cave>>8)&0xFF, cave&0xFF])
    for i in range(3, run_len):
        data[inj+i] = 0x00

    # checksum: write to last 2 bytes
    tail = size - 2
    body = data[:tail]
    fix = (-sum16(body)) & 0xFFFF
    data[tail]   = fix & 0xFF
    data[tail+1] = (fix >> 8) & 0xFF

    post_all = sum16(data)
    sha_after = hashlib.sha256(data).hexdigest()

    summary = {
        "input": str(Path(args.input)),
        "output": str(Path(args.output)),
        "size_bytes": size,
        "plan": "Plan B (late-clear stub; LJMP from padding → cave; dynamic SUM16 footer fix)",
        "parameters": {
            "inject_addr": f"0x{inj:05x}",
            "inject_run_len": run_len,
            "inject_pad_byte": f"0x{pad_b:02x}",
            "cave_addr": f"0x{cave:05x}",
            "clear_count": nclr,
            "return_addr": f"0x{ret:05x}",
            "checksum_fix_at": f"0x{tail:05x} (last 2 bytes)"
        },
        "bytes_written": {
            "inject_ljmp": f"{data[inj]:02x}{data[inj+1]:02x}{data[inj+2]:02x}",
            "inj_before": hexdump_slice(win,0,len(win)),
            "inj_after": hexdump_slice(data,inj,run_len),
            "stub_len": stub_len,
            "cave_before": hexdump_slice(cave_span,0,min(32,stub_len)),
            "stub_after": hexdump_slice(data,cave,stub_len),
        },
        "checksum": {
            "pre_sum16_all": pre_all,
            "fix_value_le": fix,
            "post_sum16_all": post_all
        },
        "hashes": {
            "sha256_before": sha_before,
            "sha256_after": sha_after
        }
    }

    if dry:
        print(json.dumps(summary, indent=2))
        print("[DRY-RUN] No file written.")
        return

    Path(args.output).write_bytes(data)
    Path(str(args.output)+".json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    print(f"[OK] Wrote {args.output} and {args.output}.json")

if __name__ == "__main__":
    main()
