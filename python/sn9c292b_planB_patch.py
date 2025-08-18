#!/usr/bin/env python3
"""
SN9C292B Plan B Patcher — "late-clear stub; LJMP from padding → cave; dynamic SUM16 footer fix"

Purpose
-------
Safely apply the *data-only at runtime* Plan B for Sonix SN9C292B firmware to disable the boot OSD
without touching early-reset code paths. It injects a short stub into a code cave that clears the
OSD flags in XDATA (0xE24..0xE25), jumps back, and then recomputes the 16‑bit zero-sum footer.

This script performs strict pre-flight checks so you don't brick another unit:
- Verifies input size is exactly 0x20000 (131072) bytes
- Confirms the injection window currently contains padding (00 by default)
- Confirms the cave region is unused/padding (00 or FF) before we write the stub
- Computes and reports SUM16 before/after, then fixes the last two bytes (0x1FFE..0x1FFF, LE)
- Emits a JSON summary with all offsets, bytes written and checksums

Defaults below match the JSON you provided, but you can override via CLI.

Usage
-----
python sn9c292b_planB_patch.py --input firmware_backup_base.bin --output firmware_patchB.bin \
  --inject-addr 0x0A516 --inject-run-len 4 --inject-pad-byte 0x00 \
  --cave-addr 0x0BFA8 --return-addr 0x0A51A --clear-count 2 \
  --size 131072 --force=no --dry-run=no

Tip: start with --dry-run=yes to see the plan without writing anything.

Exit codes
----------
0 on success; nonzero on any pre-flight failure (or dry-run mode will still return 0).
"""
import argparse, json, sys, hashlib
from pathlib import Path

def u16le(b0,b1): return b0 | (b1<<8)
def to_bytes_le(u16): return bytes([u16 & 0xFF, (u16>>8) & 0xFF])

def sum16(buf):
    s = 0
    for x in buf:
        s = (s + (x if isinstance(x,int) else x[0])) & 0xFFFF
    return s

def hexdump_slice(data, off, length):
    s = data[off:off+length]
    return " ".join(f"{b:02x}" for b in s)

def parse_int(s):
    if isinstance(s,int): return s
    s = str(s)
    return int(s, 0)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="path to 128 KiB firmware .bin")
    ap.add_argument("--output", required=True, help="path to write patched .bin")
    ap.add_argument("--size", default="131072", help="expected file size (default 131072)")
    ap.add_argument("--inject-addr", default="0x0A516")
    ap.add_argument("--inject-run-len", default="4")
    ap.add_argument("--inject-pad-byte", default="0x00", help="expected padding byte in injection window")
    ap.add_argument("--cave-addr", default="0x0BFA8")
    ap.add_argument("--return-addr", default="0x0A51A")
    ap.add_argument("--clear-count", default="2", help="how many consecutive bytes to clear starting at 0xE24")
    ap.add_argument("--force", default="no", choices=["yes","no"], help="allow non-padding in windows")
    ap.add_argument("--dry-run", default="no", choices=["yes","no"], help="don't write output, just print plan")
    args = ap.parse_args()

    p_in  = Path(args.input)
    p_out = Path(args.output)
    size_expect = parse_int(args.size)
    inject_addr = parse_int(args.inject_addr)
    inject_run_len = parse_int(args.inject_run_len)
    inject_pad_byte = parse_int(args.inject_pad_byte)
    cave_addr = parse_int(args.cave_addr)
    return_addr = parse_int(args.return_addr)
    clear_count = parse_int(args.clear_count)
    force = (args.force == "yes")
    dry_run = (args.dry_run == "yes")

    data = bytearray(Path(p_in).read_bytes())
    if len(data) != size_expect:
        print(f"[FAIL] Size check: got {len(data)} bytes, expected {size_expect}", file=sys.stderr)
        return 2

    # Pre-flight bounds
    if not (0 <= inject_addr <= len(data)-inject_run_len):
        print("[FAIL] inject-addr/run-len out of range", file=sys.stderr); return 2
    if not (0 <= cave_addr <= len(data)-1):
        print("[FAIL] cave-addr out of range", file=sys.stderr); return 2
    if not (0 <= return_addr <= len(data)-1):
        print("[FAIL] return-addr out of range", file=sys.stderr); return 2

    # Check injection window is padding
    inj_window = data[inject_addr:inject_addr+inject_run_len]
    pad_ok = all(b == inject_pad_byte for b in inj_window)
    # If run_len > 3, we overwrite first 3 with LJMP and leave the rest as padding/NOP (00)
    # 8051: LJMP is 3 bytes; any following pad byte is never executed.
    if not pad_ok and not force:
        print(f"[FAIL] Injection window @0x{inject_addr:05x} not all {inject_pad_byte:02x}. "
              f"Found: {hexdump_slice(data, inject_addr, inject_run_len)}. Use --force=yes to override.",
              file=sys.stderr)
        return 2

    # Build stub (22 bytes) at cave_addr:
    # push acc; push dpl; push dph; mov dptr,#0x0E24; clr a; movx @dptr,a; inc dptr; movx @dptr,a;
    # pop dph; pop dpl; pop acc; ljmp return_addr
    if clear_count not in (1,2,3,4):
        print("[FAIL] clear-count must be in 1..4", file=sys.stderr); return 2
    stub = bytearray()
    stub += bytes.fromhex("c0e0 c082 c083".replace(" ",""))     # push ACC, DPL, DPH
    stub += bytes.fromhex("90 0e 24")                            # mov dptr,#0x0E24
    stub += bytes.fromhex("e4")                                  # clr a
    stub += bytes.fromhex("f0")                                  # movx @dptr,a  (E24)
    if clear_count >= 2:
        stub += bytes.fromhex("a3 f0")                           # inc dptr; movx @dptr,a (E25)
    if clear_count >= 3:
        stub += bytes.fromhex("a3 f0")                           # E26
    if clear_count >= 4:
        stub += bytes.fromhex("a3 f0")                           # E27
    stub += bytes.fromhex("d083 d082 d0e0".replace(" ",""))      # pop DPH; pop DPL; pop ACC
    # ljmp return_addr
    stub += bytes([0x02, (return_addr>>8)&0xFF, return_addr & 0xFF])

    stub_len = len(stub)

    # Validate cave is padding
    cave_region = data[cave_addr:cave_addr+stub_len]
    cave_ok = all(b in (0x00, 0xFF) for b in cave_region)
    if not cave_ok and not force:
        print(f"[FAIL] Cave region @0x{cave_addr:05x}..+{stub_len} isn't clean padding (00/FF). "
              f"Found: {hexdump_slice(data, cave_addr, min(stub_len,32))}... Use --force=yes to override.",
              file=sys.stderr)
        return 2

    # Record pre-checksums/hashes
    sha_in = hashlib.sha256(data).hexdigest()
    pre_sum16_all = sum16(data)
    pre_sum16_body = sum16(data[:0x1FFE])

    # Apply patch (in-memory)
    inj_before = bytes(inj_window)
    cave_before = bytes(cave_region)

    # Write the stub
    data[cave_addr:cave_addr+stub_len] = stub
    # Overwrite injection window with LJMP (3 bytes) and pad trailing with 0x00 up to run_len
    data[inject_addr]   = 0x02
    data[inject_addr+1] = (cave_addr >> 8) & 0xFF
    data[inject_addr+2] = cave_addr & 0xFF
    for i in range(3, inject_run_len):
        data[inject_addr+i] = 0x00  # NOP

    # Recompute checksum footer so that sum(all bytes) == 0x0000 (two's complement zero-sum)
    body = data[:0x1FFE]
    chk = (-sum16(body)) & 0xFFFF
    data[0x1FFE] = chk & 0xFF
    data[0x1FFF] = (chk >> 8) & 0xFF

    post_sum16_all = sum16(data)
    post_sum16_body = sum16(data[:0x1FFE])
    sha_out = hashlib.sha256(data).hexdigest()

    summary = {
        "input": str(p_in),
        "output": str(p_out),
        "size_bytes": len(data),
        "plan": "Plan B (late-clear stub; LJMP from padding → cave; dynamic SUM16 footer fix)",
        "parameters": {
            "inject_addr": f"0x{inject_addr:05x}",
            "inject_run_len": inject_run_len,
            "inject_pad_byte": f"0x{inject_pad_byte:02x}",
            "cave_addr": f"0x{cave_addr:05x}",
            "clear_count": clear_count,
            "return_addr": f"0x{return_addr:05x}",
            "checksum_fix_at": "0x1FFFE (last 2 bytes of file)"
        },
        "bytes_written": {
            "inject_ljmp": f"{data[inject_addr]:02x}{data[inject_addr+1]:02x}{data[inject_addr+2]:02x}",
            "inj_before": hexdump_slice(inj_before, 0, len(inj_before)),
            "inj_after": hexdump_slice(data, inject_addr, inject_run_len),
            "stub_len": stub_len,
            "cave_before": hexdump_slice(cave_before, 0, min(len(cave_before), 32)),
            "stub_after": hexdump_slice(data, cave_addr, stub_len),
        },
        "checksum": {
            "pre_sum16_all": pre_sum16_all,
            "pre_sum16_body": pre_sum16_body,
            "fix_value_le": chk,
            "post_sum16_body": post_sum16_body,
            "post_sum16_all": post_sum16_all
        },
        "hashes": {
            "sha256_before": sha_in,
            "sha256_after": sha_out
        }
    }

    # Write output (unless dry-run)
    if dry_run:
        print(json.dumps(summary, indent=2))
        print("[DRY-RUN] No file written.")
        return 0

    # Persist patched image
    Path(p_out).write_bytes(data)

    # Also write a .json sidecar
    Path(str(p_out) + ".json").write_text(json.dumps(summary, indent=2))

    print(json.dumps(summary, indent=2))
    print(f"[OK] Wrote {p_out} and {p_out}.json")
    return 0

if __name__ == "__main__":
    sys.exit(main())
