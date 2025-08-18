"""
patch_boot_osd_stub_v2.py

Clean Sonix SN9C292B firmware patcher:
- Injects a tiny 'late-clear' stub that clears OSD bytes (E24..E27 or first N)
- Patches one padding window to LJMP to the stub, then LJMPs back
- Verifies sites are padding/unused (basic sanity)
- Dynamically fixes the 16-bit little-endian word-sum checksum by writing a
  two's-complement compensator into the LAST TWO BYTES of the image
  (works for 128 KiB images; no hard-coded footer offsets).

Default addresses are from your previous attempts:
  INJECT at 0x0A516  (padding window used to insert LJMP)
  CAVE   at 0x00BFA8 (code cave for the stub)
The script auto-detects how many padding bytes exist at INJECT and returns
after the whole padding block.

Usage:
  python patch_boot_osd_stub_v2.py IN.bin OUT.bin [--inj 0xA516] [--cave 0xBFA8]
       [--n 2|4] [--dry-run] [--expect FF] [--keep-original-footer]

Notes:
- This script is intentionally conservative: it aborts if the injection window
  has non-padding bytes or is shorter than 3 bytes (LJMP size).
- It writes the checksum fix to the *actual last two bytes* of the file.
- If you want to keep the original footer value (for diffing) use
  --keep-original-footer and the script will insert an internal 2-byte pad
  near the stub to absorb the checksum delta instead.

Author: gpt-5-thinking
"""

from __future__ import annotations
import argparse, json, os, sys
from typing import Tuple

def readbin(path: str) -> bytearray:
    with open(path, 'rb') as f:
        return bytearray(f.read())

def writebin(path: str, data: bytes) -> None:
    with open(path, 'wb') as f:
        f.write(data)

def is_padding_block(b: bytes) -> bool:
    """True if all bytes are 0x00 or all 0xFF."""
    if not b:
        return False
    s = set(b)
    return s == {0x00} or s == {0xFF}

def scan_padding_forward(data: bytes, start: int, limit: int = 32) -> Tuple[int, int]:
    """
    Return (run_len, pad_byte) for a padding run starting at 'start' (0x00 or 0xFF).
    If not padding, returns (0, -1). Caps run to 'limit' for safety.
    """
    if start >= len(data):
        return (0, -1)
    b0 = data[start]
    if b0 not in (0x00, 0xFF):
        return (0, -1)
    pad = b0
    end = min(len(data), start + limit)
    i = start
    while i < end and data[i] == pad:
        i += 1
    return (i - start, pad)

def ljmp_bytes(addr: int) -> bytes:
    """Generate LJMP opcode (0x02) to absolute 16-bit address (big endian)."""
    return bytes((0x02, (addr >> 8) & 0xFF, addr & 0xFF))

def build_stub_ljmp_back(return_addr: int, clear_n: int = 2) -> bytes:
    """
    Build a minimal stub that clears E24..(E24+clear_n-1) to 0x00
    Preserves ACC, DPL, DPH. Ends with LJMP return_addr.
    """
    if clear_n < 1 or clear_n > 4:
        raise ValueError("clear_n must be 1..4")
    code = bytearray()
    code += b"\xC0\xE0"      # PUSH ACC
    code += b"\xC0\x82"      # PUSH DPL
    code += b"\xC0\x83"      # PUSH DPH
    code += b"\x90\x0E\x24"  # MOV DPTR,#0x0E24
    code += b"\xE4"          # CLR A
    for i in range(clear_n):
        if i > 0:
            code += b"\xA3"  # INC DPTR
        code += b"\xF0"      # MOVX @DPTR,A
    code += b"\xD0\x83"      # POP DPH
    code += b"\xD0\x82"      # POP DPL
    code += b"\xD0\xE0"      # POP ACC
    code += ljmp_bytes(return_addr)  # LJMP back
    return bytes(code)

def sum16_words_le(data: bytes) -> int:
    """Compute little-endian 16-bit word sum over entire buffer (wrap at 0x10000)."""
    total = 0
    n = len(data)
    # process pairs
    for i in range(0, n - (n % 2), 2):
        total = (total + data[i] + (data[i+1] << 8)) & 0xFFFF
    if n % 2:
        total = (total + data[-1]) & 0xFFFF
    return total

def apply_checksum_compensator(data: bytearray, prefer_tail: bool = True, pad_addr: int | None = None) -> Tuple[int, int, int]:
    """
    Make total SUM16 == 0 by writing two's complement fix to either:
    - The last 2 bytes (prefer_tail=True), or
    - An internal pad at 'pad_addr' (prefer_tail=False).
    Returns (fix_value, where_addr, new_sum).
    """
    if prefer_tail:
        where = len(data) - 2
    else:
        if pad_addr is None:
            raise ValueError("pad_addr required when prefer_tail=False")
        where = pad_addr
        if where < 0 or where + 2 > len(data):
            raise ValueError("pad_addr outside image")
    # zero the slot
    data[where:where+2] = b"\x00\x00"
    s = sum16_words_le(data)
    fix = (-s) & 0xFFFF
    data[where] = fix & 0xFF
    data[where+1] = (fix >> 8) & 0xFF
    return (fix, where, sum16_words_le(data))

def u16le_at(data: bytes, off: int) -> int:
    return data[off] | (data[off+1] << 8)

def main():
    ap = argparse.ArgumentParser(description="SN9C292B OSD-off late-clear patcher (LJMP stub + dynamic SUM16 fix)")
    ap.add_argument("inp", help="input firmware bin")
    ap.add_argument("out", help="output firmware bin")
    ap.add_argument("--inj", type=lambda x:int(x,0), default=0x0A516, help="injection address (padding to replace with LJMP)")
    ap.add_argument("--cave", type=lambda x:int(x,0), default=0x00BFA8, help="code cave address for stub")
    ap.add_argument("--n", type=int, default=2, choices=[1,2,3,4], help="how many bytes to clear starting at 0xE24 (default 2)")
    ap.add_argument("--limit", type=int, default=32, help="max padding run to treat as a single block at --inj")
    ap.add_argument("--dry-run", action="store_true", help="do not write out.bin; just print report")
    ap.add_argument("--expect", choices=["00","FF"], help="require injection padding to be all 00 or all FF")
    ap.add_argument("--keep-original-footer", action="store_true", default=False,
                    help="do NOT overwrite last 2 bytes; instead use a tiny 2-byte pad near the stub to absorb checksum delta")
    ap.add_argument("--report", default=None, help="optional path to write JSON report")
    args = ap.parse_args()

    data = readbin(args.inp)
    size = len(data)
    if size % 2 != 0:
        print(f"[!] Warning: image size {size} not even; checksum algo assumes even length")

    # 1) Validate injection window
    run_len, pad_byte = scan_padding_forward(data, args.inj, args.limit)
    if run_len < 3:
        raise SystemExit(f"[FATAL] Injection site 0x{args.inj:05X} has run_len={run_len} (<3); not enough for LJMP")

    if args.expect is not None:
        expect = 0x00 if args.expect == "00" else 0xFF
        if pad_byte != expect:
            raise SystemExit(f"[FATAL] Injection site pad != {args.expect}; found {pad_byte:02X}")

    if not is_padding_block(bytes([pad_byte]) * run_len):
        # This is always true by construction; keep for clarity
        pass

    inj_window = bytes(data[args.inj:args.inj+run_len])
    # 2) Validate cave
    stub = build_stub_ljmp_back(return_addr=args.inj + run_len, clear_n=args.n)
    cave_span = data[args.cave:args.cave+len(stub)]
    if len(cave_span) != len(stub):
        raise SystemExit(f"[FATAL] Cave 0x{args.cave:05X} truncated (image too small?)")

    if not is_padding_block(cave_span):
        # allow mixed 00/FF but require them to be only 00 or FF, not other bytes
        s = set(cave_span)
        if not s.issubset({0x00, 0xFF}):
            raise SystemExit(f"[FATAL] Cave 0x{args.cave:05X} not empty padding; bytes={cave_span[:16].hex()}...")

    # 3) Apply patches in a working copy
    patched = bytearray(data)

    # 3a) Write stub into cave
    patched[args.cave:args.cave+len(stub)] = stub

    # 3b) Overwrite injection window with LJMP and pad the rest with original pad byte
    patched[args.inj:args.inj+3] = ljmp_bytes(args.cave)
    if run_len > 3:
        patched[args.inj+3:args.inj+run_len] = bytes([pad_byte]) * (run_len - 3)

    # 4) Checksum compensation
    before_sum = sum16_words_le(patched)
    # We'll fix to 0 by writing compensator either at tail or a tiny 2-byte pad right after the stub
    if args.keep_original_footer:
        pad_addr = args.cave + len(stub)  # right after stub (must be padding)
        # ensure 2 bytes exist
        if pad_addr + 2 > len(patched):
            raise SystemExit(f"[FATAL] No room for internal checksum pad at 0x{pad_addr:05X}")
        fix, where, after_sum = apply_checksum_compensator(patched, prefer_tail=False, pad_addr=pad_addr)
        where_desc = f"0x{where:05X} (internal pad near stub)"
    else:
        fix, where, after_sum = apply_checksum_compensator(patched, prefer_tail=True)
        where_desc = f"0x{where:05X} (last 2 bytes of file)"

    report = {
        "input": os.path.abspath(args.inp),
        "output": os.path.abspath(args.out),
        "size_bytes": size,
        "plan": "Plan B (late-clear stub; LJMP from padding → cave; dynamic SUM16 footer fix)",
        "parameters": {
            "inject_addr": f"0x{args.inj:05X}",
            "inject_run_len": run_len,
            "inject_pad_byte": f"0x{pad_byte:02X}",
            "cave_addr": f"0x{args.cave:05X}",
            "clear_count": args.n,
            "return_addr": f"0x{args.inj + run_len:05X}",
            "checksum_fix_at": where_desc
        },
        "bytes_written": {
            "inject_ljmp": patched[args.inj:args.inj+3].hex(),
            "stub_len": len(stub),
            "stub_prefix": stub[:16].hex(),
            "stub_suffix": stub[-8:].hex()
        },
        "checksum": {
            "pre_fix_sum16": before_sum,
            "fix_value_le": fix,
            "post_fix_sum16": after_sum
        }
    }

    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    # 5) Write output
    if args.dry_run:
        print(json.dumps(report, indent=2))
        return

    writebin(args.out, patched)
    print(json.dumps(report, indent=2))
    print(f"[+] Wrote patched firmware to: {args.out}")

if __name__ == "__main__":
    main()
