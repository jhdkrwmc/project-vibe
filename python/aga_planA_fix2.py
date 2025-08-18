#!/usr/bin/env python3
import argparse, os, sys

FW_SIZE_EXPECTED = 128 * 1024  # 131072

# Injection site (integrity-success window)
SITE_A_ADDR   = 0xF094
SITE_A_EXPECT = bytes([0x90, 0x09, 0x8F, 0x74, 0x01, 0xF0])  # MOV DPTR,#0x098F ; MOV A,#1 ; MOVX @DPTR,A
SITE_A_NEW    = bytes([0x12, 0xBB, 0x73, 0x90, 0x09, 0x8F])  # LCALL 0xBB73 ;  MOV DPTR,#0x098F
REEMIT_ADDR   = 0xF09A
REEMIT_BYTES  = bytes([0x74, 0x01, 0xF0])                    # MOV A,#1 ; MOVX @DPTR,A

def hexb(b: bytes) -> str:
    return ' '.join(f'{x:02X}' for x in b)

def require(cond: bool, msg: str):
    if not cond:
        raise RuntimeError(msg)

def read_file(p: str) -> bytearray:
    with open(p, 'rb') as f:
        return bytearray(f.read())

def write_file(p: str, data: bytes):
    with open(p, 'wb') as f:
        f.write(data)

def sum16_words_le(data: bytes) -> int:
    """Sum 16-bit little-endian words over the whole buffer modulo 0x10000."""
    if len(data) & 1:
        # Pad logical view with 0x00 for summation, do not modify data
        total = 0
        for i in range(0, len(data) - 1, 2):
            total = (total + (data[i] | (data[i+1] << 8))) & 0xFFFF
        total = (total + data[-1]) & 0xFFFF
        return total
    total = 0
    for i in range(0, len(data), 2):
        total = (total + (data[i] | (data[i+1] << 8))) & 0xFFFF
    return total

def sum16_bytes(data: bytes) -> int:
    """Byte-wise sum (for info only)."""
    return sum(data) & 0xFFFF

def patch_plan_a(data: bytearray, footer_addr: int, force_f09a: bool=False, target: int=0x0000) -> dict:
    n = len(data)
    require(n >= max(SITE_A_ADDR + 6, REEMIT_ADDR + 3, footer_addr + 2),
            f"Firmware too small ({n} bytes) for requested edits/footer.")
    require(0 <= footer_addr <= n-2, "Footer address out of range.")

    # 0) Report original sums
    word_sum_orig = sum16_words_le(data)
    byte_sum_orig = sum16_bytes(data)

    # 1) Save orig footer and zero it (for clean base)
    orig_footer = bytes(data[footer_addr:footer_addr+2])
    data[footer_addr:footer_addr+2] = b'\x00\x00'
    word_sum_base = sum16_words_le(data)  # words, footer zeroed
    byte_sum_base = sum16_bytes(data)     # bytes, footer zeroed

    # 2) Guard patch site and REEMIT region
    window = bytes(data[SITE_A_ADDR:SITE_A_ADDR+6])
    require(window == SITE_A_EXPECT,
            (f"Signature mismatch at 0x{SITE_A_ADDR:04X}.\n"
             f"  Have: {hexb(window)}\n"
             f"  Want: {hexb(SITE_A_EXPECT)}"))

    reemit_old = bytes(data[REEMIT_ADDR:REEMIT_ADDR+3])
    if not force_f09a:
        allowed = {b'\x00\x00\x00', b'\xFF\xFF\xFF'}
        require(reemit_old in allowed,
                (f"REEMIT at 0x{REEMIT_ADDR:04X} not pad: {hexb(reemit_old)}; "
                 f"use --force-f09a to overwrite if you are sure."))

    # 3) Apply patch + re-emit displaced bytes
    data[SITE_A_ADDR:SITE_A_ADDR+6] = SITE_A_NEW
    data[REEMIT_ADDR:REEMIT_ADDR+3] = REEMIT_BYTES

    # 4) Compute 16-bit LE word-sum compensator
    data[footer_addr:footer_addr+2] = b'\x00\x00'
    s = sum16_words_le(data)
    fix = (target - s) & 0xFFFF  # target is 0 by default
    data[footer_addr]     = fix & 0xFF
    data[footer_addr + 1] = (fix >> 8) & 0xFF

    # 5) Verify word-sum target
    word_sum_after = sum16_words_le(data)
    require(word_sum_after == (target & 0xFFFF),
            f"Final WORD-SUM16 != 0x{target:04X} (got 0x{word_sum_after:04X}).")

    # (Optional) For info only: show byte-sum too
    byte_sum_after = sum16_bytes(data)

    diff = [
        (SITE_A_ADDR, SITE_A_EXPECT, SITE_A_NEW),
        (REEMIT_ADDR, reemit_old, REEMIT_BYTES),
        (footer_addr, orig_footer, bytes(data[footer_addr:footer_addr+2])),
    ]
    return {
        "footer_addr": footer_addr,
        "word_sum_orig": word_sum_orig,
        "byte_sum_orig": byte_sum_orig,
        "word_sum_base": word_sum_base,
        "byte_sum_base": byte_sum_base,
        "word_sum_after": word_sum_after,
        "byte_sum_after": byte_sum_after,
        "fix_word": fix,
        "diff": diff
    }

def main():
    ap = argparse.ArgumentParser(description="SN9C292B Plan A patcher (word-sum, LE).")
    ap.add_argument("input", help="Input firmware .bin")
    ap.add_argument("output", help="Patched firmware .bin")
    ap.add_argument("--force-f09a", action="store_true",
                    help="Overwrite 0xF09A..0xF09C even if not pad.")
    ap.add_argument("--no-size-check", action="store_true",
                    help="Skip strict 128 KiB check.")
    ap.add_argument("--footer-addr", type=lambda x: int(x,0), default=None,
                    help="Override footer address (default=len(data)-2).")
    ap.add_argument("--target", type=lambda x: int(x,0), default=0x0000,
                    help="Target 16-bit word-sum (default 0x0000).")
    args = ap.parse_args()

    data = read_file(args.input)
    if not args.no_size_check:
        require(len(data) == FW_SIZE_EXPECTED,
                f"Unexpected size {len(data)} (expected {FW_SIZE_EXPECTED}). Use --no-size-check to override.")

    footer_addr = (len(data) - 2) if args.footer_addr is None else args.footer_addr

    try:
        res = patch_plan_a(data, footer_addr, force_f09a=args.force_f09a, target=args.target)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    # Report
    print("== Plan A patch summary ==")
    print(f"Image size                : {len(data)} bytes")
    print(f"Footer addr (LE word)     : 0x{res['footer_addr']:05X}")
    print(f"WORD-SUM16(as-is)         : 0x{res['word_sum_orig']:04X}")
    print(f"BYTE-SUM16(as-is)         : 0x{res['byte_sum_orig']:04X}")
    print(f"WORD-SUM16(base, footer=0): 0x{res['word_sum_base']:04X}")
    print(f"BYTE-SUM16(base, footer=0): 0x{res['byte_sum_base']:04X}")
    print(f"Fix word (LE)             : 0x{res['fix_word']:04X}")
    print(f"WORD-SUM16(after)         : 0x{res['word_sum_after']:04X}")
    print(f"BYTE-SUM16(after)         : 0x{res['byte_sum_after']:04X}")
    print("Edits:")
    for addr, old, new in res["diff"]:
        print(f"  0x{addr:05X}: {hexb(old)}  ->  {hexb(new)}")

    # Write out
    outdir = os.path.dirname(os.path.abspath(args.output))
    if outdir and not os.path.isdir(outdir):
        os.makedirs(outdir, exist_ok=True)
    write_file(args.output, data)
    print(f"[OK] Wrote: {args.output}")

if __name__ == "__main__":
    main()
