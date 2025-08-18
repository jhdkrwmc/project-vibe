#!/usr/bin/env python3
import argparse, sys

IMG_SIZE_EXPECTED = 128 * 1024  # 131072
SITE_ADDR   = 0xF094
SITE_EXPECT = bytes([0x90,0x09,0x8F,0x74,0x01,0xF0])          # MOV DPTR,#098F ; MOV A,#1 ; MOVX @DPTR,A
SITE_PATCH  = bytes([0x12,0xBB,0x73,0x90,0x09,0x8F])          # LCALL 0xBB73   ; MOV DPTR,#098F
REEMIT_ADDR = 0xF09A
REEMIT_BYTES= bytes([0x74,0x01,0xF0])                         # MOV A,#1 ; MOVX @DPTR,A

# Optional check for the tiny leaf at 0xBB73: MOV DPTR,#0x0E24 ; MOV A,#0xFF ; MOVX @DPTR,A ; RET
OSD_HELPER_ADDR = 0xBB73
OSD_HELPER_EXPECT_PREFIX = bytes([0x90,0x0E,0x24, 0x74,0xFF, 0xF0])  # allow either RET or INC DPTR afterwards


def hexb(b: bytes) -> str:
    return ' '.join(f'{x:02X}' for x in b)


def sum16_bytes(d: bytes) -> int:  # byte-wise mod 0x10000
    return sum(d) & 0xFFFF


def sum16_words_le(d: bytes) -> int:  # word-wise LE mod 0x10000
    n=len(d)
    total=0
    i=0
    while i+1<n:
        total=(total + (d[i] | (d[i+1]<<8))) & 0xFFFF
        i+=2
    if i<n:
        total=(total + d[i]) & 0xFFFF  # odd length: last byte
    return total


def pick_scheme(orig: bytes, footer_addr: int) -> str:
    # 1) As-is (with the original footer)
    sb_as_is = sum16_bytes(orig)
    sw_as_is = sum16_words_le(orig)
    if sb_as_is == 0 and sw_as_is != 0:
        return "byte"
    if sw_as_is == 0 and sb_as_is != 0:
        return "word"
    if sb_as_is == 0 and sw_as_is == 0:
        return "word"  # prefer word if both 0

    # 2) Try base (footer zeroed)
    work = bytearray(orig)
    work[footer_addr:footer_addr+2] = b'\x00\x00'
    sb_base = sum16_bytes(work)
    sw_base = sum16_words_le(work)

    # Prefer the one that becomes exactly 0 after writing a 2B compensator
    # Both schemes are solvable; choose word by default if ambiguous.
    if sb_base != 0 and sw_base == 0:
        return "word"
    if sw_base != 0 and sb_base == 0:
        return "byte"
    return "word"


def calc_fix_bytes(data: bytearray, footer_addr: int, scheme: str) -> int:
    data[footer_addr:footer_addr+2] = b'\x00\x00'
    if scheme == "byte":
        s = sum16_bytes(data)
    else:
        s = sum16_words_le(data)
    fix = (-s) & 0xFFFF
    data[footer_addr]     = fix & 0xFF
    data[footer_addr + 1] = (fix >> 8) & 0xFF
    return fix


def main():
    ap = argparse.ArgumentParser(description="SN9C292B Plan A patcher (post-integrity OSD-OFF + checksum fix).")
    ap.add_argument("input", help="Input 128 KiB firmware .bin")
    ap.add_argument("output", help="Output patched .bin")
    ap.add_argument("--no-size-check", action="store_true", help="Allow non-131072 sizes")
    ap.add_argument("--force-reemit", dest="force_reemit", action="store_true", help="Overwrite 0xF09A..0xF09C even if not pad")
    args = ap.parse_args()

    data = bytearray(open(args.input, "rb").read())
    n = len(data)
    if not args.no_size_check and n != IMG_SIZE_EXPECTED:
        print(f"[ERROR] Unexpected size {n}, expected {IMG_SIZE_EXPECTED}", file=sys.stderr)
        sys.exit(2)

    footer_addr = n - 2
    as_is_sb = sum16_bytes(data)
    as_is_sw = sum16_words_le(data)

    # Guard site
    win = bytes(data[SITE_ADDR:SITE_ADDR+6])
    if win != SITE_EXPECT:
        print(f"[ERROR] Signature mismatch at 0x{SITE_ADDR:04X}. Have: {hexb(win)}  Want: {hexb(SITE_EXPECT)}", file=sys.stderr)
        sys.exit(3)

    # Optional: verify OSD helper leaf at 0xBB73
    helper = bytes(data[OSD_HELPER_ADDR:OSD_HELPER_ADDR+len(OSD_HELPER_EXPECT_PREFIX)])
    if helper != OSD_HELPER_EXPECT_PREFIX:
        print(f"[ERROR] OSD helper @0x{OSD_HELPER_ADDR:04X} unexpected: {hexb(helper)} (want prefix {hexb(OSD_HELPER_EXPECT_PREFIX)})", file=sys.stderr)
        sys.exit(3)

    # Guard RE-EMIT region unless forced
    rem_old = bytes(data[REEMIT_ADDR:REEMIT_ADDR+3])
    if not args.force_reemit:
        if rem_old not in (b'\x00\x00\x00', b'\xFF\xFF\xFF'):
            print(f"[ERROR] 0x{REEMIT_ADDR:04X}.. re-emit area not pad ({hexb(rem_old)}). Use --force-reemit to overwrite.", file=sys.stderr)
            sys.exit(4)

    # Patch
    data[SITE_ADDR:SITE_ADDR+6] = SITE_PATCH
    data[REEMIT_ADDR:REEMIT_ADDR+3] = REEMIT_BYTES

    # Pick checksum scheme on original image (oracle)
    scheme = pick_scheme(open(args.input, "rb").read(), footer_addr)

    # Fix footer
    fix = calc_fix_bytes(data, footer_addr, scheme)

    # Verify
    final = sum16_bytes(data) if scheme == "byte" else sum16_words_le(data)
    if final != 0:
        print(f"[ERROR] Final {scheme}-sum != 0 (0x{final:04X})", file=sys.stderr)
        sys.exit(5)

    # Report
    print("== Plan A patch summary ==")
    print(f"Image size          : {n} bytes")
    print(f"Footer addr         : 0x{footer_addr:05X}")
    print(f"Scheme (auto)       : {scheme}-sum16")
    print(f"AS-IS byte-sum16    : 0x{as_is_sb:04X}")
    print(f"AS-IS word-sum16    : 0x{as_is_sw:04X}")
    print(f"Site @0x{SITE_ADDR:04X}: {hexb(SITE_EXPECT)}  ->  {hexb(SITE_PATCH)}")
    print(f"Re-emit @0x{REEMIT_ADDR:04X}: {hexb(rem_old)}  ->  {hexb(REEMIT_BYTES)}")
    print(f"Fix word (LE)       : 0x{fix:04X}")
    print(f"Final {scheme}-sum16: 0x{final:04X}")

    open(args.output, "wb").write(data)
    print(f"[OK] wrote {args.output}")


if __name__ == "__main__":
    main()


