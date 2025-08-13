#!/usr/bin/env python3
# make_osd_variants.py
#
# Batch out six SN9C292B firmware variants with different OSD-off strategies.
# - Verifies bytes at the four known OSD enable sites before patching.
# - Logs diffs and checksums for each output.
# - DOES NOT depend on IDA.
#
# Usage: python make_osd_variants.py "firmware_backup - Copy (4).bin" out

import sys, os, hashlib
from pathlib import Path
from textwrap import dedent

# -----------------------
# Constants / parameters
# -----------------------

FW_SIZE = 0x20000  # 128 KiB expected
# Known OSD enable sequences (file offsets in this exact image):
#   seq = [90, 0B, 75|76|77, 74, 01, F0]
OSD_SITES = [
    # (offset, third_byte (0x75..0x77), label)
    (0x0004D0, 0x77, "site_04D0_0B77"),
    (0x000AC4, 0x76, "site_0AC4_0B76"),
    (0x000AFE, 0x77, "site_0AFE_0B77"),
    (0x004522, 0x75, "site_4522_0B75"),  # often on the early init path
]

# Optional checksum footer location for variants that use it
FOOTER_ADDR = 0x1FFE  # last two bytes of 128 KiB image

# -----------------------
# Helpers
# -----------------------

def read_firmware(path: Path) -> bytearray:
    data = bytearray(path.read_bytes())
    if len(data) != FW_SIZE:
        print(f"[!] Unexpected size: {len(data)} (expected {FW_SIZE}). Will proceed anyway.")
    return data

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def hexrow(addr: int, chunk: bytes) -> str:
    return f"{addr:06X}: " + " ".join(f"{x:02X}" for x in chunk)

def dump_tail(label: str, b: bytes, outfp):
    start = max(0, len(b) - 0x40)
    outfp.write(f"\n== {label} tail (last 64 bytes) ==\n")
    for off in range(start, len(b), 16):
        outfp.write(hexrow(off, b[off:off+16]) + "\n")

def verify_osd_sites(b: bytes):
    """Return dict: offset -> {'ok':bool,'found':bytes}"""
    out = {}
    for off, third, name in OSD_SITES:
        expect = bytes([0x90, 0x0B, third, 0x74, 0x01, 0xF0])
        found = bytes(b[off:off+6])
        out[off] = {"ok": (found == expect), "found": found, "expect": expect, "name": name}
    return out

def write_diff(old: bytes, new: bytes, path: Path):
    lines = []
    for i, (a, c) in enumerate(zip(old, new)):
        if a != c:
            lines.append(f"{i:06X}: {a:02X} -> {c:02X}")
    if len(new) > len(old):
        for i in range(len(old), len(new)):
            lines.append(f"{i:06X}: -- -> {new[i]:02X}")
    path.write_text("\n".join(lines) + ("\n" if lines else ""))

def sum16_words_le(b: bytes, end_exclusive: int) -> int:
    """Little-endian 16-bit words sum over [0, end_exclusive). end_exclusive should be even."""
    total = 0
    end = end_exclusive & ~1
    for i in range(0, end, 2):
        total = (total + (b[i] | (b[i+1] << 8))) & 0xFFFF
    return total

def twos_complement16(x: int) -> int:
    return (-x) & 0xFFFF

def sum8_bytes(b: bytes, end_exclusive: int) -> int:
    total = 0
    for i in range(0, end_exclusive):
        total = (total + b[i]) & 0xFF
    return total

def write_wordsum_footer_le(buf: bytearray):
    """Compute 16-bit word-sum two's complement and write LE word at FOOTER_ADDR..+1."""
    if FOOTER_ADDR + 1 >= len(buf):
        raise ValueError("Footer address outside image")
    # Exclude footer word from the sum
    total = sum16_words_le(buf, FOOTER_ADDR)
    need = twos_complement16(total)
    buf[FOOTER_ADDR] = need & 0xFF
    buf[FOOTER_ADDR + 1] = (need >> 8) & 0xFF
    return need

def write_bytesum_footer_dup(buf: bytearray):
    """Compute 8-bit byte-sum two's complement over [0..FOOTER_ADDR) and duplicate into both bytes."""
    if FOOTER_ADDR + 1 >= len(buf):
        raise ValueError("Footer address outside image")
    total = sum8_bytes(buf, FOOTER_ADDR)
    need = (-total) & 0xFF
    buf[FOOTER_ADDR] = need
    buf[FOOTER_ADDR + 1] = need  # duplicate LSB -> MSB
    return need

def ensure_dirs(base: Path):
    (base / "logs").mkdir(parents=True, exist_ok=True)

def save_sums_and_meta(bin_path: Path, b: bytes, extra_lines=None):
    sums = []
    sums.append(f"file: {bin_path.name}")
    sums.append(f"size: {len(b)}")
    sums.append(f"sha256: {sha256_hex(b)}")
    # Also record word-sum and byte-sum (excluding footer)
    sums.append(f"wordsum16_le(0..{FOOTER_ADDR:04X}) = 0x{sum16_words_le(b, FOOTER_ADDR):04X}")
    sums.append(f"bytesum8(0..{FOOTER_ADDR:04X})     = 0x{sum8_bytes(b, FOOTER_ADDR):02X}")
    if extra_lines:
        sums.extend(extra_lines)
    (bin_path.with_suffix(".sum.txt")).write_text("\n".join(sums) + "\n")

# -----------------------
# Patch primitives
# -----------------------

def patch_immediate01_to00(buf: bytearray, site_off: int, site_desc: str, log: list):
    """Change MOV A,#01 -> MOV A,#00 at site (byte +4 in the 6-byte sequence)."""
    imm_off = site_off + 4
    old = buf[imm_off]
    if old != 0x01:
        log.append(f"[WARN] {site_desc}: expected 0x01 at +4, found 0x{old:02X}. Skipped.")
        return False
    buf[imm_off] = 0x00
    log.append(f"[OK]   {site_desc}: 0x{imm_off:06X} 01->00")
    return True

def patch_movx_to_nop(buf: bytearray, site_off: int, site_desc: str, log: list):
    """NOP the MOVX @DPTR,A (byte +5)."""
    op_off = site_off + 5
    old = buf[op_off]
    if old != 0xF0:
        log.append(f"[WARN] {site_desc}: expected MOVX F0 at +5, found 0x{old:02X}. Skipped.")
        return False
    buf[op_off] = 0x00  # 8051 NOP
    log.append(f"[OK]   {site_desc}: 0x{op_off:06X} F0->00 (NOP MOVX)")
    return True

def verify_seq_at_site(b: bytes, site_off: int, third_byte: int) -> bool:
    expect = bytes([0x90, 0x0B, third_byte, 0x74, 0x01, 0xF0])
    return b[site_off:site_off+6] == expect

# -----------------------
# Variants
# -----------------------

def build_variants(baseline: bytes, outdir: Path):
    ensure_dirs(outdir)
    logs_dir = outdir / "logs"
    (logs_dir / "ends-of-image.txt").write_text("")  # clear

    # Record tail of baseline
    with (logs_dir / "ends-of-image.txt").open("a") as fp:
        dump_tail("BASELINE", baseline, fp)

    # Re-verify OSD sites and write a mini table
    verify = verify_osd_sites(baseline)
    lines = ["| site | offset | bytes | expect | ok |",
             "|---|---:|---|---|:--:|"]
    for off, info in sorted(verify.items()):
        lines.append(
            f"| {info['name']} | 0x{off:06X} | "
            f"{' '.join(f'{x:02X}' for x in info['found'])} | "
            f"{' '.join(f'{x:02X}' for x in info['expect'])} | "
            f"{'yes' if info['ok'] else 'NO'} |"
    )

    # Helper to create one variant
    def make_variant(tag, patch_ops, write_footer=None, footer_desc=None):
        out_bin = outdir / f"fw_osd_{tag}.bin"
        out_diff = outdir / f"fw_osd_{tag}.diff.txt"
        buf = bytearray(baseline)  # copy
        before = bytes(buf)
        log_lines = []
        # Check baseline matches at sites before mutating
        for off, third, name in OSD_SITES:
            if not verify_seq_at_site(before, off, third):
                log_lines.append(f"[WARN] {name}@0x{off:06X}: sequence mismatch; expected "
                                 f"{' '.join(f'{x:02X}' for x in bytes([0x90,0x0B,third,0x74,0x01,0xF0]))}, "
                                 f"found {' '.join(f'{x:02X}' for x in before[off:off+6])}")
        # Apply requested patch ops
        ok_any = False
        for desc, fn in patch_ops:
            if fn(buf, desc, log_lines):
                ok_any = True

        # Optional footer write *after* edits
        extra_sum_lines = []
        if write_footer is not None:
            try:
                val = write_footer(buf)
                if footer_desc:
                    extra_sum_lines.append(f"{footer_desc}: 0x{val:04X}" if isinstance(val, int) else f"{footer_desc}: {val}")
            except Exception as e:
                log_lines.append(f"[ERR] Footer write failed: {e!r}")

        # Write files
        out_bin.write_bytes(buf)
        write_diff(before, buf, out_diff)
        save_sums_and_meta(out_bin, buf, extra_lines=extra_sum_lines)
        # Append tail dump
        with (logs_dir / "ends-of-image.txt").open("a") as fp:
            dump_tail(tag.upper(), buf, fp)
        # Save patch log
        (out_bin.with_suffix(".patchlog.txt")).write_text("\n".join(log_lines) + ("\n" if log_lines else ""))

    # Build all six variants
    # V0: patch only 0x4522 immediate 01->00
    make_variant(
        "v0_min",
        patch_ops=[
            ("site_4522_0B75", lambda buf, desc, log: patch_immediate01_to00(buf, 0x4522, desc, log)),
        ],
    )

    # V1: NOP MOVX at 0x4522
    make_variant(
        "v1_nop",
        patch_ops=[
            ("site_4522_0B75", lambda buf, desc, log: patch_movx_to_nop(buf, 0x4522, desc, log)),
        ],
    )

    # V2: patch two sites (0x4522 and 0x0AC4) imm 01->00
    make_variant(
        "v2_two",
        patch_ops=[
            ("site_4522_0B75", lambda buf, desc, log: patch_immediate01_to00(buf, 0x4522, desc, log)),
            ("site_0AC4_0B76", lambda buf, desc, log: patch_immediate01_to00(buf, 0x0AC4, desc, log)),
        ],
    )

    # V3: patch all four sites imm 01->00, no footer change
    make_variant(
        "v3_all4_noftr",
        patch_ops=[
            ("site_04D0_0B77", lambda buf, desc, log: patch_immediate01_to00(buf, 0x04D0, desc, log)),
            ("site_0AC4_0B76", lambda buf, desc, log: patch_immediate01_to00(buf, 0x0AC4, desc, log)),
            ("site_0AFE_0B77", lambda buf, desc, log: patch_immediate01_to00(buf, 0x0AFE, desc, log)),
            ("site_4522_0B75", lambda buf, desc, log: patch_immediate01_to00(buf, 0x4522, desc, log)),
        ],
    )

    # V4: patch all four, then compute 16-bit word-sum footer at 0x1FFE..0x1FFF (LE)
    make_variant(
        "v4_all4_wordsum",
        patch_ops=[
            ("site_04D0_0B77", lambda buf, desc, log: patch_immediate01_to00(buf, 0x04D0, desc, log)),
            ("site_0AC4_0B76", lambda buf, desc, log: patch_immediate01_to00(buf, 0x0AC4, desc, log)),
            ("site_0AFE_0B77", lambda buf, desc, log: patch_immediate01_to00(buf, 0x0AFE, desc, log)),
            ("site_4522_0B75", lambda buf, desc, log: patch_immediate01_to00(buf, 0x4522, desc, log)),
        ],
        write_footer=write_wordsum_footer_le,
        footer_desc="wordsum16_le footer written at 0x1FFE (LE)"
    )

    # V5: patch all four, then compute 8-bit byte-sum footer duplicated into both bytes
    make_variant(
        "v5_all4_bytesum",
        patch_ops=[
            ("site_04D0_0B77", lambda buf, desc, log: patch_immediate01_to00(buf, 0x04D0, desc, log)),
            ("site_0AC4_0B76", lambda buf, desc, log: patch_immediate01_to00(buf, 0x0AC4, desc, log)),
            ("site_0AFE_0B77", lambda buf, desc, log: patch_immediate01_to00(buf, 0x0AFE, desc, log)),
            ("site_4522_0B75", lambda buf, desc, log: patch_immediate01_to00(buf, 0x4522, desc, log)),
        ],
        write_footer=write_bytesum_footer_dup,
        footer_desc="bytesum8 dup footer written at 0x1FFE..0x1FFF"
    )

# -----------------------
# Main
# -----------------------

def main():
    if len(sys.argv) != 3:
        print(dedent(f"""\
            Usage: {Path(sys.argv[0]).name} <input.bin> <out_dir>

            Produces 6 variants with logs/diffs/hashes.
        """))
        sys.exit(1)

    in_path = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)

    baseline = read_firmware(in_path)
    build_variants(baseline, out_dir)

    print("[+] Done. Check outputs in:", out_dir)

if __name__ == "__main__":
    main()
