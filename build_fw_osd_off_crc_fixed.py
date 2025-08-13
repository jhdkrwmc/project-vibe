import os
import struct
from pathlib import Path

IN_PATH = Path("firmware_backup - Copy (4).bin")
OUT_DIR = Path("out")
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Outputs
OUT_BIN_CRCFIX = OUT_DIR / "fw_osd_off_crc_fixed.bin"
OUT_BIN_NOCK = OUT_DIR / "fw_osd_off.bin"
OUT_BIN_BYPASS = OUT_DIR / "fw_osd_off_bypass.bin"
OUT_BIN_STAGE2 = OUT_DIR / "fw_stage2_bypass_only.bin"
OUT_BIN_STAGE2_CRC = OUT_DIR / "fw_stage2_bypass_only_crc_fixed.bin"
OUT_BIN_LATECLR = OUT_DIR / "fw_late_clear_crc_fixed.bin"
OUT_BIN_V7_EARLY = OUT_DIR / "fw_v7_early_bypass_crc_fixed.bin"

OUT_SUM = OUT_DIR / "fw_osd_off_crc_fixed.sum.txt"
OUT_SUM_NOCK = OUT_DIR / "fw_osd_off.sum.txt"
OUT_SUM_STAGE2 = OUT_DIR / "fw_stage2_bypass_only.sum.txt"
OUT_SUM_V7_EARLY = OUT_DIR / "fw_v7_early_bypass_crc_fixed.sum.txt"
OUT_DIFF = OUT_DIR / "fw_osd_off_crc_fixed.diff.txt"
OUT_DIFF_BYPASS = OUT_DIR / "fw_osd_off_bypass.diff.txt"
OUT_DIFF_STAGE2 = OUT_DIR / "fw_stage2_bypass_only.diff.txt"
OUT_DIFF_LATECLR = OUT_DIR / "fw_late_clear_crc_fixed.diff.txt"
OUT_DIFF_V7_EARLY = OUT_DIR / "fw_v7_early_bypass_crc_fixed.diff.txt"

OUT_TAIL = OUT_DIR / "logs"
OUT_TAIL.mkdir(parents=True, exist_ok=True)
OUT_TAIL_FILE = OUT_TAIL / "ends-of-image.txt"

# OSD patches: offsets -> expected original -> new
PATCHES_OSD = [
    (0x04D4, 0x01, 0x00),  # 0x04D0: 90 0B 77 74 01 F0 → flip 01→00
    (0x0AC8, 0x01, 0x00),  # 0x0AC4: 90 0B 76 74 01 F0 → flip 01→00
    (0x0B02, 0x01, 0x00),  # 0x0AFE: 90 0B 77 74 01 F0 → flip 01→00
    (0x4526, 0x01, 0x00),  # 0x4522: 90 0B 75 74 01 F0 → flip 01→00
]

# Runtime integrity branch flip (V6_BYPASS_ONLY): address -> (expected_old, new_value)
PATCHES_BYPASS = [
    (0x01D0, 0x70, 0x70),  # keep opcode JNZ, displacement below
    (0x01D1, 0x03, 0x00),  # JNZ +3 -> +0
    (0x01D6, 0x60, 0x60),  # keep opcode JZ
    (0x01D7, 0x3C, 0x00),  # JZ +0x3C -> +0
]

# Stage-2 bypass-only flips (diagnostic; do not change OSD or footer)
# 0x244: CJNE A,#01 -> #00; 0x288: XRL A,#84 -> #00
PATCHES_STAGE2 = [
    (0x0244, 0x01, 0x00),
    (0x0288, 0x84, 0x00),
]

# Late-clear variant: do not touch init (0x4522) or 0x0AC4 (0x0B76)
# Redirect later OSD writes (0x04D0, 0x0AFE) to clear 0x0B75 with 0x00
# 0x04D2: 0x77 -> 0x75 ; 0x04D4: 0x01 -> 0x00
# 0x0B00? Actually 0x0AFE+2: 0x77 -> 0x75 ; 0x0AFE+4: 0x01 -> 0x00
PATCHES_LATECLR = [
    (0x04D2, 0x77, 0x75),
    (0x04D4, 0x01, 0x00),
    (0x0B00, 0x77, 0x75),
    (0x0B02, 0x01, 0x00),
]

# V7_EARLY_BYPASS: Early compare site conditional flips
# Target early integrity checks around 0x023E, 0x025A, 0x0283
PATCHES_V7_EARLY = [
    (0x0245, 0x08, 0x00),  # 0x023E: CJNE A,#01,+8 -> +0 (no-op)
    (0x025F, 0x06, 0x00),  # 0x025A: CJNE A,#84,+6 -> +0 (no-op)
    (0x0289, 0x03, 0x00),  # 0x0283: JZ +3 -> +0 (no-op)
]

SIZE_EXPECTED = 0x20000
CHK_POS = 0x1FFE  # little-endian uint16 checksum


def read_firmware(path: Path) -> bytearray:
    if not path.exists():
        raise FileNotFoundError(f"Input firmware not found: {path}")
    data = bytearray(path.read_bytes())
    if len(data) != SIZE_EXPECTED:
        raise ValueError(f"Unexpected firmware size: {len(data):#x} (expected {SIZE_EXPECTED:#x})")
    return data


def apply_patches(data: bytearray, patches) -> list[str]:
    diffs = []
    for off, want_old, new_val in patches:
        old = data[off]
        if old != want_old:
            diffs.append(f"SKIP @ {off:#06x}: expected {want_old:02X} but found {old:02X}")
            continue
        data[off] = new_val
        diffs.append(f"OK   @ {off:#06x}: {want_old:02X} -> {new_val:02X}")
    return diffs


def compute_checksum_bytesum(data: bytes) -> tuple[int, int]:
    end_excl = 0x1FFE
    s = 0
    for i in range(0, end_excl):
        s = (s + data[i]) & 0xFFFF
    comp = (-s) & 0xFFFF
    return s, comp


def write_checksum(data: bytearray, checksum: int) -> None:
    data[CHK_POS] = checksum & 0xFF
    data[CHK_POS + 1] = (checksum >> 8) & 0xFF


def sum_full_image_bytes(data: bytes) -> int:
    s = 0
    for b in data:
        s = (s + b) & 0xFFFF
    return s


def sum_full_image_words_le(data: bytes) -> int:
    s = 0
    for i in range(0, len(data), 2):
        lo = data[i]
        hi = data[i + 1] if i + 1 < len(data) else 0
        s = (s + ((hi << 8) | lo)) & 0xFFFF
    return s


def write_tail_dump(data: bytes, path: Path) -> None:
    tail = data[-64:]
    rows = []
    for i in range(0, len(tail), 16):
        chunk = tail[i:i+16]
        rows.append(" ".join(f"{b:02X}" for b in chunk))
    path.write_text("\n".join(rows))


def main() -> None:
    base = read_firmware(IN_PATH)

    # Variant A: OSD only, footer untouched
    data_nock = bytearray(base)
    diffs_nock = apply_patches(data_nock, PATCHES_OSD)
    OUT_BIN_NOCK.write_bytes(data_nock)

    # Variant B: OSD + checksum write
    data_crcfix = bytearray(base)
    diffs_crcfix = apply_patches(data_crcfix, PATCHES_OSD)
    partial, comp = compute_checksum_bytesum(data_crcfix)
    write_checksum(data_crcfix, comp)
    final_sum_bytes = sum_full_image_bytes(data_crcfix)
    final_sum_words = sum_full_image_words_le(data_crcfix)
    OUT_BIN_CRCFIX.write_bytes(data_crcfix)

    # Variant C: OSD + runtime bypass (footer untouched)
    data_bypass = bytearray(base)
    diffs_bypass = apply_patches(data_bypass, PATCHES_OSD)
    diffs_bypass += apply_patches(data_bypass, PATCHES_BYPASS)
    OUT_BIN_BYPASS.write_bytes(data_bypass)

    # Variant D: Stage-2 bypass-only (no OSD changes)
    data_stage2 = bytearray(base)
    diffs_stage2 = apply_patches(data_stage2, PATCHES_STAGE2)
    OUT_BIN_STAGE2.write_bytes(data_stage2)
    # Also provide checksum-fixed copy
    data_stage2_crc = bytearray(data_stage2)
    part_s2, comp_s2 = compute_checksum_bytesum(data_stage2_crc)
    write_checksum(data_stage2_crc, comp_s2)
    OUT_BIN_STAGE2_CRC.write_bytes(data_stage2_crc)

    # Variant E: Late-clear (redirect later writes to clear 0x0B75), checksum-fixed
    data_late = bytearray(base)
    diffs_late = apply_patches(data_late, PATCHES_LATECLR)
    part_late, comp_late = compute_checksum_bytesum(data_late)
    write_checksum(data_late, comp_late)
    OUT_BIN_LATECLR.write_bytes(data_late)

    # Variant F: Early bypass (V7_EARLY_BYPASS)
    data_v7_early = bytearray(base)
    diffs_v7_early = apply_patches(data_v7_early, PATCHES_OSD)
    diffs_v7_early += apply_patches(data_v7_early, PATCHES_V7_EARLY)
    # Apply checksum fix
    part_v7, comp_v7 = compute_checksum_bytesum(data_v7_early)
    write_checksum(data_v7_early, comp_v7)
    OUT_BIN_V7_EARLY.write_bytes(data_v7_early)

    # Write reports
    OUT_DIFF.write_text("\n".join(diffs_crcfix) + "\n")
    OUT_DIFF_BYPASS.write_text("\n".join(diffs_bypass) + "\n")
    OUT_DIFF_STAGE2.write_text("\n".join(diffs_stage2) + "\n")
    OUT_DIFF_LATECLR.write_text("\n".join(diffs_late) + "\n")
    OUT_DIFF_V7_EARLY.write_text("\n".join(diffs_v7_early) + "\n")

    OUT_SUM.write_text(
        "\n".join([
            f"Partial byte-sum [0x0000..0x1FFD]: {partial:#06x}",
            f"Computed checksum (two's complement): {comp:#06x}",
            f"Checksum bytes @ 0x1FFE..0x1FFF (LE): {comp & 0xFF:02X} {(comp >> 8) & 0xFF:02X}",
            f"Final 16-bit sum (byte-wise) of entire image: {final_sum_bytes:#06x}",
            f"Final 16-bit sum (word-wise LE) of entire image: {final_sum_words:#06x}",
            "Verification (byte-wise): PASS" if final_sum_bytes == 0 else "Verification (byte-wise): FAIL",
        ]) + "\n"
    )

    s_bytes_nock = sum_full_image_bytes(data_nock)
    s_words_nock = sum_full_image_words_le(data_nock)
    OUT_SUM_NOCK.write_text(
        "\n".join([
            "Footer unchanged (no checksum write).",
            f"Final 16-bit sum (byte-wise) of entire image: {s_bytes_nock:#06x}",
            f"Final 16-bit sum (word-wise LE) of entire image: {s_words_nock:#06x}",
            f"Tail @ 0x1FFE..0x1FFF: {data_nock[0x1FFE]:02X} {data_nock[0x1FFF]:02X}",
        ]) + "\n"
    )

    # Stage-2 sums
    s2_bytes = sum_full_image_bytes(data_stage2)
    s2_words = sum_full_image_words_le(data_stage2)
    OUT_SUM_STAGE2.write_text(
        "\n".join([
            f"Stage2 (no footer change) byte-sum: {s2_bytes:#06x}",
            f"Stage2 word-sum: {s2_words:#06x}",
        ]) + "\n"
    )

    # Tail dump from the no-checksum variant (original tail state after OSD edits)
    write_tail_dump(data_nock, OUT_TAIL_FILE)

    print(f"Wrote:\n  {OUT_BIN_NOCK}\n  {OUT_BIN_CRCFIX}\n  {OUT_BIN_BYPASS}\n  {OUT_BIN_STAGE2}\n  {OUT_BIN_STAGE2_CRC}\n  {OUT_BIN_LATECLR}\n  {OUT_BIN_V7_EARLY}")
    print(f"Diffs saved to: {OUT_DIFF}, {OUT_DIFF_BYPASS}, {OUT_DIFF_STAGE2}, {OUT_DIFF_LATECLR}, {OUT_DIFF_V7_EARLY}")
    print(f"Checksum reports saved to: {OUT_SUM}, {OUT_SUM_NOCK}, {OUT_SUM_STAGE2}, {OUT_SUM_V7_EARLY}")
    print(f"Tail dump saved to {OUT_TAIL_FILE}")


if __name__ == "__main__":
    main()
