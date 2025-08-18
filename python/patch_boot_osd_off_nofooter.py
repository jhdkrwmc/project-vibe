from pathlib import Path

# Configuration (root-level files)
INPUT_PATH = Path("firmware_backup_base.bin")
OUTPUT_PATH = Path("firmware_boot_osd_off_nofooter.bin")

# Injection site and bytes
PATCH_ADDR = 0x0A516  # Expected NOP window (4 bytes)
PATCH_BYTES = bytes([0x12, 0xBB, 0x73])  # 8051: LCALL 0xBB73

# Footer (information only; do not modify)
FOOTER_LO = 0x1FFE
FOOTER_HI = 0x1FFF


def sum16_words_le(buf: bytes) -> int:
    if len(buf) % 2 != 0:
        raise ValueError("Firmware length must be even for 16-bit word sum")
    total = 0
    for i in range(0, len(buf), 2):
        total = (total + (buf[i] | (buf[i + 1] << 8))) & 0xFFFF
    return total


def main() -> None:
    if not INPUT_PATH.exists():
        raise FileNotFoundError(f"Input firmware not found: {INPUT_PATH}")

    data = bytearray(INPUT_PATH.read_bytes())

    # Snapshot original window and footer
    orig_window = bytes(data[PATCH_ADDR : PATCH_ADDR + 4])
    orig_footer = (data[FOOTER_LO], data[FOOTER_HI])
    orig_sum = sum16_words_le(data)

    # Apply injection only
    data[PATCH_ADDR : PATCH_ADDR + 3] = PATCH_BYTES

    # Keep footer intact
    data[FOOTER_LO] = orig_footer[0]
    data[FOOTER_HI] = orig_footer[1]

    new_sum = sum16_words_le(data)

    OUTPUT_PATH.write_bytes(data)

    print("Patched firmware written:", OUTPUT_PATH)
    print("Injection @ 0x%05X: %s -> %s" % (
        PATCH_ADDR,
        orig_window.hex(" "),
        bytes(data[PATCH_ADDR : PATCH_ADDR + 4]).hex(" ")
    ))
    print("Footer (unchanged) @ 0x%05X..0x%05X = %02X %02X" % (
        FOOTER_LO, FOOTER_HI, data[FOOTER_LO], data[FOOTER_HI]
    ))
    print("Sum16 (LE words): before=0x%04X after=0x%04X" % (orig_sum, new_sum))


if __name__ == "__main__":
    main()


