from pathlib import Path

# Configuration
INPUT_PATH = Path("firmware_backup_base.bin")
OUTPUT_PATH = Path("firmware_boot_osd_off.bin")

# Injection site and bytes
PATCH_ADDR = 0x0A516  # Expected NOP window (4 bytes)
PATCH_BYTES = bytes([0x12, 0xBB, 0x73])  # 8051: LCALL 0xBB73

# Footer (16-bit checksum word, little-endian)
FOOTER_LO = 0x1FFE
FOOTER_HI = 0x1FFF

def sum16_words_le(buf: bytes) -> int:
    """Compute 16-bit word-sum over entire buffer (little-endian words)."""
    if len(buf) % 2 != 0:
        raise ValueError("Firmware length must be even for 16-bit word sum")
    total = 0
    for i in range(0, len(buf), 2):
        word = buf[i] | (buf[i + 1] << 8)
        total = (total + word) & 0xFFFF
    return total


def main() -> None:
    if not INPUT_PATH.exists():
        raise FileNotFoundError(f"Input firmware not found: {INPUT_PATH}")

    data = bytearray(INPUT_PATH.read_bytes())
    size = len(data)

    # Basic sanity
    if size < max(PATCH_ADDR + len(PATCH_BYTES), FOOTER_HI + 1):
        raise ValueError(
            f"Firmware too small: {size} bytes; needs >= {max(PATCH_ADDR + len(PATCH_BYTES), FOOTER_HI + 1)}"
        )

    # Snapshot original 4 bytes at injection site
    orig_window = bytes(data[PATCH_ADDR : PATCH_ADDR + 4])

    # Apply injection (3 bytes)
    data[PATCH_ADDR : PATCH_ADDR + 3] = PATCH_BYTES

    # Zero footer before recomputing the word-sum
    data[FOOTER_LO] = 0x00
    data[FOOTER_HI] = 0x00

    # Compute 16-bit little-endian word-sum over full image
    s = sum16_words_le(data)
    fix = (-s) & 0xFFFF

    # Write checksum footer (little-endian)
    data[FOOTER_LO] = fix & 0xFF
    data[FOOTER_HI] = (fix >> 8) & 0xFF

    # Verify
    verify_sum = sum16_words_le(data)
    if verify_sum != 0:
        raise RuntimeError(f"Checksum verification failed: sum16=0x{verify_sum:04X}")

    # Save
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_bytes(data)

    # Minimal, high-signal output
    print("Patched firmware written:", OUTPUT_PATH)
    print("Injection @ 0x%05X: %s -> %s" % (
        PATCH_ADDR,
        orig_window.hex(" "),
        bytes(data[PATCH_ADDR : PATCH_ADDR + 4]).hex(" ")
    ))
    print("Footer @ 0x%05X..0x%05X = %02X %02X (sum16 -> 0)" % (
        FOOTER_LO,
        FOOTER_HI,
        data[FOOTER_LO],
        data[FOOTER_HI],
    ))


if __name__ == "__main__":
    main()


