from pathlib import Path
import argparse

# Input/output (root-level files)
DEFAULT_INPUT = Path("firmware_backup_base.bin")
DEFAULT_OUTPUT = Path("firmware_boot_osd_stub.bin")

# Injection site: replace with LJMP to code cave
INJECT_ADDR = 0x0A516  # expected 4x NOPs
RETURN_ADDR = 0x0A519   # next instruction after injection site

# Code cave for stub (ensure enough 0x00 padding exists here)
CAVE_ADDR = 0x00BFA8

# Footer addresses (if you choose to fix)
FOOTER_LO = 0x1FFE
FOOTER_HI = 0x1FFF


def sum16_words_le(buf: bytes) -> int:
    if len(buf) % 2 != 0:
        raise ValueError("Firmware length must be even for 16-bit word sum")
    total = 0
    for i in range(0, len(buf), 2):
        total = (total + (buf[i] | (buf[i + 1] << 8))) & 0xFFFF
    return total


def build_stub(return_addr: int) -> bytes:
    # 8051 stub:
    # push PSW, ACC, DPL, DPH, B
    code = bytearray()
    code += bytes([0xC0, 0xD0])  # PUSH PSW
    code += bytes([0xC0, 0xE0])  # PUSH ACC
    code += bytes([0xC0, 0x82])  # PUSH DPL
    code += bytes([0xC0, 0x83])  # PUSH DPH
    code += bytes([0xC0, 0xF0])  # PUSH B

    # MOV DPTR,#0x0E24
    code += bytes([0x90, 0x0E, 0x24])
    # MOV A,#0x00
    code += bytes([0x74, 0x00])
    # Clear 0xE24..0xE27
    code += bytes([0xF0, 0xA3])  # MOVX @DPTR,A ; INC DPTR
    code += bytes([0xF0, 0xA3])
    code += bytes([0xF0, 0xA3])
    code += bytes([0xF0])

    # pop B, DPH, DPL, ACC, PSW
    code += bytes([0xD0, 0xF0])  # POP B
    code += bytes([0xD0, 0x83])  # POP DPH
    code += bytes([0xD0, 0x82])  # POP DPL
    code += bytes([0xD0, 0xE0])  # POP ACC
    code += bytes([0xD0, 0xD0])  # POP PSW

    # LJMP return_addr
    code += bytes([0x02, (return_addr >> 8) & 0xFF, return_addr & 0xFF])
    return bytes(code)


def main() -> None:
    parser = argparse.ArgumentParser(description="Inject OSD-off stub into firmware")
    parser.add_argument("-i", "--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--fix-footer", action="store_true", help="Recalculate 16-bit LE word-sum and write footer")
    args = parser.parse_args()

    data = bytearray(args.input.read_bytes())

    # Sanity: injection window
    window = bytes(data[INJECT_ADDR : INJECT_ADDR + 4])
    # Prepare stub
    stub = build_stub(RETURN_ADDR)

    # Write stub at code cave
    data[CAVE_ADDR : CAVE_ADDR + len(stub)] = stub

    # Overwrite injection site with LJMP cave
    data[INJECT_ADDR : INJECT_ADDR + 3] = bytes([0x02, (CAVE_ADDR >> 8) & 0xFF, CAVE_ADDR & 0xFF])

    # Optionally fix footer
    if args.fix_footer:
        data[FOOTER_LO] = 0x00
        data[FOOTER_HI] = 0x00
        s = sum16_words_le(data)
        fix = (-s) & 0xFFFF
        data[FOOTER_LO] = fix & 0xFF
        data[FOOTER_HI] = (fix >> 8) & 0xFF

    # Save
    args.output.write_bytes(data)

    # Print brief info
    after = bytes(data[INJECT_ADDR : INJECT_ADDR + 4])
    footer = (data[FOOTER_LO], data[FOOTER_HI])
    print("Patched:", args.output)
    print("Inject @ 0x%05X: %s -> %s" % (INJECT_ADDR, window.hex(" "), after.hex(" ")))
    print("Stub @ 0x%05X (%d bytes)" % (CAVE_ADDR, len(stub)))
    s = sum16_words_le(data)
    print("Sum16(LE words)=0x%04X, footer=%02X %02X%s" % (s, footer[0], footer[1], " (fixed)" if args.fix_footer else " (unchanged)"))


if __name__ == "__main__":
    main()


