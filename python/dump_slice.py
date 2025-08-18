import sys
from pathlib import Path

def main():
    if len(sys.argv) < 4:
        print("Usage: dump_slice.py <bin> <start_hex> <end_hex>")
        sys.exit(1)
    p = Path(sys.argv[1])
    start = int(sys.argv[2], 16)
    end = int(sys.argv[3], 16)
    data = p.read_bytes()
    if start < 0 or end > len(data) or start >= end:
        print("Invalid range")
        sys.exit(2)
    chunk = data[start:end]
    # print address-tagged hex, 16 bytes per line
    base = start
    for i in range(0, len(chunk), 16):
        row = chunk[i:i+16]
        print(f"0x{base+i:05X}: {row.hex(' ')}")

if __name__ == "__main__":
    main()



