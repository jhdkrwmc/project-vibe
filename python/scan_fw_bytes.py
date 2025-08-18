from pathlib import Path

def find_all(data: bytes, needle: bytes) -> list[int]:
    out = []
    i = 0
    while True:
        j = data.find(needle, i)
        if j < 0:
            return out
        out.append(j)
        i = j + 1

def main() -> None:
    p = Path("firmware_backup_base.bin")
    if not p.exists():
        p = Path("firmware/firmware_backup_base.bin")
    data = p.read_bytes()
    print("Loaded:", p, len(data))

    # Scan for DPTR loads to 0xE00..0xEFF: opcode 90 0E xx
    dptr_hits = []
    for off in range(0, len(data) - 2):
        if data[off] == 0x90 and data[off + 1] == 0x0E:
            dptr_hits.append(off)

    # Specific ones of interest
    e24_hits = find_all(data, bytes([0x90, 0x0E, 0x24]))
    e27_hits = find_all(data, bytes([0x90, 0x0E, 0x27]))

    # Candidate default triples seen at runtime
    tri1 = find_all(data, bytes([0x21, 0xE0, 0x94]))
    tri2 = find_all(data, bytes([0xFF, 0xD0, 0xDC]))

    print("DPTR 0xE00.. occurrences:", len(dptr_hits))
    print("First 50 DPTR hits:", [hex(x) for x in dptr_hits[:50]])
    print("e24 hits:", [hex(x) for x in e24_hits])
    print("e27 hits:", [hex(x) for x in e27_hits])
    print("tri1 21 E0 94 count:", len(tri1), "examples:", [hex(x) for x in tri1[:10]])
    print("tri2 FF D0 DC count:", len(tri2), "examples:", [hex(x) for x in tri2[:10]])

    # Dump small windows around each e24 hit
    for off in e24_hits:
        ctx = data[max(0, off - 16) : off + 64]
        print("\nContext @", hex(off), ctx.hex(" "))

if __name__ == "__main__":
    main()


