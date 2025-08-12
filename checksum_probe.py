import ida_bytes, time, os, json

START = 0x0000
END   = 0x1FFD  # inclusive; footer at 0x1FFE..0x1FFF (LE)

def main():
    data = ida_bytes.get_bytes(START, END - START + 1)
    if data is None:
        print("ERROR: cannot read ROM range 0x%04X..0x%04X" % (START, END))
        return
    s = sum(data) & 0xFFFF
    b0 = ida_bytes.get_byte(0x1FFE)
    b1 = ida_bytes.get_byte(0x1FFF)
    footer = (b1 << 8) | b0
    check  = (s + footer) & 0xFFFF
    rec    = (-s) & 0xFFFF

    print("SUM16=0x%04X" % s)
    print("FOOTER_LE16=0x%04X (bytes %02X %02X)" % (footer, b0, b1))
    print("CHECK=(sum+footer)&0xFFFF=0x%04X (0 means OK)" % check)
    print("RECOMMENDED_FOOTER_LE16=0x%04X" % rec)

    base = r"C:\Users\arnax\Desktop\project-vibe"
    os.makedirs(os.path.join(base, "exports"), exist_ok=True)
    out = os.path.join(base, "exports", f"checksum_probe_{int(time.time())}.json")
    with open(out, "w") as f:
        json.dump(
            {"sum16": s, "footer": footer, "check": check, "recommended_footer": rec},
            f, indent=2
        )
    print("WROTE:"+out)

if __name__ == "__main__":
    main()
