# intel_crc_scan.py — IDA 9.x safe
# Scans for likely CRC/checksum routines in 8051 firmware.
# Writes: %IDADIR%/intel_crc_candidates.json

import idaapi, idautils, idc, json, os

def user_out(path):
    try:
        base = idaapi.get_user_idadir()
    except Exception:
        base = os.getcwd()
    return os.path.join(base, path)

OUTPUT_FILE = user_out("intel_crc_candidates.json")

def op(ea, n):
    try:
        s = idc.print_operand(ea, n)
        return (s or "").lower()
    except Exception:
        return ""

def back_edge(src, dst):
    # treat as a loop if it jumps backwards within a small window
    return (dst is not None) and (dst < src) and ((src - dst) < 0x800)

def scan_for_crc_candidates():
    candidates = []
    print("\n=== Scanning for CRC/Checksum candidates (8051) ===")

    for fva in idautils.Functions():
        f = idaapi.get_func(fva)
        if not f:
            continue

        has_movc = False     # table/code read
        has_loop = False     # back-edge
        has_cmp  = False     # compare then conditional branch
        cmp_ea   = None
        loop_hdr = None

        ea = f.start_ea
        while ea < f.end_ea:
            mnem = (idc.print_insn_mnem(ea) or "").lower()

            # 8051 table/code read: MOVC A,@A+DPTR or MOVC A,@A+PC
            if mnem == "movc" and op(ea, 0) == "a" and ("@a+dptr" in op(ea, 1) or "@a+pc" in op(ea, 1)):
                has_movc = True

            # back-edge loop: any near jump/cond jump going backwards
            if mnem in ("sjmp","ajmp","ljmp","jz","jnz","jc","jnc","jb","jnb","jbc","djnz"):
                dst = idc.get_operand_value(ea, 0)
                if dst and back_edge(ea, dst):
                    has_loop = True
                    loop_hdr = dst

            # compare pattern: CJNE …  then a conditional right after,
            # or SUBB/CLR flags compare followed by conditional
            if mnem in ("cjne","subb"):
                next_ea = idc.next_head(ea, f.end_ea)
                nm = (idc.print_insn_mnem(next_ea) or "").lower()
                if nm in ("jz","jnz","jc","jnc","sjmp"):
                    has_cmp = True
                    cmp_ea = ea

            ea = idc.next_head(ea, f.end_ea)

        if has_movc and (has_loop or has_cmp):
            name = idc.get_func_name(fva) or f"sub_{fva:X}"
            print(f"[+] Candidate: {name} @ 0x{fva:X}  movc={has_movc} loop={has_loop} cmp={has_cmp}")
            candidates.append({
                "ea": f"0x{fva:X}",
                "name": name,
                "has_movc": has_movc,
                "has_loop": has_loop,
                "has_cmp": has_cmp,
                "cmp_ea": f"0x{cmp_ea:X}" if cmp_ea else None,
                "loop_hdr": f"0x{loop_hdr:X}" if loop_hdr else None
            })

    return candidates

def main():
    print("DB:", idaapi.get_input_file_path())
    cands = scan_for_crc_candidates()
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(cands, f, indent=2)
    print(f"[=] Wrote {OUTPUT_FILE} ({len(cands)} candidates)")

    # also drop a copy next to the DB for convenience
    try:
        dbdir = os.path.dirname(idaapi.get_database_filename())
        p2 = os.path.join(dbdir, "intel_crc_candidates.json")
        with open(p2, "w", encoding="utf-8") as f:
            json.dump(cands, f, indent=2)
        print(f"[=] Copied to: {p2}")
    except Exception:
        pass

if __name__ == "__main__":
    main()
