# search_integrity_checks.py — IDA 9.x safe, 8051-focused
# Finds likely integrity checks: MOVC/MOVX reads + compare + conditional branch.
import idaapi, idautils, idc, json, os

def get_db_dir() -> str:
    # Robust DB directory (IDA 8/9 compatible)
    try:
        p = idaapi.get_path(idaapi.PATH_TYPE_IDB)
        if p:
            return os.path.dirname(p)
    except Exception:
        pass
    try:
        import ida_nalt
        p = ida_nalt.get_input_file_path()
        if p:
            return os.path.dirname(p)
    except Exception:
        pass
    try:
        p = idaapi.get_input_file_path()
        if p:
            return os.path.dirname(p)
    except Exception:
        pass
    return os.getcwd()

def disasm(ea: int) -> str:
    s = idc.generate_disasm_line(ea, 0) or idc.GetDisasm(ea)
    return s or ""

def is_code_ea(ea: int) -> bool:
    try:
        import ida_bytes
        return ida_bytes.is_code(ida_bytes.get_full_flags(ea))
    except Exception:
        return idaapi.is_code(idaapi.get_flags(ea))

def is_potential_integrity_check(instructions):
    if len(instructions) < 3:
        return False
    has_mem = False
    has_cmp = False
    has_cbr = False
    for inst in instructions:
        ea = inst['ea']
        mnem = (idc.print_insn_mnem(ea) or "").lower()
        txt  = inst['disasm'].lower()
        # memory reads
        if mnem in ('mov', 'movx', 'movc'):
            if '@' in txt or '+dptr' in txt or '+pc' in txt or '[' in txt:
                has_mem = True
        # comparisons (8051)
        elif mnem in ('cjne','subb'):
            has_cmp = True
        # conditional branches (8051)
        elif mnem in ('jz','jnz','jc','jnc','jb','jnb','jbc','djnz','sjmp'):
            has_cbr = True
    return has_mem and (has_cmp or has_cbr)

def iter_code_ranges():
    # prefer actual code segments over hard-coded ranges
    ranges = []
    qty = idaapi.get_segm_qty()
    for i in range(qty):
        s = idaapi.getnseg(i)
        if s and s.type == idaapi.SEG_CODE:
            ranges.append((s.start_ea, s.end_ea, f"seg_{i:02d}"))
    if not ranges:
        # fallback to full 64K window if segments aren’t present
        ranges = [(0x0000, 0x10000, "flat_64k")]
    return ranges

def search_memory_regions():
    print("\n=== Searching Memory Regions for Integrity Checks ===")
    results = []
    for start, end, desc in iter_code_ranges():
        print(f"\nSearching {desc} (0x{start:04X}-0x{end:04X})...")
        ea = start
        while ea < end:
            if is_code_ea(ea):
                # pull next 5 instructions window
                instructions = []
                cur = ea
                for _ in range(5):
                    if cur >= end:
                        break
                    instructions.append({'ea': cur, 'disasm': disasm(cur)})
                    nxt = idc.next_head(cur, end)
                    if nxt == idc.BADADDR or nxt <= cur:
                        break
                    cur = nxt
                if is_potential_integrity_check(instructions):
                    func_name = idc.get_func_name(ea) or f"sub_{ea:X}"
                    print(f"[?] Potential integrity check @ 0x{ea:04X} ({func_name})")
                    results.append({
                        'ea': f"0x{ea:X}",
                        'name': func_name,
                        'instructions': [{'ea': f"0x{i['ea']:X}", 'disasm': i['disasm']} for i in instructions]
                    })
            # stride safely to next head to stay aligned on code
            nxt = idc.next_head(ea, end)
            ea = nxt if nxt != idc.BADADDR and nxt > ea else ea + 2
    return results

def main():
    print("=== Integrity Check Scanner for 8051 ===")
    try:
        db = idaapi.get_input_file_path()
    except Exception:
        db = "<unknown>"
    print(f"Database input: {db}")

    results = search_memory_regions()

    # Save to user IDA dir
    out_user = os.path.join(idaapi.get_user_idadir(), "integrity_checks.json")
    with open(out_user, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f"[=] Saved: {out_user}")

    # Also save next to the DB
    out_proj = os.path.join(get_db_dir(), "integrity_checks.json")
    if out_proj != out_user:
        with open(out_proj, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        print(f"[=] Copied: {out_proj}")

    print(f"[=] Found {len(results)} potential sites")

if __name__ == "__main__":
    main()
