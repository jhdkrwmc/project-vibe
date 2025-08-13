# names_to_json.py — dump all named EAs to JSON (IDA 9.x safe, 8051-friendly)
import idaapi, idautils, idc
import ida_funcs, ida_bytes, ida_segment, ida_name, ida_nalt
import json, os

def get_db_dir() -> str:
    # robust path to the current DB folder
    try:
        p = idaapi.get_path(idaapi.PATH_TYPE_IDB)
        if p:
            return os.path.dirname(p)
    except Exception:
        pass
    try:
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

def seg_name(ea: int) -> str:
    s = ida_segment.getseg(ea)
    try:
        return ida_segment.get_segm_name(s) if s else ""
    except Exception:
        return s.name if s else ""

def is_code_ea(ea: int) -> bool:
    try:
        return ida_bytes.is_code(ida_bytes.get_full_flags(ea))
    except Exception:
        return idaapi.is_code(idaapi.get_flags(ea))

def demangle(name: str) -> str | None:
    try:
        dn = ida_name.demangle_name(name, ida_name.MNG_NODEFINIT)
        if dn and dn != name:
            return dn
    except Exception:
        pass
    return None

def main():
    items = []
    for ea, nm in idautils.Names():  # all global names (like the Names window)
        short = ida_name.get_short_name(ea) or nm or ""
        dn = demangle(short)

        f = ida_funcs.get_func(ea)
        typ = "func" if f else ("code" if is_code_ea(ea) else "data")

        entry = {
            "ea": f"0x{ea:X}",
            "name": short,
            "demangled": dn,
            "segment": seg_name(ea),
            "type": typ,
        }
        if f:
            entry["end_ea"] = f"0x{f.end_ea:X}"
            entry["size"]   = f.end_ea - f.start_ea

        items.append((ea, entry))

    # sort by address and strip temp key
    items.sort(key=lambda t: t[0])
    out_list = [e for _, e in items]

    # write outputs
    user_out = os.path.join(idaapi.get_user_idadir(), "names_full.json")
    with open(user_out, "w", encoding="utf-8") as fp:
        json.dump(out_list, fp, indent=2, ensure_ascii=False)

    proj_out = os.path.join(get_db_dir(), "names_full.json")
    if proj_out != user_out:
        with open(proj_out, "w", encoding="utf-8") as fp:
            json.dump(out_list, fp, indent=2, ensure_ascii=False)

    print(f"[=] names_full.json written: {len(out_list)} entries")
    print(f"    user dir : {user_out}")
    print(f"    project  : {proj_out}")

if __name__ == "__main__":
    main()
