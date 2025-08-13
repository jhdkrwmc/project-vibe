# xrefs_callgraph_crc.py — IDA 9.x
# Build call xrefs to/from TARGET_NAME up to MAX_DEPTH.
# Writes: xrefs_to_<name>_d<depth>.json and xrefs_from_<name>_d<depth>.json

import idaapi, idautils, idc
import ida_funcs, ida_xref, ida_segment, ida_bytes, ida_name
import json, os, collections

TARGET_NAME = "crc32_combine64_0"
MAX_DEPTH   = 5

# --- helpers ---------------------------------------------------------------

def get_db_dir() -> str:
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

def func_start(ea: int) -> int | None:
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else None

def func_obj(ea: int):
    return ida_funcs.get_func(ea)

def func_name(start_ea: int) -> str:
    return idc.get_func_name(start_ea) or f"sub_{start_ea:X}"

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

def call_xref_type(t: int) -> bool:
    # 8051 calls are "code far/near" xrefs
    return t in (ida_xref.fl_CF, ida_xref.fl_CN)

# --- graph building --------------------------------------------------------

def iter_callers_of_func(fn) -> list[dict]:
    """All call-sites (code xrefs) that target anywhere inside fn."""
    out = []
    # iterate all items in the callee function, gather xrefs TO any ea inside it
    ea = fn.start_ea
    while ea < fn.end_ea:
        for xr in idautils.XrefsTo(ea, 0):
            if call_xref_type(xr.type):
                caller_f = func_obj(xr.frm)
                if caller_f:
                    out.append({
                        "site_ea": xr.frm,
                        "caller_start": caller_f.start_ea,
                        "callee_ea": ea,
                        "xref_type": int(xr.type),
                    })
        ea = idc.next_head(ea, fn.end_ea)
        if ea == idc.BADADDR or ea <= fn.start_ea:
            break
    return out

def iter_callees_of_func(fn) -> list[dict]:
    """All call-sites (code xrefs) that originate inside fn."""
    out = []
    for insn_ea in idautils.FuncItems(fn.start_ea):
        for xr in idautils.XrefsFrom(insn_ea, 0):
            if call_xref_type(xr.type):
                callee_start = func_start(xr.to)
                if callee_start:
                    out.append({
                        "site_ea": insn_ea,
                        "caller_start": fn.start_ea,
                        "callee_start": callee_start,
                        "xref_type": int(xr.type),
                    })
    return out

def bfs_callers(start_fn, max_depth):
    nodes = {}  # start_ea -> node
    edges = []  # {src, dst, site_ea, type, level}
    q = collections.deque()
    visited = set([start_fn.start_ea])
    q.append( (start_fn.start_ea, 0) )

    # register root
    nodes[start_fn.start_ea] = {
        "ea": f"0x{start_fn.start_ea:X}",
        "name": func_name(start_fn.start_ea),
        "segment": seg_name(start_fn.start_ea),
        "level": 0,
    }

    while q:
        cur, lvl = q.popleft()
        if lvl >= max_depth:
            continue
        fn = func_obj(cur)
        if not fn:
            continue
        for x in iter_callers_of_func(fn):
            caller = x["caller_start"]
            if caller not in nodes:
                nodes[caller] = {
                    "ea": f"0x{caller:X}",
                    "name": func_name(caller),
                    "segment": seg_name(caller),
                    "level": lvl+1,
                }
            edges.append({
                "src": f"0x{caller:X}",
                "dst": f"0x{cur:X}",
                "site_ea": f"0x{x['site_ea']:X}",
                "xref_type": x["xref_type"],
                "level": lvl+1,
            })
            if caller not in visited:
                visited.add(caller)
                q.append( (caller, lvl+1) )
    return {"root": f"0x{start_fn.start_ea:X}", "nodes": list(nodes.values()), "edges": edges, "direction": "to"}

def bfs_callees(start_fn, max_depth):
    nodes = {}
    edges = []
    q = collections.deque()
    visited = set([start_fn.start_ea])
    q.append( (start_fn.start_ea, 0) )

    nodes[start_fn.start_ea] = {
        "ea": f"0x{start_fn.start_ea:X}",
        "name": func_name(start_fn.start_ea),
        "segment": seg_name(start_fn.start_ea),
        "level": 0,
    }

    while q:
        cur, lvl = q.popleft()
        if lvl >= max_depth:
            continue
        fn = func_obj(cur)
        if not fn:
            continue
        for x in iter_callees_of_func(fn):
            callee = x["callee_start"]
            if callee not in nodes:
                nodes[callee] = {
                    "ea": f"0x{callee:X}",
                    "name": func_name(callee),
                    "segment": seg_name(callee),
                    "level": lvl+1,
                }
            edges.append({
                "src": f"0x{cur:X}",
                "dst": f"0x{callee:X}",
                "site_ea": f"0x{x['site_ea']:X}",
                "xref_type": x["xref_type"],
                "level": lvl+1,
            })
            if callee not in visited:
                visited.add(callee)
                q.append( (callee, lvl+1) )
    return {"root": f"0x{start_fn.start_ea:X}", "nodes": list(nodes.values()), "edges": edges, "direction": "from"}

# --- main ------------------------------------------------------------------

def main():
    name = TARGET_NAME
    target_ea = idc.get_name_ea_simple(name)
    if target_ea == idc.BADADDR:
        print(f"[!] Name '{name}' not found. Aborting.")
        return
    f = func_obj(target_ea)
    if not f:
        # If the name points into code but not at a function start, try the containing function.
        fstart = func_start(target_ea)
        if not fstart:
            print(f"[!] '{name}' (0x{target_ea:X}) is not inside a function. Aborting.")
            return
        f = func_obj(fstart)

    print(f"[=] Target: {name} @ 0x{f.start_ea:X}  depth={MAX_DEPTH}")

    graph_to   = bfs_callers(f, MAX_DEPTH)
    graph_from = bfs_callees(f, MAX_DEPTH)

    base = get_db_dir()
    out_to   = os.path.join(base, f"xrefs_to_{name}_d{MAX_DEPTH}.json")
    out_from = os.path.join(base, f"xrefs_from_{name}_d{MAX_DEPTH}.json")

    with open(out_to, "w", encoding="utf-8") as fp:
        json.dump(graph_to, fp, indent=2)
    with open(out_from, "w", encoding="utf-8") as fp:
        json.dump(graph_from, fp, indent=2)

    # also drop copies in the user IDA dir
    try:
        udir = idaapi.get_user_idadir()
        with open(os.path.join(udir, os.path.basename(out_to)), "w", encoding="utf-8") as fp:
            json.dump(graph_to, fp, indent=2)
        with open(os.path.join(udir, os.path.basename(out_from)), "w", encoding="utf-8") as fp:
            json.dump(graph_from, fp, indent=2)
    except Exception:
        pass

    print(f"[=] Wrote:\n  {out_to}\n  {out_from}")
    print(f"[=] Nodes(to/from): {len(graph_to['nodes'])}/{len(graph_from['nodes'])}")
    print(f"[=] Edges(to/from): {len(graph_to['edges'])}/{len(graph_from['edges'])}")

if __name__ == "__main__":
    main()
