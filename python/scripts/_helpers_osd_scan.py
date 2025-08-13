# _helpers_osd_scan.py (writes to project dir)
import idaapi, ida_bytes, ida_funcs, ida_kernwin, idautils, idc, os, json

OUTDIR = r"C:\Users\arnax\Desktop\project-vibe\intel"
os.makedirs(OUTDIR, exist_ok=True)
rows=[]

def ctx(ea,n=32):
    b=ida_bytes.get_bytes(ea,n) or b""
    return " ".join(f"{x:02X}" for x in b)

def file_off(ea):
    off = ida_bytes.get_fileregion_offset(ea)
    return f"0x{off:X}" if (off is not None and off>=0) else "n/a"

def reachable_from_reset(tgt, maxd=6):
    seen=set([tgt]); cur=[tgt]; d=0
    while cur and d<maxd:
        nxt=[]
        for ea in cur:
            for caller in idautils.CodeRefsTo(ea, True):
                if caller not in seen:
                    seen.add(caller)
                    nxt.append(caller)
        d+=1; cur=nxt
    return any(ea==0x0 for ea in seen)

def scan():
    inf = idaapi.get_inf_structure()
    start, end = inf.min_ea, inf.max_ea
    ea = start
    
    while True:
        ea = ida_bytes.find_binary(ea, end, "90 0B ?? 74 01 F0", 16, ida_bytes.SEARCH_DOWN)
        if ea == idaapi.BADADDR:
            break
            
        bb = ida_bytes.get_bytes(ea, 6) or b""
        if len(bb) == 6 and bb[2] in (0x75, 0x76, 0x77):
            rows.append({
                "ea": f"0x{ea:X}",
                "file_off": file_off(ea),
                "target": f"0x0B{bb[2]:02X}",
                "bytes32": ctx(ea, 32),
                "fn": ida_funcs.get_func_name(ea) or "(no func)",
                "init_path": reachable_from_reset(ea)
            })
        ea += 1

# Execute the scan
scan()

# Write JSON output
json_path = os.path.join(OUTDIR, "osd_sites.json")
with open(json_path, "w") as f:
    json.dump(rows, f, indent=2)

# Write Markdown table
md_path = os.path.join(OUTDIR, "osd_sites.md")
with open(md_path, "w", encoding="utf-8") as f:
    f.write("| File Offset | EA | Target | First 32 Bytes | Function | Reaches Reset |\n")
    f.write("|-------------|----|--------|----------------|----------|----------------|\n")
    for r in rows:
        f.write(f"| {r['file_off']} | {r['ea']} | {r['target']} | {r['bytes32']} | {r['fn']} | {'✓' if r['init_path'] else '✗'} |\n")

print(f"[+] Found {len(rows)} OSD sites")
print(f"[+] Wrote {json_path}")
print(f"[+] Wrote {md_path}")

# Show completion message in IDA
ida_kernwin.msg(f"[+] OSD sites scan complete: {len(rows)} found\n")
