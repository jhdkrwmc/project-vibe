
#!/usr/bin/env python3
# Sonix 8051 OSD/Config Writer Finder
# Scans IDA .asm/.lst disassembly text to locate MOVX @DPTR,A writes into 0x0B00..0x0BFF,
# infer immediate vs RMW patterns, collect masks, and flag nearby #0x86.
#
# Usage:
#   python sonix_osd_probe.py dump1.asm dump2.lst ...
#
# Outputs:
#   - osd_probe_report.csv
#   - osd_probe_report.md

import re, sys, os, csv, textwrap
from collections import deque

HEX = r"(?:0x[0-9a-fA-F]+|[0-9A-Fh]+)"
def parse_hex(token):
    t = token.strip().rstrip(',')
    if not t:
        return None
    if t.endswith('h') or t.endswith('H'):
        return int(t[:-1], 16)
    if t.lower().startswith('0x'):
        return int(t, 16)
    # try decimal then hex
    try:
        return int(t, 10)
    except:
        try:
            return int(t, 16)
        except:
            return None

def norm(s):
    return re.sub(r"\s+", " ", s.strip()).lower()

re_label = re.compile(r"^\s*[A-Za-z_.$?][\w.$?:]*\s*:")
re_addr  = re.compile(r"^\s*([0-9a-fA-F]{2,8})\s*:")
re_mov_dptr_imm = re.compile(r"\bmov\s+dptr\s*,\s*#\s*("+HEX+")")
re_mov_dph_imm  = re.compile(r"\bmov\s+dph\s*,\s*#\s*("+HEX+")")
re_mov_dpl_imm  = re.compile(r"\bmov\s+dpl\s*,\s*#\s*("+HEX+")")
re_mov_a_imm    = re.compile(r"\bmov\s+a\s*,\s*#\s*("+HEX+")")
re_movx_w       = re.compile(r"\bmovx\s+@dptr\s*,\s*a\b")
re_movx_r       = re.compile(r"\bmovx\s+a\s*,\s*@dptr\b")
re_anl_a_imm    = re.compile(r"\banl\s+a\s*,\s*#\s*("+HEX+")")
re_orl_a_imm    = re.compile(r"\borl\s+a\s*,\s*#\s*("+HEX+")")
re_cpl_acc_bit  = re.compile(r"\bcpl\s+acc\.(\d)\b")
re_movc         = re.compile(r"\bmovc\s+a\s*,\s*@a\+dptr\b")
re_immediate86  = re.compile(r"(?:#\s*)?(0x86|86h|\\b86\\b)", re.IGNORECASE)

class State:
    def __init__(self):
        self.dpl = None
        self.dph = None
        self.dptr = None
        self.a_imm = None
        self.last_movx_read = False
        self.last_masks = []
        self.context = deque(maxlen=8)

    def update_dptr(self):
        if self.dpl is not None and self.dph is not None:
            self.dptr = ((self.dph & 0xFF) << 8) | (self.dpl & 0xFF)

def scan_file(path):
    results = []
    dp_hits_specific = []
    table_users = []
    imm86_hits = []

    st = State()
    with open(path, 'r', errors='ignore') as f:
        lines = f.readlines()

    for idx, raw in enumerate(lines):
        line = norm(raw)
        st.context.append(raw.rstrip("\\n"))
        maddr = re_addr.match(raw)
        addr_str = maddr.group(1) if maddr else ""

        if re_label.search(raw):
            st = State()

        m = re_mov_dptr_imm.search(line)
        if m:
            val = parse_hex(m.group(1))
            if val is not None:
                st.dptr = val & 0xFFFF
                st.dpl = st.dptr & 0xFF
                st.dph = (st.dptr >> 8) & 0xFF
                if 0x0B70 <= st.dptr <= 0x0B7F:
                    dp_hits_specific.append((path, idx+1, addr_str, st.dptr, '\\n'.join(st.context)))

        m = re_mov_dph_imm.search(line)
        if m:
            v = parse_hex(m.group(1))
            if v is not None:
                st.dph = v & 0xFF
                st.update_dptr()

        m = re_mov_dpl_imm.search(line)
        if m:
            v = parse_hex(m.group(1))
            if v is not None:
                st.dpl = v & 0xFF
                st.update_dptr()

        m = re_mov_a_imm.search(line)
        if m:
            v = parse_hex(m.group(1))
            st.a_imm = None if v is None else (v & 0xFF)
            st.last_movx_read = False
            st.last_masks.clear()

        if re_movc.search(line):
            table_users.append((path, idx+1, addr_str, st.dptr, '\\n'.join(st.context)))

        manl = re_anl_a_imm.search(line)
        if manl:
            v = parse_hex(manl.group(1))
            if v is not None:
                st.last_masks.append(("ANL", v & 0xFF, idx+1))

        morl = re_orl_a_imm.search(line)
        if morl:
            v = parse_hex(morl.group(1))
            if v is not None:
                st.last_masks.append(("ORL", v & 0xFF, idx+1))

        mcpl = re_cpl_acc_bit.search(line)
        if mcpl:
            bit = int(mcpl.group(1))
            st.last_masks.append(("CPL", bit, idx+1))

        if re_movx_r.search(line):
            st.last_movx_read = True
            st.a_imm = None
            st.last_masks.clear()

        if re_movx_w.search(line):
            tgt = st.dptr
            if tgt is not None and (0x0B00 <= tgt <= 0x0BFF):
                write_type = "unknown"
                value = None
                details = ""
                if st.a_imm is not None and not st.last_movx_read and not st.last_masks:
                    write_type = "IMM->WRITE"
                    value = st.a_imm
                elif st.a_imm is not None and st.last_masks:
                    write_type = "IMM->MASK->WRITE"
                    value = st.a_imm
                    details = " masks=" + ",".join(f"{op}:{hex(v) if op!='CPL' else op+'.'+str(v)}" for op,v,*_ in st.last_masks)
                elif st.last_movx_read and st.last_masks:
                    write_type = "RMW->MASK->WRITE"
                    details = " masks=" + ",".join(f"{op}:{hex(v) if op!='CPL' else op+'.'+str(v)}" for op,v,*_ in st.last_masks)
                elif st.last_movx_read and not st.last_masks:
                    write_type = "RMW->WRITE(no mask)"
                else:
                    write_type = "WRITE(unknown source)"

                imm86 = bool(re_immediate86.search('\\n'.join(st.context)))

                results.append({
                    "file": os.path.basename(path),
                    "line": idx+1,
                    "addr": addr_str,
                    "dptr": hex(tgt),
                    "range_hit": "0x0B70-0x0B7F" if 0x0B70 <= tgt <= 0x0B7F else "0x0B00-0x0BFF",
                    "write_type": write_type,
                    "a_imm": (hex(value) if value is not None else ""),
                    "masks": ";".join(f"{op}:{hex(v) if op!='CPL' else op+'.'+str(v)}" for op,v,*_ in st.last_masks),
                    "imm86_in_context": "yes" if imm86 else "no",
                    "context": '\\n'.join(st.context)
                })

                st.last_movx_read = False
                st.last_masks.clear()

        if re_immediate86.search(line):
            imm86_hits.append((path, idx+1, addr_str, '\\n'.join(st.context)))

    return results, dp_hits_specific, table_users, imm86_hits

def main(argv):
    if len(argv) < 2:
        print("Usage: python sonix_osd_probe.py <disasm1.asm> [<disasm2.lst> ...]")
        return 2

    all_results = []
    all_dp_hits = []
    all_tables = []
    all_imm86 = []
    for p in argv[1:]:
        if not os.path.isfile(p):
            print(f"[WARN] Not a file: {p}")
            continue
        r, dph, tabs, imm = scan_file(p)
        all_results.extend(r)
        all_dp_hits.extend(dph)
        all_tables.extend(tabs)
        all_imm86.extend(imm)

    os.makedirs(os.path.dirname(os.path.abspath("osd_probe_report.csv")), exist_ok=True)

    csv_path = "osd_probe_report.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=[
            "file","line","addr","dptr","range_hit","write_type","a_imm","masks","imm86_in_context","context"
        ])
        w.writeheader()
        for row in all_results:
            w.writerow(row)

    md_path = "osd_probe_report.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Sonix 8051 OSD/Config Writer Probe\\n\\n")
        f.write("This report lists MOVX @DPTR,A writes into 0x0B00–0x0BFF, with heuristics to detect immediate writes, RMW masking patterns, and nearby 0x86 immediates. It also notes DPTR loads into 0x0B70–0x0B7F and MOVC table usage sites.\\n\\n")

        f.write("## Summary Stats\\n")
        f.write(f"- Total MOVX writes into 0x0B00–0x0BFF: **{len(all_results)}**\\n")
        f.write(f"- DPTR loads into 0x0B70–0x0B7F: **{len(all_dp_hits)}**\\n")
        f.write(f"- MOVC A,@A+DPTR sites (table users): **{len(all_tables)}**\\n")
        f.write(f"- #0x86 immediates seen: **{len(all_imm86)}**\\n\\n")

        def dump_section(title, rows, formatter):
            f.write(f"## {title}\\n\\n")
            if not rows:
                f.write("_None_\\n\\n")
                return
            for r in rows[:3000]:
                f.write(formatter(r))
                f.write("\\n")

        def fmt_movx(row):
            return textwrap.dedent(f\"\"\"\\
            **{row['file']}:{row['line']} @ {row['addr']}**
            - DPTR: {row['dptr']} ({row['range_hit']})
            - Type: {row['write_type']}
            - A immediate: {row['a_imm']}
            - Masks: {row['masks']}
            - 0x86 in context: {row['imm86_in_context']}
            - Context:
            ```
            {row['context']}
            ```
            \"\"\")

        dump_section("MOVX @DPTR,A into 0x0Bxx", all_results, fmt_movx)

        def fmt_dph(r):
            path, line, addr, dptr, ctx = r
            return textwrap.dedent(f\"\"\"\\
            **{os.path.basename(path)}:{line} @ {addr}**
            - DPTR load: {hex(dptr)}
            - Context:
            ```
            {ctx}
            ```
            \"\"\")
        dump_section("DPTR loads into 0x0B70–0x0B7F", all_dp_hits, fmt_dph)

        def fmt_tab(r):
            path, line, addr, dptr, ctx = r
            return textwrap.dedent(f\"\"\"\\
            **{os.path.basename(path)}:{line} @ {addr}**
            - MOVC A,@A+DPTR detected (table usage), DPTR≈ {hex(dptr) if dptr is not None else 'unknown'}
            - Context:
            ```
            {ctx}
            ```
            \"\"\")
        dump_section("MOVC Table Users", all_tables, fmt_tab)

        def fmt_imm(r):
            path, line, addr, ctx = r
            return textwrap.dedent(f\"\"\"\\
            **{os.path.basename(path)}:{line} @ {addr}**
            - #0x86 immediate detected
            - Context:
            ```
            {ctx}
            ```
            \"\"\")
        dump_section("#0x86 Immediates (near anything)", all_imm86, fmt_imm)

    print("Wrote:")
    print(csv_path)
    print(md_path)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
