import ida_bytes
import idaapi
import os

OUTDIR = r"C:\Users\arnax\Desktop\project-vibe\logs"
os.makedirs(OUTDIR, exist_ok=True)
outfile = os.path.join(OUTDIR, "step01_tail.txt")

inf = idaapi.get_inf_structure()
max_ea = ida_bytes.get_max_ea()
start_addr = max(inf.min_ea, max_ea - 64)

tail_bytes = ida_bytes.get_bytes(start_addr, 64)

if tail_bytes:
    hex_rows = []
    for i in range(0, len(tail_bytes), 16):
        chunk = tail_bytes[i:i+16]
        hex_str = ' '.join(f'{b:02X}' for b in chunk)
        hex_rows.append(hex_str)
    
    formatted_hex = '\n'.join(hex_rows)

    with open(outfile, 'w') as f:
        f.write(formatted_hex)
    
    print(f"Success. Tail bytes written to {outfile}")
else:
    print("Error: Could not read tail bytes from IDA.")
