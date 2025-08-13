
#!/usr/bin/env python3
# External helper — Quick diff of two firmware images (offset, old->new)
#
# Usage:
#   python diff_fw.py original.bin patched.bin [--limit 200]
#
import sys

def main():
    if len(sys.argv) < 3:
        print("Usage: diff_fw.py OLD.bin NEW.bin [--limit N]"); return
    oldf, newf = sys.argv[1], sys.argv[2]
    limit = 200
    if len(sys.argv) >= 5 and sys.argv[3] == "--limit":
        limit = int(sys.argv[4], 0)
    a = open(oldf, "rb").read()
    b = open(newf, "rb").read()
    n = 0
    for i,(x,y) in enumerate(zip(a,b)):
        if x != y:
            print(f"0x{i:06X}: {x:02X} -> {y:02X}")
            n += 1
            if n >= limit:
                print("...")
                break
    print(f"Total diffs (truncated to {limit}): {n}")
if __name__ == "__main__":
    main()
