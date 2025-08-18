import os
import re
import hashlib
import binascii
from typing import List, Tuple


def read_bytes(path: str) -> bytes:
	with open(path, "rb") as f:
		return f.read()


def be16_sum(data: bytes) -> int:
	# Sum of big-endian 16-bit words modulo 0x10000
	if len(data) % 2 != 0:
		data = data + b"\x00"
	total = 0
	for i in range(0, len(data), 2):
		word = (data[i] << 8) | data[i + 1]
		total = (total + word) & 0xFFFF
	return total


def find_all(data: bytes, pattern: bytes) -> List[int]:
	return [m.start() for m in re.finditer(re.escape(pattern), data)]


def summarize_file(path: str) -> None:
	print(f"FILE: {path}")
	if not os.path.exists(path):
		print("  exists: False\n")
		return
	data = read_bytes(path)
	sha1 = hashlib.sha1(data).hexdigest()
	print(f"  exists: True, size: {len(data)} bytes, sha1: {sha1}")

	anchors = [
		b"SN9C", b"SFLib", b"V00.00", b"H264", b"CAM", b"GEN", b"ISP", b"VPATH",
		b"XUJIN", b"Webcam USB", b"GC2053",
	]
	present = [a.decode(errors="ignore") for a in anchors if a in data]
	print(f"  anchors: {present}")

	# OSD-related DPTR constants
	osd_ptrs: List[Tuple[bytes, str]] = [
		(b"\x90\x0E\x24", "MOV DPTR,#0x0E24"),
		(b"\x90\x0E\x25", "MOV DPTR,#0x0E25"),
		(b"\x90\x0E\x26", "MOV DPTR,#0x0E26"),
		(b"\x90\x0E\x27", "MOV DPTR,#0x0E27"),
	]
	for sig, name in osd_ptrs:
		hits = find_all(data, sig)
		preview = ", ".join(hex(x) for x in hits[:8])
		extra = f" (+{len(hits) - 8} more)" if len(hits) > 8 else ""
		print(f"  {name}: [{preview}]{extra}")

	# Common write walk pattern F0 A3 F0 A3 F0 A3
	walk = find_all(data, b"\xF0\xA3\xF0\xA3\xF0\xA3")
	print(f"  write-walk F0 A3 *3: hits={len(walk)} first={[hex(x) for x in walk[:8]]}")

	# V-tags present
	v_tags = sorted(set(m.decode() for m in re.findall(rb"V\d\d\.\d\d-[A-Za-z0-9_]+", data)))
	if v_tags:
		print(f"  V-tags ({len(v_tags)}): {v_tags[:20]}{' ...' if len(v_tags) > 20 else ''}")

	# Tail checksum overview
	sum_be16 = be16_sum(data)
	print(f"  be16 sum mod 0x10000: {hex(sum_be16)}; last2={data[-2:].hex()}")

	print()


def main() -> None:
	base_dir = os.getcwd()
	paths = [
		os.path.join(base_dir, "new path", "firmware_backup_base.bin"),
		os.path.join(base_dir, "new path", "firmware5262-GC2053-(HD264-Webcam-USB)-2005200301-Black Screen issue.src"),
		os.path.join(base_dir, "new path", "SonixAllRomFile.src"),
	]
	for p in paths:
		summarize_file(p)


if __name__ == "__main__":
	main()


