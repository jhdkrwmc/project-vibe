import os
import sys
from typing import Tuple


def read_file(path: str) -> bytearray:
	with open(path, "rb") as f:
		return bytearray(f.read())


def write_file(path: str, data: bytes) -> None:
	with open(path, "wb") as f:
		f.write(data)


def sum16_be(data: bytes) -> int:
	# big-endian 16-bit words
	if len(data) % 2 == 1:
		data = data + b"\x00"
	total = 0
	for i in range(0, len(data), 2):
		word = (data[i] << 8) | data[i + 1]
		total = (total + word) & 0xFFFF
	return total


def sum16_le(data: bytes) -> int:
	# little-endian 16-bit words
	if len(data) % 2 == 1:
		data = data + b"\x00"
	total = 0
	for i in range(0, len(data), 2):
		word = data[i] | (data[i + 1] << 8)
		total = (total + word) & 0xFFFF
	return total


def calc_tail_fix(original: bytes) -> Tuple[str, int]:
	# Determine which scheme the original uses by checking if the current tail equals the proper fix
	if len(original) < 2:
		raise ValueError("Input too small")
	base = original[:-2]
	tail = original[-2:]
	be_fix = (-sum16_be(base)) & 0xFFFF
	le_fix = (-sum16_le(base)) & 0xFFFF
	# Choose the scheme whose expected tail matches current tail
	if tail == be_fix.to_bytes(2, "big"):
		return ("be", be_fix)
	if tail == le_fix.to_bytes(2, "little"):
		return ("le", le_fix)
	# If neither matches, default to big-endian (most common on these dumps)
	return ("be", be_fix)


def set_tail(data: bytearray, scheme: str) -> None:
	base = bytes(data[:-2])
	if scheme == "be":
		fix = (-sum16_be(base)) & 0xFFFF
		data[-2:] = fix.to_bytes(2, "big")
	else:
		fix = (-sum16_le(base)) & 0xFFFF
		data[-2:] = fix.to_bytes(2, "little")


def main() -> None:
	if len(sys.argv) < 2:
		print("Usage: python planC_patch_minconst.py <input_firmware> [output_firmware]")
		sys.exit(1)
	input_path = sys.argv[1]
	if len(sys.argv) >= 3:
		output_path = sys.argv[2]
	else:
		base_dir, name = os.path.split(input_path)
		root, ext = os.path.splitext(name)
		output_path = os.path.join(base_dir, f"{root}_patchC_minconst{ext or '.bin'}")

	data = read_file(input_path)
	print(f"Loaded {input_path}: {len(data)} bytes")

	if len(data) != 131072:
		print(f"Warning: expected 131072 bytes (128 KiB), got {len(data)}")

	# Minimal-constant flip: code_BB73 'mov A,#0xFF' -> '#0x00'
	# Address 0xBB73 sequence: 90 0E 24 74 FF F0 A3 22
	# We change the immediate at 0xBB77 from 0xFF to 0x00
	offset = 0xBB77
	orig = data[offset]
	if orig != 0xFF:
		print(f"ERROR: Byte at 0x{offset:05X} is 0x{orig:02X}, expected 0xFF. Aborting to avoid unintended changes.")
		sys.exit(2)
	data[offset] = 0x00
	print(f"Patched 0x{offset:05X}: 0xFF -> 0x00 (BB73 immediate)")

	# Fix tail checksum using scheme detected from original
	original_full = bytes(read_file(input_path))
	original_tail = original_full[-2:]
	if original_tail == b"\xFF\xFF":
		print("Tail bytes are 0xFFFF in original; preserving as-is (no checksum rewrite)")
	else:
		scheme, _ = calc_tail_fix(original_full)
		set_tail(data, scheme)
		print(f"Tail checksum updated using {scheme}-endian 16-bit word-sum scheme")

	write_file(output_path, data)
	print(f"Wrote {output_path}")


if __name__ == "__main__":
	main()


