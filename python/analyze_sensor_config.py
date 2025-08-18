import os
import sys
from typing import List, Tuple, Dict


def read_file(path: str) -> bytes:
	with open(path, "rb") as f:
		return f.read()


def find_sensor_patterns(data: bytes) -> Dict[str, List[int]]:
	"""Find sensor-related patterns in firmware"""
	patterns = {}
	
	# Common sensor I2C addresses
	sensor_addrs = [0x36, 0x37, 0x6C, 0x6D, 0x78, 0x79, 0x7A, 0x7B]
	
	# Look for MOV DPTR,#sensor_addr patterns (90 XX XX)
	dptr_refs = []
	for i in range(0, len(data)-2):
		if data[i] == 0x90:  # MOV DPTR,#immediate
			addr = (data[i+1] << 8) | data[i+2]
			if addr in sensor_addrs:
				dptr_refs.append(i)
	patterns["dptr_sensor"] = dptr_refs
	
	# Look for MOV A,#sensor_addr patterns (74 XX)
	mov_a_refs = []
	for i in range(0, len(data)-1):
		if data[i] == 0x74:  # MOV A,#immediate
			if data[i+1] in sensor_addrs:
				mov_a_refs.append(i)
	patterns["mov_a_sensor"] = mov_a_refs
	
	# Look for I2C-like bit operations (SETB/CLR on common I2C pins)
	i2c_ops = []
	for i in range(0, len(data)-1):
		if data[i] in [0xD2, 0xC2]:  # SETB/CLR bit
			if data[i+1] in [0x90, 0x91, 0x92, 0x93]:  # Common I2C pin addresses
				i2c_ops.append(i)
	patterns["i2c_ops"] = i2c_ops
	
	# Look for sensor initialization sequences
	# Common: delays, register writes, power-up sequences
	init_seqs = []
	for i in range(0, len(data)-8):
		# Look for sequences like: delay, write, delay, write
		if (data[i] == 0x12 and  # LCALL
			data[i+3] == 0x12 and  # Another LCALL
			data[i+6] == 0x12):    # Third LCALL
			init_seqs.append(i)
	patterns["init_seqs"] = init_seqs
	
	return patterns


def find_differences(fw1: bytes, fw2: bytes, patterns: Dict[str, List[int]]) -> Dict[str, List[Tuple[int, bytes, bytes]]]:
	"""Find differences in sensor-related regions"""
	differences = {}
	
	for pattern_name, addresses in patterns.items():
		diffs = []
		for addr in addresses:
			if addr < len(fw1) and addr < len(fw2):
				# Compare 16 bytes around each pattern
				start = max(0, addr - 8)
				end1 = min(len(fw1), addr + 8)
				end2 = min(len(fw2), addr + 8)
				
				chunk1 = fw1[start:end1]
				chunk2 = fw2[start:end2]
				
				if chunk1 != chunk2:
					diffs.append((addr, chunk1, chunk2))
		
		differences[pattern_name] = diffs
	
	return differences


def main() -> None:
	if len(sys.argv) < 3:
		print("Usage: python analyze_sensor_config.py <working_fw> <non_video_fw>")
		sys.exit(1)
	
	working_fw = read_file(sys.argv[1])
	non_video_fw = read_file(sys.argv[2])
	
	print(f"Working firmware: {len(working_fw)} bytes")
	print(f"Non-video firmware: {len(non_video_fw)} bytes")
	
	# Find sensor patterns in working firmware
	print("\nAnalyzing working firmware for sensor patterns...")
	working_patterns = find_sensor_patterns(working_fw)
	
	for pattern_name, addresses in working_patterns.items():
		print(f"{pattern_name}: {len(addresses)} found")
		if addresses:
			print(f"  First few: {[hex(x) for x in addresses[:5]]}")
	
	# Find differences
	print("\nComparing sensor-related regions...")
	differences = find_differences(working_fw, non_video_fw, working_patterns)
	
	for pattern_name, diffs in differences.items():
		print(f"\n{pattern_name} differences: {len(diffs)}")
		for addr, chunk1, chunk2 in diffs[:3]:  # Show first 3
			print(f"  At 0x{addr:05X}:")
			print(f"    Working: {chunk1.hex(' ')}")
			print(f"    Non-vid: {chunk2.hex(' ')}")


if __name__ == "__main__":
	main()
