import os
import sys
from typing import List, Tuple


def read_file(path: str) -> bytes:
	with open(path, "rb") as f:
		return f.read()


def write_file(path: str, data: bytes) -> None:
	with open(path, "wb") as f:
		f.write(data)


def find_sensor_constants(data: bytes) -> List[Tuple[int, bytes]]:
	"""Find sensor-related constants that are safe to transplant"""
	constants = []
	
	# Look for sensor register values (common patterns)
	# These are usually immediate values that configure sensor behavior
	for i in range(0, len(data)-4):
		# Pattern: MOV A,#value followed by sensor-like operations
		if (data[i] == 0x74 and      # MOV A,#immediate
			data[i+2] == 0xF0 and    # MOVX @DPTR,A
			data[i+3] == 0xA3):      # INC DPTR
			
			value = data[i+1]
			# Only consider values that look like sensor registers (0x00-0xFF)
			if value != 0x00 and value != 0xFF:
				constants.append((i+1, bytes([value])))
	
	return constants


def create_minimal_hybrid(base_fw: bytes, sensor_fw: bytes) -> bytes:
	"""Create minimal hybrid by only transplanting essential sensor constants"""
	hybrid = bytearray(base_fw)
	
	print(f"Creating minimal hybrid firmware...")
	print(f"Base firmware: {len(base_fw)} bytes")
	print(f"Sensor firmware: {len(sensor_fw)} bytes")
	
	# Find sensor constants in working firmware
	sensor_constants = find_sensor_constants(sensor_fw)
	print(f"Found {len(sensor_constants)} potential sensor constants")
	
	# Only transplant a few critical constants to minimize disruption
	transplanted = 0
	for addr, value in sensor_constants[:20]:  # Limit to first 20
		if addr < len(hybrid):
			original = hybrid[addr]
			hybrid[addr] = value[0]
			if original != value[0]:
				transplanted += 1
				print(f"Transplanted 0x{addr:05X}: 0x{original:02X} -> 0x{value[0]:02X}")
	
	print(f"Total transplanted constants: {transplanted}")
	return bytes(hybrid)


def main() -> None:
	if len(sys.argv) < 4:
		print("Usage: python create_minimal_hybrid.py <working_fw> <non_video_fw> <output_hybrid>")
		sys.exit(1)
	
	working_fw_path = sys.argv[1]
	non_video_fw_path = sys.argv[2]
	output_path = sys.argv[3]
	
	# Read firmwares
	working_fw = read_file(working_fw_path)
	non_video_fw = read_file(non_video_fw_path)
	
	# Create minimal hybrid
	hybrid_fw = create_minimal_hybrid(non_video_fw, working_fw)
	
	# Write output
	write_file(output_path, hybrid_fw)
	print(f"\nMinimal hybrid firmware written to: {output_path}")
	print(f"Size: {len(hybrid_fw)} bytes")


if __name__ == "__main__":
	main()
