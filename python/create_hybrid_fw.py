import os
import sys
from typing import List, Tuple


def read_file(path: str) -> bytes:
	with open(path, "rb") as f:
		return f.read()


def write_file(path: str, data: bytes) -> None:
	with open(path, "wb") as f:
		f.write(data)


def find_sensor_init_blocks(data: bytes) -> List[Tuple[int, int, bytes]]:
	"""Find sensor initialization blocks by looking for patterns of register writes"""
	blocks = []
	
	# Look for sequences that might be sensor register writes
	# Common pattern: MOV A,#reg, MOVX @DPTR,A, INC DPTR, MOV A,#val, MOVX @DPTR,A
	for i in range(0, len(data)-16):
		# Pattern: 74 XX F0 A3 74 YY F0 (MOV A,#XX; MOVX @DPTR,A; INC DPTR; MOV A,#YY; MOVX @DPTR,A)
		if (data[i] == 0x74 and      # MOV A,#immediate
			data[i+2] == 0xF0 and    # MOVX @DPTR,A
			data[i+3] == 0xA3 and    # INC DPTR
			data[i+4] == 0x74 and    # MOV A,#immediate
			data[i+6] == 0xF0):      # MOVX @DPTR,A
			
			# Look for the end of this block (usually a jump or return)
			end = i + 16
			for j in range(i+16, min(i+64, len(data))):
				if data[j] in [0x22, 0x02, 0x80, 0x70]:  # RET, LJMP, SJMP, JNZ
					end = j + 2
					break
			
			block_data = data[i:end]
			if len(block_data) >= 16:  # Only keep substantial blocks
				blocks.append((i, end, block_data))
	
	return blocks


def find_differences_in_blocks(fw1: bytes, fw2: bytes, blocks: List[Tuple[int, int, bytes]]) -> List[Tuple[int, int, bytes, bytes]]:
	"""Find blocks that differ significantly between firmwares"""
	differences = []
	
	for start, end, block1 in blocks:
		if start < len(fw2) and end <= len(fw2):
			block2 = fw2[start:end]
			if block1 != block2:
				# Calculate difference percentage
				diff_bytes = sum(1 for a, b in zip(block1, block2) if a != b)
				diff_percent = (diff_bytes / len(block1)) * 100
				
				if diff_percent > 30:  # Only keep significantly different blocks
					differences.append((start, end, block1, block2))
	
	return differences


def create_hybrid_firmware(base_fw: bytes, sensor_fw: bytes, differences: List[Tuple[int, int, bytes, bytes]]) -> bytes:
	"""Create hybrid firmware by transplanting sensor blocks"""
	hybrid = bytearray(base_fw)
	
	print(f"Creating hybrid firmware...")
	print(f"Base firmware: {len(base_fw)} bytes")
	print(f"Sensor firmware: {len(sensor_fw)} bytes")
	
	transplanted_blocks = 0
	for start, end, sensor_block, base_block in differences:
		if start < len(hybrid) and end <= len(hybrid):
			# Transplant the sensor configuration block
			hybrid[start:end] = sensor_block
			transplanted_blocks += 1
			print(f"Transplanted block at 0x{start:05X}-0x{end:05X} ({len(sensor_block)} bytes)")
	
	print(f"Total transplanted blocks: {transplanted_blocks}")
	return bytes(hybrid)


def main() -> None:
	if len(sys.argv) < 4:
		print("Usage: python create_hybrid_fw.py <working_fw> <non_video_fw> <output_hybrid>")
		sys.exit(1)
	
	working_fw_path = sys.argv[1]
	non_video_fw_path = sys.argv[2]
	output_path = sys.argv[3]
	
	# Read firmwares
	working_fw = read_file(working_fw_path)
	non_video_fw = read_file(non_video_fw_path)
	
	print(f"Working firmware: {len(working_fw)} bytes")
	print(f"Non-video firmware: {len(non_video_fw)} bytes")
	
	# Find sensor initialization blocks in working firmware
	print("\nAnalyzing working firmware for sensor blocks...")
	sensor_blocks = find_sensor_init_blocks(working_fw)
	print(f"Found {len(sensor_blocks)} potential sensor blocks")
	
	# Find differences
	print("\nComparing blocks between firmwares...")
	differences = find_differences_in_blocks(working_fw, non_video_fw, sensor_blocks)
	print(f"Found {len(differences)} significantly different blocks")
	
	# Show some examples
	for i, (start, end, sensor_block, base_block) in enumerate(differences[:3]):
		print(f"\nBlock {i+1} at 0x{start:05X}-0x{end:05X}:")
		print(f"  Sensor: {sensor_block[:16].hex(' ')}...")
		print(f"  Base:   {base_block[:16].hex(' ')}...")
	
	# Create hybrid firmware
	hybrid_fw = create_hybrid_firmware(non_video_fw, working_fw, differences)
	
	# Write output
	write_file(output_path, hybrid_fw)
	print(f"\nHybrid firmware written to: {output_path}")
	print(f"Size: {len(hybrid_fw)} bytes")


if __name__ == "__main__":
	main()
