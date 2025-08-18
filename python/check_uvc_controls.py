import os
import sys
from typing import List, Dict


def read_file(path: str) -> bytes:
	with open(path, "rb") as f:
		return f.read()


def find_uvc_control_patterns(data: bytes) -> Dict[str, List[int]]:
	"""Find UVC control patterns in firmware"""
	patterns = {}
	
	# Look for XU control patterns
	# Common: 0x9A (XU tag), 0x04 (OSD subcommand), etc.
	xu_patterns = []
	for i in range(0, len(data)-2):
		if data[i] == 0x9A:  # XU tag
			xu_patterns.append(i)
	patterns["xu_tag"] = xu_patterns
	
	# Look for control command patterns
	control_patterns = []
	for i in range(0, len(data)-2):
		if data[i] == 0x04:  # Common subcommand
			control_patterns.append(i)
	patterns["subcmd_04"] = control_patterns
	
	# Look for UVC descriptor patterns
	uvc_patterns = []
	for i in range(0, len(data)-4):
		if (data[i] == 0x24 and      # UVC
			data[i+1] == 0x02 and    # Video Control
			data[i+2] == 0x00):      # Interface
			uvc_patterns.append(i)
	patterns["uvc_descriptor"] = uvc_patterns
	
	return patterns


def analyze_firmware_uvc(fw_path: str) -> None:
	"""Analyze UVC capabilities of a firmware"""
	data = read_file(fw_path)
	
	print(f"\nAnalyzing: {fw_path}")
	print(f"Size: {len(data)} bytes")
	
	patterns = find_uvc_control_patterns(data)
	
	for pattern_name, addresses in patterns.items():
		print(f"{pattern_name}: {len(addresses)} found")
		if addresses:
			print(f"  First few: {[hex(x) for x in addresses[:5]]}")
			
			# Show context around first few patterns
			for addr in addresses[:3]:
				if addr < len(data) - 16:
					context = data[addr:addr+16]
					print(f"    At 0x{addr:05X}: {context.hex(' ')}")


def main() -> None:
	if len(sys.argv) < 2:
		print("Usage: python check_uvc_controls.py <firmware_path>")
		sys.exit(1)
	
	fw_path = sys.argv[1]
	analyze_firmware_uvc(fw_path)


if __name__ == "__main__":
	main()
