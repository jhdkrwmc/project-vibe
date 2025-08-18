#!/usr/bin/env python3
"""
Fix FW_A checksum after data-only patch
"""

def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def write_file(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)

def calculate_checksum(data: bytes) -> int:
    """Calculate checksum using the same algorithm as compare_fw.py"""
    total = 0
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            word = (data[i] << 8) | data[i+1]
        else:
            word = data[i] << 8
        total = (total + word) & 0xFFFF
    return total

def main():
    # Read the patched firmware
    patched_path = "fw_a_safe_data_patched.bin"
    firmware = read_file(patched_path)
    
    print(f"Firmware size: {len(firmware)} bytes")
    
    # Calculate current checksum
    current_checksum = calculate_checksum(firmware)
    print(f"Current checksum: 0x{current_checksum:04X}")
    
    # Target checksum from compare_fw.py: 0x876f
    target_checksum = 0x876f
    print(f"Target checksum: 0x876f")
    
    # Calculate compensation needed
    compensation = (target_checksum - current_checksum) & 0xFFFF
    print(f"Compensation needed: 0x{compensation:04X}")
    
    # Apply compensation to last two bytes
    patched = bytearray(firmware)
    patched[0x1FFFE] = (compensation >> 8) & 0xFF
    patched[0x1FFFF] = compensation & 0xFF
    
    # Verify final checksum
    final_checksum = calculate_checksum(patched)
    print(f"Final checksum: 0x{final_checksum:04X}")
    print(f"Target achieved: {'YES' if final_checksum == target_checksum else 'NO'}")
    
    # Save corrected firmware
    corrected_path = "fw_a_safe_data_patched_fixed.bin"
    write_file(corrected_path, bytes(patched))
    
    print(f"\nCorrected firmware saved to: {corrected_path}")
    
    # Show the patch details
    print(f"\nPatch Summary:")
    print(f"  0xBB77: 0xFF -> 0x00 (OSD enable -> disable)")
    print(f"  0x1FFFE-0x1FFFF: checksum compensation")
    print(f"  Total changes: 3 bytes")
    print(f"  Strategy: Data-only, no code injection")

if __name__ == "__main__":
    main()
