#!/usr/bin/env python3
"""
Fix FW_B checksum after data-only patch
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
    patched_path = "fw_b_safe_data_patched.bin"
    firmware = read_file(patched_path)
    
    print(f"Firmware size: {len(firmware)} bytes")
    
    # Calculate current checksum
    current_checksum = calculate_checksum(firmware)
    print(f"Current checksum: 0x{current_checksum:04X}")
    
    # Target checksum from compare_fw.py: 0xE349
    target_checksum = 0xE349
    print(f"Target checksum: 0xE349")
    
    # Calculate compensation needed
    compensation = (target_checksum - current_checksum) & 0xFFFF
    print(f"Compensation needed: 0x{compensation:04X}")
    
    # Apply compensation to last two bytes
    patched = bytearray(firmware)
    
    # Get current last two bytes
    current_last = (patched[0x1FFFE] << 8) | patched[0x1FFFF]
    print(f"Current last two bytes: 0x{current_last:04X}")
    
    # Calculate new last two bytes
    new_last = (current_last + compensation) & 0xFFFF
    print(f"New last two bytes: 0x{new_last:04X}")
    
    # Apply the compensation
    patched[0x1FFFE] = (new_last >> 8) & 0xFF
    patched[0x1FFFF] = new_last & 0xFF
    
    # Verify final checksum
    final_checksum = calculate_checksum(patched)
    print(f"Final checksum: 0x{final_checksum:04X}")
    print(f"Target achieved: {'YES' if final_checksum == target_checksum else 'NO'}")
    
    # Save corrected firmware
    corrected_path = "fw_b_safe_data_patched_final.bin"
    write_file(corrected_path, bytes(patched))
    
    print(f"\nCorrected firmware saved to: {corrected_path}")
    
    # Show the patch details
    print(f"\nPatch Summary:")
    print(f"  0x056D: 0xFF -> 0x00 (OSD enable -> disable)")
    print(f"  0x1FFFE-0x1FFFF: 0x{current_last:04X} -> 0x{new_last:04X}")
    print(f"  Total changes: 3 bytes")
    print(f"  Strategy: Data-only, no code injection")
    print(f"  Risk: VERY LOW")

if __name__ == "__main__":
    main()
