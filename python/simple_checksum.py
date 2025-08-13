#!/usr/bin/env python3
"""
Simple checksum verification
"""

print("Starting checksum verification...")

try:
    with open("firmware_backup - Copy (4).bin", 'rb') as f:
        data = f.read()
    print(f"Read {len(data)} bytes")
    
    if len(data) != 0x20000:
        print(f"ERROR: Expected 0x20000 bytes, got {len(data):#x}")
    else:
        # Calculate sum of bytes 0x0000 to 0x1FFD
        partial_sum = sum(data[0:0x1FFE]) & 0xFFFF
        
        # Read checksum from 0x1FFE-0x1FFF (little-endian)
        stored_checksum = (data[0x1FFF] << 8) | data[0x1FFE]
        
        print(f"Partial sum [0x0000..0x1FFD]: {partial_sum:#06x}")
        print(f"Stored checksum @ 0x1FFE-0x1FFF: {stored_checksum:#06x}")
        print(f"Bytes at 0x1FFE-0x1FFF: {data[0x1FFE]:02X} {data[0x1FFF]:02X}")
        
        # Calculate total sum
        total_sum = (partial_sum + stored_checksum) & 0xFFFF
        print(f"Total sum: {total_sum:#06x}")
        print(f"Verification: {'PASS' if total_sum == 0 else 'FAIL'}")
        
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()

print("Done.") 