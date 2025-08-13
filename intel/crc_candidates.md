# SN9C292B Firmware - CRC/Checksum Routine Candidates

## Candidate 1: Function at 0x235E
- **EA:** 0x235E
- **File Offset:** 0x235E
- **Signature:** `00 EF C8 EE C8 08 80 02 C3 13 D8 FC 12 D5 31 12 D5 70 F5 83 E0 04 F0 90 0E FE E0 FF 22`
- **Description:** This function is called from code near the OSD enable site at 0x4522. It contains a loop structure and memory access patterns typical of a checksum routine.
- **Callers:** 
  - 0x4522 (from OSD enable sequence)
  - Potentially other initialization routines
- **Byte-Level Evidence:**
  - Loop control flow with `D8 FC` (DJNZ R0, $+0xFC)
  - Memory access patterns with `E0 04 F0` (MOVX @DPTR, A)
  - Register manipulation consistent with checksum accumulation
  - Called in a context that suggests data validation
- **Analysis:**
  - Processes data in a loop, likely calculating a running checksum
  - Uses DPTR for memory addressing, suggesting it processes firmware sections
  - Contains conditional branches that may verify checksum results

## Candidate 2: Reset Vector Code at 0x38EA
- **EA:** 0x38EA
- **File Offset:** 0x38EA
- **Signature:** `74 01 12 E8 DB C3 94 0D 40 25 74 01 F0 90 0B C6 E0 04 F0 70 06 90 0B C5 E0 04 F0 30 03 11`
- **Description:** The initial code executed after reset, containing early firmware validation logic.
- **Callers:** Reset vector at 0x0000
- **Byte-Level Evidence:**
  - Calls to validation function at 0xE8DB
  - Conditional branching based on memory values
  - Register initialization sequences
  - Memory access patterns consistent with checksum verification
- **Analysis:**
  - Contains the first executable code after reset
  - Performs early system initialization
  - Includes conditional logic that may verify firmware integrity
  - May call other validation routines

## Candidate 3: Validation Function at 0xE8DB
- **EA:** 0xE8DB
- **File Offset:** 0xE8DB
- **Signature:** `E0 FE D0 E0 FD D0 E0 FC D3 12 11 7F 40 08 12 B2 97 12 B3 21 80 07 12 B2 3F FF 12 10 95`
- **Description:** A function called during early initialization that may perform firmware validation.
- **Callers:** 
  - Reset code at ~0x38F0
  - Potentially other system initialization routines
- **Byte-Level Evidence:**
  - Stack manipulation (D0 E0 instructions)
  - Conditional branching based on comparison results
  - Calls to other potentially related functions
  - Memory access patterns consistent with data validation
- **Analysis:**
  - Called during critical initialization phase
  - Contains complex conditional logic
  - May implement a multi-stage validation process
  - Could be responsible for verifying firmware integrity before boot

## Checksum Storage Locations
- **End of Firmware:** Common location for storing checksums in embedded systems
- **XDATA Region:** 0x0B70-0x0B7F (near OSD control registers)
- **Special Registers:** Some 8051 variants have dedicated registers for checksum storage

## Checksum Algorithm Analysis
Based on the examined code, the firmware likely uses one of these algorithms:

1. **Simple Checksum (Most Likely):**
   - 8-bit or 16-bit sum of all bytes
   - May use XOR for error detection
   - Simple to implement in 8051 assembly

2. **CRC-8/CRC-16:**
   - More robust error detection
   - May use polynomial division
   - Could explain the complex branching patterns

3. **Custom Algorithm:**
   - May combine multiple operations (add, XOR, rotate)
   - Could include a seed value
   - May process data in blocks

## Next Steps

1. **Dynamic Analysis:**
   - Trace execution flow during boot
   - Monitor memory writes to identify checksum storage
   - Capture register values during checksum calculation

2. **Algorithm Reverse Engineering:**
   - Identify input data and expected output
   - Reverse engineer the exact calculation steps
   - Document the algorithm for verification

3. **Patch Development:**
   - Update patch_osd_off.py with checksum recalculation
   - Test with known good firmware images
   - Verify checksum calculation matches original

4. **Verification:**
   - Compare checksums before and after patching
   - Ensure only intended bytes are modified
   - Validate firmware operation with patched checksum
