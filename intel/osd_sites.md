# OSD Enable Sites in SN9C292B Firmware

This document lists all identified OSD enable sequences in the firmware.

## OSD Enable Sites

| File Offset | Effective Address | Target Register | Instruction Bytes | Function | Init Path | A=0x01 Intact | Description |
|-------------|-------------------|-----------------|-------------------|-----------|-----------|----------------|-------------|
| 0x04D0 | 0x04D0 | 0x0B77 | 90 0B 77 74 01 F0 | Unknown | ❌ | ✅ | OSD enable sequence 1 (0x0B77) |
| 0x0AC4 | 0x0AC4 | 0x0B76 | 90 0B 76 74 01 F0 | Unknown | ❌ | ✅ | OSD enable sequence 2 (0x0B76) |
| 0x0AFE | 0x0AFE | 0x0B77 | 90 0B 77 74 01 F0 | Unknown | ❌ | ✅ | OSD enable sequence 3 (0x0B77) |
| 0x4522 | 0x4522 | 0x0B75 | 90 0B 75 74 01 F0 | Unknown | ✅ | ✅ | OSD enable sequence 4 (0x0B75) |

## Notes
- **File Offset**: Position in the firmware binary file
- **Effective Address**: Memory address where the instruction is located
- **Target Register**: XDATA register being written to (0x0B75-0x0B77 for OSD control)
- **Instruction Bytes**: Raw bytes of the instruction sequence
- **Function**: Name of the containing function (if known)
- **Init Path**: Whether this write occurs during the initialization path
- **A=0x01 Intact**: Whether the accumulator is set to 0x01 before the MOVX instruction

## Analysis
All four OSD enable sequences follow the same pattern: `MOV DPTR, #0x0B7x` followed by `MOV A, #0x01` and `MOVX @DPTR, A`. The target register varies between 0x0B75, 0x0B76, and 0x0B77, which are part of the OSD control window in XDATA memory.

The sequence at 0x4522 is particularly interesting as it appears to be part of the initialization path and writes to 0x0B75, which might be a master enable bit.
