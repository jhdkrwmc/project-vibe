# XDATA Write Map (0x0B00-0x0BFF)

## Overview
This document tracks all MOVX write operations to the XDATA region 0x0B00-0x0BFF, with a focus on OSD control registers and reset-related writes.

## OSD Control Registers

| Address | EA      | File Offset | Value | Instruction | Function     | Context |
|---------|---------|-------------|-------|-------------|--------------|---------|
| 0x0B75  | 0x04525 | 0x4525      | 0x01  | MOVX @DPTR,A| sub_4522     | OSD Enable (Main) |
| 0x0B76  | 0x00AC7 | 0x0AC7      | 0x01  | MOVX @DPTR,A| sub_AC4      | OSD Control |
| 0x0B77  | 0x00B01 | 0x0B01      | 0x01  | MOVX @DPTR,A| sub_AFE      | OSD Control |
| 0x0B77  | 0x004D3 | 0x04D3      | 0x01  | MOVX @DPTR,A| sub_4D0      | OSD Enable |

## Reset Block Writes (0x0BC0-0x0BCF)

| Address | EA      | File Offset | Value | Instruction | Function     | Context |
|---------|---------|-------------|-------|-------------|--------------|---------|
| 0x0BC3  | 0x038F0 | 0x38F0      | 0x01  | MOVX @DPTR,A| Reset_Handler| Reset Init |
| 0x0BC5  | 0x03907 | 0x3907      | A+1   | MOVX @DPTR,A| Reset_Handler| Reset Counter (MSB) |
| 0x0BC6  | 0x038FF | 0x38FF      | A+1   | MOVX @DPTR,A| Reset_Handler| Reset Counter (LSB) |

## Other Notable XDATA Writes

| Address | EA      | File Offset | Value | Instruction | Function     | Context |
|---------|---------|-------------|-------|-------------|--------------|---------|
| 0x0BA5  | 0x00B1E | 0x0B1E      | 0x01  | MOVX @DPTR,A| sub_AFE      | Unknown |
| 0x0BA6  | 0x00B25 | 0x0B25      | 0x01  | MOVX @DPTR,A| sub_AFE      | Unknown |
| 0x0BA7  | 0x00B2C | 0x0B2C      | 0x01  | MOVX @DPTR,A| sub_AFE      | Unknown |

## Reset Counter Behavior

1. **Location**: 0x0BC5 (MSB) and 0x0BC6 (LSB)
2. **Increment Pattern**:
   - On each reset, 0x0BC6 is incremented
   - If 0x0BC6 overflows (0xFF → 0x00), 0x0BC5 is incremented
3. **Initialization**:
   ```assembly
   ; Reset_Handler at ~0x38EA
   90 0B C6    MOV DPTR, #0x0BC6
   E0          MOVX A, @DPTR
   04          INC A
   F0          MOVX @DPTR, A    ; Increment LSB
   70 06       JNZ  skip_msb_inc
   90 0B C5    MOV DPTR, #0x0BC5
   E0          MOVX A, @DPTR
   04          INC A
   F0          MOVX @DPTR, A    ; Increment MSB if LSB overflowed
   ```

## OSD Enable Sequence Analysis

### Main Enable (0x4522)
```assembly
90 0B 75    MOV DPTR, #0x0B75    ; OSD Control Register
74 01       MOV A, #0x01
F0          MOVX @DPTR, A         ; Enable OSD
```

### Secondary Enables
- **0x0AC7**: Enables OSD control at 0x0B76
- **0x0B01**: Enables OSD control at 0x0B77
- **0x04D3**: Enables OSD control at 0x0B77

## Potential Late-Disable Targets

1. **0x0B75 (Main OSD Enable)**
   - Written at 0x4522 during initialization
   - Good candidate for patching to 0x00

2. **0x0B76-0x0B77 (OSD Control)**
   - Written by multiple functions
   - May control specific OSD features

## Next Steps

1. Analyze all functions that write to 0x0B75-0x0B77
2. Determine safe patching locations
3. Verify no critical functionality depends on these writes
4. Test OSD disable patches
