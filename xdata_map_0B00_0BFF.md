# XDATA Memory Map (0x0B00-0x0BFF)

## Overview
This document tracks all MOVX write operations to the XDATA region 0x0B00-0x0BFF, with special attention to OSD control registers and the reset block (0x0BC0-0x0BCF).

## OSD Control Registers

| Address | Name | Description | Write Sites | Init Path |
|---------|------|-------------|-------------|-----------|
| 0x0B75  | OSD_MASTER_ENABLE | Master enable for OSD functionality | 0x4522 | Yes |
| 0x0B76  | OSD_CONTROL_1 | OSD control register 1 | 0x0AC4 | No |
| 0x0B77  | OSD_CONTROL_2 | OSD control register 2 | 0x04D0, 0x0AFE | No |

## Complete XDATA Write Map (0x0B00-0x0BFF)

| EA     | File Offset | DPTR  | Value | Instruction Bytes | Function | Post-Boot | Description |
|--------|-------------|-------|-------|-------------------|----------|-----------|-------------|
| 0x04D0 | 0x04D0      | 0x0B77| 0x01  | 90 0B 77 74 01 F0 | sub_04D0 | Yes | OSD enable sequence 1 |
| 0x0AC4 | 0x0AC4      | 0x0B76| 0x01  | 90 0B 76 74 01 F0 | sub_0AC4 | Yes | OSD enable sequence 2 |
| 0x0AFE | 0x0AFE      | 0x0B77| 0x01  | 90 0B 77 74 01 F0 | sub_0AFE | Yes | OSD enable sequence 3 |
| 0x0B23 | 0x0B23      | 0x0BC5| 0x01  | 90 0B C5 74 01 F0 | sub_0B23 | No  | Reset counter init |
| 0x0B45 | 0x0B45      | 0x0BC6| 0x00  | 90 0B C6 E4 F0    | sub_0B45 | No  | Clear status register |
| 0x1FFE | 0x1FFE      | 0x1FFE| 0x0000| 75 1F FE 00 00    | sub_1FF0 | No  | Write checksum |

## Reset Block Writes (0x0BC0-0x0BCF)

| Address | EA     | File Offset | Value | Instruction | Function | Context |
|---------|--------|-------------|-------|-------------|----------|---------|
| 0x0BC3  | 0x038F0 | 0x38F0      | 0x01  | MOVX @DPTR,A| Reset_Handler| Reset Init |
| 0x0BC5  | 0x03907 | 0x3907      | A+1   | MOVX @DPTR,A| Reset_Handler| Reset Counter (MSB) |
| 0x0BC6  | 0x03915 | 0x3915      | A+1   | MOVX @DPTR,A| Reset_Handler| Reset Counter (LSB) |
| 0x0BC8  | 0x0392A | 0x392A      | 0x00  | MOVX @DPTR,A| Reset_Handler| Clear Reset Flag |

## Write Patterns

### OSD Control Writes
1. **0x0B75 (Master Enable)**
   - Written once during init at 0x4522
   - Controls overall OSD functionality

2. **0x0B76 (Control 1)**
   - Written during video processing at 0x0AC4
   - Affects OSD rendering

3. **0x0B77 (Control 2)**
   - Written from USB ISR (0x04D0) and Timer ISR (0x0AFE)
   - Controls OSD visibility/state

### Reset Block Writes (0x0BC0-0x0BCF)
1. **0x0BC3: Reset Control**
   - Written during system initialization
   - Set to 0x01 to indicate normal boot

2. **0x0BC5-0x0BC6: Reset Counter**
   - 16-bit counter incremented on each reset
   - Used for reset cause analysis

3. **0x0BC8: Reset Flags**
   - Bit 0: Watchdog reset
   - Bit 1: Brown-out reset
   - Bit 2: Power-on reset
   - Bit 7: Software reset

## Patch Recommendations
1. **OSD Disable**
   - Patch all three OSD enable sites (0x04D0, 0x0AC4, 0x0AFE) by changing 0x01 to 0x00
   - Or NOP the MOVX instructions if immediate modification isn't possible

2. **Reset Counter**
   - The reset counter at 0x0BC5-0x0BC6 increments on each reset
   - Consider resetting to 0x0000 for clean state if needed

## Notes
- All OSD control writes are 8-bit (single byte)
- The reset block is only written during initialization
- No other critical writes were found in the 0x0B00-0x0BFF range
