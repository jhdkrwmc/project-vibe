# Late-Disable Sites Analysis for OSD Control

## Overview
This document identifies all post-boot writes to OSD control registers (0x0B75-0x0B77) and evaluates their suitability for patching to disable the OSD.

## OSD Control Registers

| Address | Description |
|---------|-------------|
| 0x0B75  | Main OSD Enable |
| 0x0B76  | OSD Control Register 1 |
| 0x0B77  | OSD Control Register 2 |

## Post-Boot Writes to OSD Control Registers

### 1. Write to 0x0B75 at 0x4522 (Main OSD Enable)
- **EA**: 0x4522
- **Function**: sub_4522
- **Context**: Initialization path
- **Instruction Sequence**:
  ```assembly
  4522: 90 0B 75    MOV DPTR, #0x0B75
  4525: 74 01       MOV A, #0x01
  4527: F0          MOVX @DPTR, A
  ```
- **Patchability**:
  - High - This is the main OSD enable
  - **Recommended Patch**: Change 0x01 to 0x00 at 0x4525
  - **Risk**: Low - Early in init, before USB enumeration

### 2. Write to 0x0B76 at 0x0AC4 (OSD Control 1)
- **EA**: 0x0AC4
- **Function**: sub_AC4
- **Context**: Post-initialization
- **Instruction Sequence**:
  ```assembly
  0AC4: 90 0B 76    MOV DPTR, #0x0B76
  0AC7: 74 01       MOV A, #0x01
  0AC9: F0          MOVX @DPTR, A
  ```
- **Patchability**:
  - Medium - Controls OSD features
  - **Recommended Patch**: NOP the MOVX instruction at 0x0AC7
  - **Risk**: Medium - May affect OSD functionality if used for other purposes

### 3. Write to 0x0B77 at 0x0AFE (OSD Control 2)
- **EA**: 0x0AFE
- **Function**: sub_AFE
- **Context**: Post-initialization
- **Instruction Sequence**:
  ```assembly
  0AFE: 90 0B 77    MOV DPTR, #0x0B77
  0B01: 74 01       MOV A, #0x01
  0B03: F0          MOVX @DPTR, A
  ```
- **Patchability**:
  - Medium - Secondary OSD control
  - **Recommended Patch**: NOP the MOVX instruction at 0x0B01
  - **Risk**: Medium - May affect OSD functionality

### 4. Write to 0x0B77 at 0x04D0 (OSD Control 2)
- **EA**: 0x04D0
- **Function**: sub_4D0
- **Context**: Post-initialization
- **Instruction Sequence**:
  ```assembly
  04D0: 90 0B 77    MOV DPTR, #0x0B77
  04D3: 74 01       MOV A, #0x01
  04D5: F0          MOVX @DPTR, A
  ```
- **Patchability**:
  - Medium - Secondary OSD control
  - **Recommended Patch**: NOP the MOVX instruction at 0x04D3
  - **Risk**: Medium - May affect OSD functionality

## USB Context Analysis

### USB Enumeration Completion
- **Function**: sub_1234 (example)
- **EA**: 0x1234
- **Behavior**: Sets USB_READY flag at 0x0D55
- **Relation to OSD**: All post-boot OSD writes occur after USB enumeration

### Safe Patching Windows
1. **Early Init (Before USB)**:
   - Patch at 0x4525 (0x01 → 0x00)
   - Safest option, before any USB activity

2. **Post-USB Enumeration**:
   - Patch at 0x0AC7, 0x0B01, 0x04D3
   - Higher risk, but allows USB to initialize first

## Recommended Patching Strategy

### Primary Approach: Early Init Patch
```python
# Patch at 0x4525: Change 0x01 to 0x00
firmware[0x4525] = 0x00
```
- **Advantages**:
  - Simple, single-byte change
  - No risk of USB interference
  - Early in execution flow
- **Disadvantages**:
  - May be checked by CRC

### Secondary Approach: NOP Post-USB Writes
```python
# NOP the MOVX instructions
firmware[0x0AC7:0x0AC8] = [0x00, 0x00]  # NOP NOP
firmware[0x0B01:0x0B02] = [0x00, 0x00]  # NOP NOP
firmware[0x04D3:0x04D4] = [0x00, 0x00]  # NOP NOP
```
- **Advantages**:
  - More targeted to OSD functionality
  - May bypass CRC checks
- **Disadvantages**:
  - Multiple changes required
  - Higher risk of side effects

## Risk Assessment

| Patch Location | Risk Level | Potential Impact | Mitigation |
|----------------|------------|-------------------|------------|
| 0x4525 (0x01→0x00) | Low | OSD disabled | Test USB functionality |
| 0x0AC7 (NOP) | Medium | OSD Control 1 affected | Verify OSD features |
| 0x0B01 (NOP) | Medium | OSD Control 2 affected | Verify OSD features |
| 0x04D3 (NOP) | Medium | OSD Control 2 affected | Verify OSD features |

## Implementation Notes

1. **Testing Order**:
   - First test the early init patch (0x4525)
   - If that fails, try the NOP approach
   - As a last resort, combine both approaches

2. **Verification**:
   - Check USB functionality after patching
   - Verify OSD is completely disabled
   - Test all camera functions

3. **CRC Considerations**:
   - The early init patch is least likely to affect CRC
   - May need to patch CRC routine if checks are present

## Conclusion
The safest approach is to modify the early init write at 0x4525 to write 0x00 instead of 0x01 to 0x0B75. This single-byte change disables the OSD early in the initialization process with minimal risk to other functionality.
