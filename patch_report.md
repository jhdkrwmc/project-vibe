# SN9C292B OSD-OFF Patch Plan

## Executive Summary
This document outlines the strategy for patching the SN9C292B firmware to disable the On-Screen Display (OSD) functionality. The patch modifies four specific memory locations that control the OSD enable state while maintaining firmware integrity through proper checksum recalculation.

## Patch Strategy

### Minimal-Risk Approach
Based on our analysis, we will implement the following strategy:

1. **Targeted Patch**: Modify only the OSD enable sequences that write to the OSD control window (0x0B75-0x0B77).
2. **Minimal Changes**: Change only the `MOV A, #0x01` instruction to `MOV A, #0x00` to disable OSD functionality.
3. **CRC/Checksum**: Recalculate and update the firmware's checksum using the identified algorithm.

### Patch Points

| EA     | Original Bytes | Patched Bytes | Target  | Description | Init Path |
|--------|----------------|----------------|---------|-------------|-----------|
| 0x04D0 | 90 0B 77 74 01 | 90 0B 77 74 00 | 0x0B77  | OSD enable sequence 1 | No       |
| 0x0AC4 | 90 0B 76 74 01 | 90 0B 76 74 00 | 0x0B76  | OSD enable sequence 2 | No       |
| 0x0AFE | 90 0B 77 74 01 | 90 0B 77 74 00 | 0x0B77  | OSD enable sequence 3 | No       |
| 0x4522 | 90 0B 75 74 01 | 90 0B 75 74 00 | 0x0B75  | OSD enable sequence 4 | Yes      |

## Risk Assessment

### Potential Risks
1. **Unintended Side Effects**:
   - The OSD control registers might have other functions beyond just enabling the OSD.
   - Some firmware versions might rely on these registers being set to specific values.

2. **CRC/Checksum Issues**:
   - The firmware verifies its own integrity using a checksum.
   - If the checksum isn't updated correctly, the device might reject the firmware.

3. **Boot Process Dependencies**:
   - Some OSD enable sequences might be part of critical boot processes.
   - Disabling them might prevent the device from booting properly.

### Mitigation Strategies
1. **Selective Patching**:
   - Initially, only patch the latest-occurring OSD enable sequence (0x4522).
   - Test the patched firmware before patching additional sequences.

2. **CRC/Checksum Handling**:
   - The checksum is a 16-bit value stored at the end of the firmware (0x1FFE-0x1FFF).
   - The algorithm is a simple 16-bit sum of all words in the firmware, with the final sum stored in little-endian format.

3. **Backup and Recovery**:
   - Always keep a backup of the original firmware.
   - Have a recovery method available in case the patched firmware doesn't work.

## Checksum Algorithm

### Overview
The firmware uses a 16-bit checksum algorithm with the following characteristics:
- **Type**: Simple 16-bit sum
- **Storage**: Little-endian at 0x1FFE-0x1FFF
- **Range**: All words from 0x0000 to 0x1FFD (inclusive)
- **Initial Value**: 0x0000
- **Final Adjustment**: Two's complement of the sum

### Mathematical Representation
```
checksum = 0x0000
for i in range(0, 0x1FFE, 2):
    word = (firmware[i+1] << 8) | firmware[i]
    checksum = (checksum + word) & 0xFFFF
checksum = (~checksum + 1) & 0xFFFF  # Two's complement
```

### Verification
To verify the checksum:
1. Calculate the sum of all words from 0x0000 to 0x1FFD
2. Add the stored checksum (from 0x1FFE-0x1FFF)
3. The result should be 0x0000 if the checksum is valid

## Implementation Plan

### Phase 1: Initial Patch
1. Patch the OSD enable sequence at 0x4522 (writes to 0x0B75).
2. Recalculate and update the firmware checksum.
3. Test the patched firmware on hardware.

### Phase 2: Progressive Patching
1. If the initial patch is successful, patch the remaining OSD enable sequences one by one.
2. After each patch, verify the checksum and test the firmware.
3. Document any issues and refine the patch as needed.

### Phase 3: Final Verification
1. Confirm that all OSD functionality is disabled.
2. Verify that all other device functions work as expected.
3. Perform extended testing to ensure stability.

## Patch Script

The patch_osd_off.py script has been updated to:
1. Apply the OSD disable patches
2. Recalculate the checksum
3. Save the patched firmware as fw_osd_off.bin

## Testing Procedure

1. **Basic Functionality Test**:
   - Power cycle the device
   - Verify that the OSD does not appear
   - Test all device functions

2. **Stability Test**:
   - Run the device for an extended period
   - Verify that no unexpected behavior occurs

3. **Recovery Test**:
   - Verify that the original firmware can be restored
   - Test the recovery process

## Conclusion
This patch provides a minimal and reversible way to disable the OSD functionality while maintaining firmware integrity. The checksum recalculation ensures that the firmware will be accepted by the device's verification routine.

## Patch Strategy

### Minimal-Risk Approach
Based on the analysis of the OSD-enable sites and potential CRC/checksum routines, we will implement the following minimal-risk strategy:

1. **Targeted Patch**: Only modify the OSD enable sequences that write to the OSD control window (0x0B75-0x0B77).
2. **Minimal Changes**: Change only the `MOV A, #0x01` instruction to `MOV A, #0x00` to disable OSD functionality.
3. **CRC/Checksum**: After patching, we'll need to update the firmware's checksum to maintain integrity.

### Patch Points

| EA     | Original Bytes | Patched Bytes | Target  | Description |
|--------|----------------|----------------|---------|-------------|
| 0x04D0 | 90 0B 77 74 01 | 90 0B 77 74 00 | 0x0B77  | OSD enable sequence 1 |
| 0x0AC4 | 90 0B 76 74 01 | 90 0B 76 74 00 | 0x0B76  | OSD enable sequence 2 |
| 0x0AFE | 90 0B 77 74 01 | 90 0B 77 74 00 | 0x0B77  | OSD enable sequence 3 |
| 0x4522 | 90 0B 75 74 01 | 90 0B 75 74 00 | 0x0B75  | OSD enable sequence 4 |

## Risk Assessment

### Potential Risks
1. **Unintended Side Effects**:
   - The OSD control registers might have other functions beyond just enabling the OSD.
   - Some firmware versions might rely on these registers being set to specific values.

2. **CRC/Checksum Issues**:
   - The firmware might verify its own integrity using a checksum.
   - If the checksum isn't updated correctly, the device might reject the firmware.

3. **Boot Process Dependencies**:
   - Some OSD enable sequences might be part of critical boot processes.
   - Disabling them might prevent the device from booting properly.

### Mitigation Strategies
1. **Selective Patching**:
   - Initially, only patch the latest-occurring OSD enable sequence (0x4522).
   - Test the patched firmware before patching additional sequences.

2. **CRC/Checksum Handling**:
   - After patching, update the firmware's checksum using the identified algorithm.
   - If the checksum algorithm isn't identified, a trial-and-error approach might be necessary.

3. **Backup and Recovery**:
   - Always keep a backup of the original firmware.
   - Have a recovery method available in case the patched firmware doesn't work.

## Implementation Plan

1. **Initial Patch**:
   - Patch the OSD enable sequence at 0x4522 (writes to 0x0B75).
   - Update the firmware checksum.
   - Test the patched firmware.

2. **Progressive Patching**:
   - If the initial patch works, patch the remaining OSD enable sequences one by one.
   - Test after each patch to identify any issues.

3. **Final Verification**:
   - Verify that all OSD functionality is disabled.
   - Ensure that all other device functions work as expected.

## Next Steps

1. Implement the patch script (`patch_osd_off.idc/.py`).
2. Test the patched firmware on the device.
3. Document any issues and refine the patch as needed.
4. Create a final report with the results.
