# Compare Sites - Integrity Bypass Patch Strategy

## Primary Bypass Target: 0x01D0

### Original Code
- **Address**: 0x01D0
- **Original Bytes**: `70 03 02 A4 BD`
- **Instruction**: `JNZ 0x01D6` (Jump if Not Zero to 0x01D6)
- **Context**: Multi-stage integrity check after 0x0BA5 validation

### Proposed Patch Options

#### Option 1: Invert Conditional (Recommended)
- **New Bytes**: `70 00 02 A4 BD`
- **Change**: `70 03` → `70 00`
- **Effect**: JNZ becomes JNZ to same location (no-op jump)
- **Risk**: Low - maintains instruction flow

#### Option 2: Short Jump Over
- **New Bytes**: `02 A4 BD 90 90`
- **Change**: Replace entire instruction with `LJMP 0x01A4BD`
- **Effect**: Unconditional jump over integrity check
- **Risk**: Medium - changes control flow significantly

### Disassembly Context
```
0x01C8: 90 0B A5 E0    MOVX A, @DPTR (read 0x0BA5)
0x01CC: 70 03          JNZ 0x01D1    (jump if A != 0)
0x01CE: 02 A4 BD       LJMP 0x01A4BD (fail path)
0x01D1: 90 0B 77 E0    MOVX A, @DPTR (read 0x0B77)
0x01D5: 14             DEC A
0x01D6: 60 3C          JZ 0x01F4     (jump if A == 0)
```

## Secondary Bypass Target: 0x01D6

### Original Code
- **Address**: 0x01D6
- **Original Bytes**: `60 3C`
- **Instruction**: `JZ 0x01F4` (Jump if Zero to 0x01F4)
- **Context**: OSD enable flag (0x0B77) validation

### Proposed Patch
- **New Bytes**: `60 00`
- **Change**: `60 3C` → `60 00`
- **Effect**: JZ becomes JZ to same location (no-op jump)
- **Risk**: Low - maintains instruction flow

## Patch Summary

### V6_BYPASS_ONLY Configuration
- **Primary Patch**: 0x01D0: `70 03` → `70 00`
- **Secondary Patch**: 0x01D6: `60 3C` → `60 00`
- **Total Changes**: 2 bytes
- **Effect**: Bypass integrity checks while maintaining USB functionality

### Risk Assessment
- **USB Bring-up**: ✅ Preserved (no changes to USB init code)
- **OSD Functionality**: ✅ Preserved (OSD writes remain intact)
- **System Stability**: ✅ Low risk (minimal instruction changes)
- **Detection**: ⚠️ Medium (integrity checks bypassed but not removed)

### Verification Steps
1. **Pre-patch**: Verify bytes at 0x01D0 = `70 03`, 0x01D6 = `60 3C`
2. **Post-patch**: Verify bytes at 0x01D0 = `70 00`, 0x01D6 = `60 00`
3. **Functionality**: Confirm USB enumeration and OSD control

## Implementation Notes

### File Offsets
- **0x01D0**: File offset 0x01D0
- **0x01D6**: File offset 0x01D6

### Displacement Analysis
- **0x01D0 JNZ**: Original displacement 0x03, new displacement 0x00
- **0x01D6 JZ**: Original displacement 0x3C, new displacement 0x00

### Backup Strategy
- **Original Bytes**: `70 03 60 3C`
- **Patched Bytes**: `70 00 60 00`
- **Restore**: Simple byte replacement if issues arise

## Stop Point for Operator

**V6_BYPASS_ONLY is ready for flash testing.**
- **Patch Size**: 2 bytes
- **Risk Level**: Low
- **Expected Result**: USB enumeration with OSD control, integrity checks bypassed
- **Next Phase**: Hardware testing and USB Device Tree analysis
