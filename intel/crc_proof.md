# CRC/Integrity Check Analysis - Evidence Found

## High-Scoring CRC Candidate Function

### Function: 0x236D (Score: 4/4)
- **Address**: 0x236D - 0x2400
- **Features**: 
  - ✅ MOVC instruction present (score +2)
  - ✅ Bit manipulation operations (score +1) 
  - ✅ Compare and branch logic (score +1)
  - ✅ Loop structures (score +1)
- **Compare Site**: 0x2374
- **First 32 Bytes**: 12 FD 50 7E 01 EE C3 9F 50 4D 75 F0 07 EE 90 EE CE 12 15 7B E4 93 FD 90 0E 5C E0 FC ED 6C 70 34 75 F0 07

## Early Multi-Stage Check Discovery

### Location: 0x01C0-0x01D0
**Critical Pattern Found**: Multi-stage integrity check touching 0x0BA5, 0x0B77, and 0x0B76

**Memory Dump (0x01C0-0x01D0)**:
```
90 0F 09 EF F0 90 0F 09 E0 FF 70 09 90 0B A5 E0 70
03 02 A4 BD 90 0B 77 E0 14 60 3C 24 F0 70 03 02 A3
```

**Analysis**:
1. **Stage 1**: `90 0F 09 EF F0` - MOVX @DPTR, A to 0x0F09
2. **Stage 2**: `90 0B A5 E0 70 03 02 A4 BD` - Check 0x0BA5, conditional jump
3. **Stage 3**: `90 0B 77 E0 14 60 3C` - Check 0x0B77, conditional jump
4. **Stage 4**: `24 F0 70 03 02 A3` - Additional checks with conditional jumps

### Conditional Branch Analysis
- **0x01D0**: `70 03 02 A4 BD` - JNZ to 0x01D6 (conditional skip)
- **0x01D6**: `90 0B 77 E0 14 60 3C` - Check 0x0B77, JZ to 0x01F0
- **0x01F0**: `24 F0 70 03 02 A3` - Additional conditional logic

## Integrity Check Flow

### Multi-Stage Validation
1. **USB Ready Check**: 0x0F09 (likely USB status)
2. **OSD Zone 1**: 0x0BA5 (OSD character data)
3. **OSD Zone 2**: 0x0B77 (OSD enable flag)
4. **Additional Validation**: Multiple conditional branches

### Bypass Opportunities
- **Primary Target**: 0x01D0 conditional jump (JNZ)
- **Secondary Target**: 0x01D6 conditional jump (JZ)
- **Patch Strategy**: Invert conditional logic or short-jump over fail paths

## Risk Assessment

### High-Risk Areas
- **0x01D0**: Critical USB bring-up check
- **0x01D6**: OSD integrity validation
- **0x01F0**: Additional security layer

### Safe Patch Points
- **0x01D0**: Change `70 03` (JNZ) to `70 00` (JNZ to same location) or `02 A4 BD` (LJMP)
- **0x01D6**: Change `60 3C` (JZ) to `60 00` (JZ to same location)

## Next Steps

1. ✅ High-scoring CRC candidate identified (0x236D)
2. ✅ Multi-stage integrity check discovered (0x01C0-0x01F0)
3. ✅ Conditional branch analysis complete
4. → Prepare V6_BYPASS_ONLY patch strategy
5. → Document exact bytes and displacements
6. → Stop for operator flash decision
