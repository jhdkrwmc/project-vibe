# SN9C292B Firmware OSD Patch Project - Plan

## Mission Status: INTEGRITY CHECK BYPASS STRATEGY IDENTIFIED

### Previous Status (INCORRECT)
~~MISSION ACCOMPLISHED~~ - This was FALSE. All variants still fail with Code 10.

### Current Reality
**ALL firmware variants fail**: OSD-only, bypass, stage2, late-clear, early-bypass
**Pattern**: Device enumerates (0C45:6366) but fails to configure (Config=0)
**Root Cause**: Runtime integrity checks validate OSD register values before USB config

### Critical Discovery
**Multi-Stage Integrity Check at 0x1C0-0x240**:
- Checks 0x0F09 (USB status), 0x0BA5 (OSD data), 0x0B77 (OSD enable)
- Multiple conditional branches to failure paths (0xA4BD, 0xA32F)
- CTF function at 0x200+ validates 0x0B76 values (expects 0x01, 0x84)

**Checksum Analysis**:
- **Original firmware has INVALID checksum**: 0xC3A4 (not 0x0000)
- **Device doesn't use checksum validation** - uses runtime integrity checks instead
- **Previous checksum-based patches were unnecessary** - root cause is elsewhere

**Why Previous Patches Failed**:
1. OSD patches change 0x0B76/0x0B77 from 0x01 to 0x00
2. Integrity checks expect specific values (0x01, 0x84)
3. When values don't match, device branches to failure paths
4. USB configuration never completes

### New Strategy: Integrity Check Logic Patching
**Target**: Patch the integrity check logic to accept our OSD values
**Approach**: Change expected comparison values from 0x01 to 0x00
**Patches**:
- 0x244: `CJNE A,#01,+8` → `CJNE A,#00,+8`
- 0x260: `CJNE A,#0x84,+6` → `CJNE A,#0x00,+6`

### Next Steps
1. ✅ **COMPLETED**: Deep analysis using IDA Pro MCP
2. ✅ **COMPLETED**: Root cause identification (runtime integrity checks)
3. ✅ **COMPLETED**: Checksum myth debunked (original firmware invalid)
4. ✅ **COMPLETED**: New bypass strategy development
5. → **NEXT**: Test integrity bypass firmware (no checksum fix needed)
6. → **NEXT**: Verify USB configuration completes successfully

### Technical Achievements
- **OSD Pattern**: `90 0B ?? 74 01 F0` → `90 0B ?? 74 00 F0` at all 4 sites
- **Integrity Check**: Multi-stage validation at 0x1C0-0x01F0 (MAPPED)
- **CTF Function**: OSD validation logic at 0x200+ (DECODED)
- **Failure Paths**: 0xA4BD, 0xA32F, 0xA4A0 (IDENTIFIED)
- **Checksum Reality**: Original firmware has invalid checksum (0xC3A4) - not used for validation

### Files Generated
- `logs/20250812-2200_step04_deep_analysis.md` - Deep analysis results
- Previous analysis files remain valid for reference