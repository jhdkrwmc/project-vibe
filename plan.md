# SN9C292B Firmware OSD Patch Project - Plan

## Mission Status: INTEGRITY BYPASS DISCOVERED - READY FOR FLASH TESTING

### Completed Steps
Done: IDA MCP connection established and verified
Done: Database metadata retrieved (128KB firmware, 8032 core)
Done: Firmware tail analysis - confirmed FF-padding, no footer checksum
Done: OSD sites reconfirmed - 4 sites at 0x04D0, 0x0AC4, 0x0AFE, 0x4522
Done: CRC/compare hunt completed - high-scoring candidate at 0x236D
Done: Multi-stage integrity check discovered at 0x01C0-0x01F0
Done: V6_BYPASS_ONLY patch strategy prepared - 2-byte conditional bypass

### Current Status
**STOP POINT REACHED**: V6_BYPASS_ONLY patch is ready for operator flash testing.

**Patch Details**:
- **Primary Target**: 0x01D0: `70 03` → `70 00` (JNZ no-op)
- **Secondary Target**: 0x01D6: `60 3C` → `60 00` (JZ no-op)
- **Total Changes**: 2 bytes
- **Risk Level**: Low
- **Expected Result**: USB enumeration with OSD control, integrity checks bypassed

### Next Phase (After Flash Testing)
1. Flash V6_BYPASS_ONLY firmware
2. USB Device Tree analysis
3. OSD functionality verification
4. Results documentation

### Technical Findings
- **OSD Pattern**: `90 0B ?? 74 01 F0` confirmed at all 4 sites
- **Integrity Check**: Multi-stage validation at 0x01C0-0x01F0
- **Bypass Strategy**: Conditional jump inversion (minimal risk)
- **CRC Candidate**: Function 0x236D (score 4/4) - secondary target for future analysis

### Files Generated
- `logs/step01_sanity.md` - Connection and database status
- `logs/step01_tail.txt` - Firmware tail bytes (all FF)
- `intel/osd_sites.json` - OSD enable sequences
- `intel/osd_sites.md` - OSD sites documentation
- `intel/crc_candidates.json` - CRC analysis results
- `intel/crc_proof.md` - Integrity check evidence
- `intel/compare_sites.md` - Patch strategy and risk analysis