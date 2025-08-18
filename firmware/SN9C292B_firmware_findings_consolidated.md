### SN9C292B Firmware — Consolidated Findings (OSD, Integrity, Dispatch)

- Build scope: 8051 firmware image (128KB). Analysis in IDA.
- Targets: OSD flags 0xE24..0xE27 persistence, integrity/CRC gating, computed-dispatch map.

### OSD flags and writers (XDATA 0xE24..0xE27)

- Confirmed writer/helper and handler sites:
  - Helper: `0xBB73` writes to `0xE24` (with `#0xFF`, then increments DPTR)
  - Handler subpaths set DPTR to `0xE24` and write sequences; `0xAE74` targets `0xE27`.

Disassembly (window around 0xADBE/0xADCD/0xADD7/0xADFD/0xAE74):

```29:0xADB0..0xAEB3
0xADBE: mov DPTR,#0xE24
0xADC1: ljmp 0xAE3D
0xADCD: mov DPTR,#0xE24
0xADD0: ljmp 0xAE69
0xADD7: mov DPTR,#0xE24
0xADE0: lcall 0xBB73
...
0xADFD: mov DPTR,#0xE24
...
0xAE74: mov DPTR,#0xE27
0xAE77: lcall 0xBB63
0xAE83: movx @DPTR,A ; OSD bit update at 0xE27
```

Helper (0xBB60 region):

```15:0xBB60..0xBB7F
0xBB73: mov DPTR,#0xE24
0xBB76: mov A,#0xFF
0xBB78: movx @DPTR,A
0xBB79: inc DPTR
0xBB7A: ret
```

- Global search for `mov DPTR,#0xE24..0xE27` outside the handler family returned only the above sites. No reset/boot writers.
- Neighbor early-init writers hit `0xE0xx` ranges (0xE04, 0xE06, 0xE0F, 0xE2C, 0xE42–0xE48, etc.) but never increment into `0xE24`. No incremental loop transitions into `0xE24` observed.

Xrefs to `0xBB73`: only handler-family callers (e.g., `0xADE0`, `0xAE06`, `0xAE22`, `0xAE32`, `0xAE4E`, `0xAE5E`). No reset callers.

### Reset / early-init fan-out

Checked: `0xAA04, 0xAA0B, 0xAA2B, 0xAA3A, 0xB88A, 0xB930, 0xB932, 0xC56A, 0xC632, 0xC63C, 0xC641, 0xC646`.

- Summary per site: DPTR to 0x0E2x? MOVX writes? Branches to hold loops?

- 0xAA04/0xAA0B/0xAA2B/0xAA3A: MOVX to 0x52F/0x54B/0x5C5 and related; no DPTR=0x0E2x; no hold-loop branches.

```20:0xAA04..0xAA51
0xAA37: mov DPTR,#0x52F
0xAA3A: movx A,@DPTR ; add/store
...
0xAA54: mov DPTR,#0x54B
...
0xAA77: mov DPTR,#0x5C5
```

- 0xB88A..: service/control of other XDATA; no 0xE2x; no hold loops.

```16:0xB88A..0xB8A5
0xB890: mov DPTR,#0xDC3
...
0xB89B: mov DPTR,#0x52E
... (no 0xE2x)
```

- 0xB930/0xB932: small copy/interrupt toggling; no 0xE2x; no hold-loop.

```12:0xB930..0xB93D
0xB937: mov DPTR,#0x548 ; not E2x
```

- 0xC56A/0xC632/0xC63C/0xC641/0xC646: parser/IO/config-ish flows; heavy MOVX but not to 0xE24..0xE27; no hold-loop.

```24:0xC56A..0xC58D
0xC56A: movx A,@DPTR
... DPTR #0xBCx / tables
```

Conclusion: no early-init writers to OSD quartet; OSD is not set by reset-time bulk XDATA writers.

### Hold/fail sinks & gates

Confirmed sink self-loops:

```4:0x29D8..0x29DE
0x29D8: sjmp 0x29D8
```

```4:0x3360..0x3365
0x3362: sjmp 0x3362
```

```2:0xF018..0xF019
0xF018: sjmp 0xF018
```

```2:0xF57B..0xF57C
0xF57B: sjmp 0xF57B
```

Dispatcher at 0x29D5:

```6:0x29D3..0x29D8
0x29D3: .byte 90 10 73   ; mov DPTR,#0x1073 (encoded)
0x29D5: jmp @A+DPTR
```

- Full 0x1073 island decoded to CSV: `firmware/branch_island_0x1073_map.csv`.
- Multiple entries are SJMP/LJMP/LCALL; at least one entry lands in sinks (by virtue of code paths). Notably, this table is not a plain series of LJMPs; it’s intermixed code fragments and near jumps.

### Integrity unit near 0xF01A

- Behavior: manipulates `0xE18/0xE19/0xE1C`; selects table at `0x09CE..` depending on a flag in `0xE20`; on failure, can fall into `0xF018` sink.

```30:0xF01A..0xF07F
0xF01A: mov DPTR,#0xE1C
...
0xF040: mov DPTR,#0xE20 ; gate
...
0xF047/0xF04C/0xF051: DPTR <- {0x09CE,0x09CF,0x09D0}
...
0xF07F: mov DPTR,#0xE1C ; alternate path
```

- Flags: sets bytes at `0x98F` and `0x99B` on success paths.
- Data consumed at `0x09CE` (first 96 bytes):

```16:0x09CE..(+96)
raw: 08 f0 22 c2 af af 50 ae 4f ad 4e ac 4d 90 0b a8 12 14 a8 d2 af 90 11 00 e0 54 fc 22 90 11 01 e0 54 fe f0 90 10 61 e0 54 fd f0 74 11 90 0b 76 f0 90 10 03 e0 22 90 10 61 a3 e0 90 11 cb f0 ...
```

Interpretation: firmware-internal config/guard bytes; used to tweak sums and branches before committing to success; failure can jump to `0xF018`.

### Config/script loaders (CJNE #0x9A parser family)

Representative sites show CJNE A,#0x9A followed by MOVC/MOVX table access and writes to various XDATA (0xE4x/0xE8x/0x0C1x/0x16xx), but not the OSD quartet.

- `0xC38E`:

```8:0xC38E..0xC396
cjne A,#0x9A, ...
lcall 0xB2CA
```

- `0xC4DF`:

```10:0xC4DF..0xC4F1
cjne A,#0x9A, ...
lcall 0xB2CA
... jmp @A+DPTR via 0xA4FB
```

- `0xC9B6` / `0xCA78` / `0xCBE9`: similar tag parse and subcmd branches; tables in `0xAC04..`, `0xAB16..` etc., writing to `0xC1x`, `0x168x`, `0xE80`, `0x240` ranges.

Conclusion: these are boot/runtime script parsers but do not hydrate `0xE24..0xE27` defaults. Marked “not OSD quartet loader”.

### Config-copy candidates

`0xF5B3..0xF5BD` writes into `0xED2..0xED4` and uses MOVC reads at `0xF5D1/0xF5D5`; acts like a parameter updater, not a bulk hydrator of 0xE00..0xE27.

```22:0xF5B3..0xF5C3
mov DPTR,#0xED2
mov A,R6 ; R6/R7 -> ED2/ED3
...
mov DPTR,#0xED4 ; scale select
... movc A,@A+DPTR
```

- No evidence of a MOVC→INC DPTR→MOVX loop copying a block into `0xE00..0xE27` in reset/init.
- Therefore, OSD defaults are not bulk-copied at boot in this build; runtime handler touches only.

### TLV 0x9A 0x04 reality check

- No contiguous literal `9A 04` TLV found in 0x0000–0x1FFFF.
- Tags appear via parser comparisons (CJNE #0x9A / immediate subcmd compares) rather than static TLV tables.

Evidence windows:

```3:0xC38E..0xC394
B4 9A 05 ; cjne A,#0x9A
```

```3:0xCA78..0xCA7E
B4 9A 05 ; cjne A,#0x9A
```

### Checksum/integrity footer

- Last 32 bytes of image are all `FF`.
- Footer at `0x1FFE..0x1FFF` (LE16) = `0xFFFF`.
- Computed sums (over the file `firmware_backup_base.bin`):
  - Sum over 0x0000..0x1FFD: `0x81BB`
  - Sum over 0x0000..0x1FFF: `0x83B9`
- Two’s-complement zero-sum would require footer = `(-sum_0..1FFD) & 0xFFFF = 0x7E45`, not `0xFFFF`. Current footer does not zero the sum.

### Cross-gen OSD mapping sanity

- Search for classic OSD addresses like `0x0B75..0x0B77` not present as DPTR immediates in this build.
- Reaffirmed OSD quartet here is `0xE24..0xE27`.

### XDATA Writer Atlas (early init)

| Site Addr | DPTR Base(s)           | Pattern        | Touched Range        | Reaches E24? |
|-----------|-------------------------|----------------|----------------------|--------------|
| 0xAA04    | 0x52F,0x54B,0x5C5       | E0/24/F0       | low XDATA service    | No           |
| 0xAA0B    | 0x52F,0x54B,0x5C5       | E0/24/F0       | low XDATA service    | No           |
| 0xAA2B    | 0x52F                   | E0/24/F0       | low XDATA            | No           |
| 0xAA3A    | 0x52F                   | E0/24/F0       | low XDATA            | No           |
| 0xB88A    | 0x52E,0x5CE/CF          | F0 writes      | status/reg           | No           |
| 0xB930    | 0x548                   | E0/A3/F0       | misc                 | No           |
| 0xC56A    | 0xBCx, tables           | MOVC/MOVX      | config pages         | No           |
| 0xC632    | 0xC11/0x158x            | MOVX writes    | reg/config           | No           |

### Conclusions

- Plan A (config/defaults patch): Not supported by evidence for a bulk loader into `0xE24..0xE27`. The OSD quartet is not hydrated at boot by a MOVC→MOVX copy.
- Plan B (gate flip): The `0x1073` dispatch island is mapped; gating and sinks confirmed. However, safe single-byte flip locations affecting OSD at boot are not identified yet. More mapping needed to tie integrity to OSD write inhibition without entering sinks.
- Plan C (handler patch): Still last resort due to Code 10 risk. Handler family clearly writes OSD; patching here is high risk without checksum/integrity accommodation.

### Next Actions

- Capture XDATA snapshots pre/post the script runner to confirm any late-stage hydration into `0xE00..` region.
- Expand MOVC copy hunt beyond current candidates, including potential compressed or indexed copies, to 0xE2x.
- Use recovery-mode dumps and diffs across OSD-on/off states to locate any persistent defaults sector.
- Further decode the `0x1073` island usage paths that eventually route to sinks when integrity fails; identify low-risk branch flips in the same window.

### Appendix — Select hexdumps

- Dispatcher base bytes at `0x1073` (first 32 shown):

```16:0x1073..0x1082
A3 E0 90 11 CB F0 90 11 3E E0 44 08 F0 90 12 0E 12 0E E0  
```

- Integrity table window at `0x09CE` (first ~48 shown):

```16:0x09CE..(+) 
08 f0 22 c2 af af 50 ae 4f ad 4e ac 4d 90 0b a8 12 14 a8 d2 af 90 11 00 e0 54 fc 22 90 11 01 e0 54 fe f0 90 10 61 e0 54 fd f0 74 11 90 0b 76 f0
```
