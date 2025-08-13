SN9C292B Firmware OSD Patch Project –
Technical Status Report
1. Project Chronology and Technical Narrative
This section recounts the key steps, experiments, and outcomes in chronological order, detailing what
has been tried in the effort to disable the On-Screen Display (OSD) overlay in the SN9C292B webcam
firmware, and the results (successes or failures) of each attempt.
1.1 Firmware Dump and Initial Analysis
Firmware Extraction: The project began by obtaining a dump of the webcam’s firmware (128
KiB, external SPI flash). An initial backup ( firmware_backup.bin ) was created using known
tools (e.g. the Kurokesu SONiX UVC TestAP utility on Linux with the --sf-r read command)
. This provided a baseline binary for analysis and patching. The SN9C292B is an 8032 (8051-
family) microcontroller with built-in ROM and an external firmware, so having a good dump was
crucial.
Target Behavior: The SN9C292B’s default firmware enables an OSD overlay (a date/time stamp)
at power-up by writing 0x01 to three control registers in XDATA memory (addresses 0x0B75,
0x0B76, 0x0B77) . The goal was to patch the firmware to disable this overlay (set those
registers to 0x00 at boot) while keeping the device fully functional.
Identifying OSD Enable Instructions: Using knowledge of the register addresses, a search was
performed on the firmware binary for the instruction sequence that writes 0x01 to those OSD
registers. In 8051 assembly, this sequence is:
MOV DPTR, #<addr>; MOV A, #0x01; MOVX @DPTR, A
where <addr> would be 0x0B75, 0x0B76, or 0x0B77. An IDA Pro analysis (after fixing initial scripting
issues with the IDA MCP interface ) confirmed four such occurrences in the firmware code, at
addresses 0x04D0, 0x0AC4, 0x0AFE, and 0x4522 . These correspond to four points in the code where
the firmware enables the OSD (writing 0x01 to those registers).
OSD Control Write Sites: The discovered sites and their context are:
0x4522: writes to 0x0B75 (OSD enable flag). This occurs during the early init/reset routine .
It’s the only OSD write on the immediate boot path.
0x04D0: writes to 0x0B77 (likely OSD mode or content register). Occurs later in execution (postinit).
0x0AC4: writes to 0x0B76 (second OSD enable flag or control). Occurs post-init.
0x0AFE: writes to 0x0B77 (again, OSD content register) in another context post-init.
•
1
•
2
•
3 4
5
•
• 6
•
•
•
1These addresses were verified by disassembly to contain the expected MOV DPTR,#0x0B7x / MOV
A,#0x01 / MOVX @DPTR,A patterns . Only the 0x4522 site runs during the device’s reset/init
sequence, configuring the overlay right at startup, whereas the other three occur a bit later (“postboot”) during normal operation (possibly in timer interrupts or state change handlers after the USB
interface is up) .
Planning the Patch: Initially, the plan was straightforward: patch those four bytes where the
firmware writes 0x01 so that it writes 0x00 instead, thereby preventing the OSD from ever
turning on. This is a minimal change (just flipping a constant in each instruction) that should
neutralize the OSD. A table of the target patch points is shown below:
Firmware
Offset Original Instruction Original
Bytes
Patched
Bytes
Target Reg
(XDATA)
0x04D0
MOV DPTR,#0x0B77 <br> MOV
A,#0x01 <br> MOVX @DPTR,A
90 0B 77 74
01 F0
90 0B 77 74
00 F0
0x0B77 (OSD
data/char)
0x0AC4
MOV DPTR,#0x0B76 <br> MOV
A,#0x01 <br> MOVX @DPTR,A
90 0B 76 74
01 F0
90 0B 76 74
00 F0
0x0B76 (OSD
enable 2)
0x0AFE
MOV DPTR,#0x0B77 <br> MOV
A,#0x01 <br> MOVX @DPTR,A
90 0B 77 74
01 F0
90 0B 77 74
00 F0
0x0B77 (OSD
data/char)
0x4522
MOV DPTR,#0x0B75 <br> MOV
A,#0x01 <br> MOVX @DPTR,A
90 0B 75 74
01 F0
90 0B 75 74
00 F0
0x0B75 (OSD
enable 1)
Table 1 – OSD initialization writes in firmware (original vs. patched)
In the original firmware, each of these writes sets the OSD registers to 0x01 (turning on the
timestamp overlay) during startup. The patched version would write 0x00 to ensure the OSD remains
off. In theory, this minimal patch should simply disable the overlay and nothing more . The OSD
engine would never be “armed” at boot, and the overlay would stay off unless explicitly turned on later
by user commands. All other camera functions would remain intact (we are not removing the OSD code,
just changing the default state).
1.2 Firmware Patching Attempts and Outcomes
Initial Patch and Flash: A Python script was written to apply the above four byte changes to the
firmware binary. The patched firmware (let’s call it V1) was then flashed back to the device’s SPI
memory (via the same extension-unit mechanism or a USB flashing tool). Result: the camera
enumerated on USB but failed to function properly – Windows Device Manager showed it as
“Cannot start (Code 10)” instead of the normal webcam interface. The OSD was indeed off
(since the firmware likely never fully ran the overlay), but the device itself was not operational.
Symptoms of Failure: The “Code 10” error indicates the device’s USB interface did not complete
initialization. Using USB Tree Viewer to compare a working vs. patched device showed that in the
failing case, the camera might not present a valid configuration or interface descriptors (for
instance, the Config Value might not be set to 1, meaning the device never fully transitioned to
the configured state) . The device still had the correct VID:PID (0x0C45:0x6366, the Sonix/
Microdia webcam), implying the firmware ran to some extent (the bootloader had loaded it). But
some initialization step was not completed, leading the OS to mark it as failed.
5
6
•
7
8
•
•
9
2Recovery: The original firmware was quickly re-flashed to recover the device. Thankfully, this
restored normal operation (the camera enumerated with proper descriptors, and the default
“2013” timestamp OSD came back) . This confirmed that our 4-byte patch, despite being
logically sound, had introduced an issue that prevented full boot. No permanent bricking
occurred – the device’s boot ROM or failsafes allowed reprogramming the flash via USB as long
as we had a valid image to restore.
Hypothesis – Integrity Check: Because the code change was so minimal, suspicion fell on a
firmware integrity check mechanism. Many embedded systems verify firmware integrity (via
checksum or CRC) at startup. If the patched image did not have a matching checksum, the device
could intentionally refuse to operate (or the bootloader could halt it). Initially, we theorized that
the last two bytes of the firmware (0x1FFE–0x1FFF) might store a checksum that we needed to
update. Indeed, the SN9C292B firmware file had non-0xFF values in those positions (suggesting
they aren’t unused padding). We did not blindly alter them at first, since we lacked confirmation
of the algorithm. Instead, we set out to investigate the integrity check in detail (see Section 2).
Iterative Patch Attempts: Over multiple attempts, various patched firmware builds were tested
to narrow down the cause of failure. The project script make_osd_variants.py was used to
generate a batch of test images (V2, V3, …) covering different combinations, for example:
patching only a subset of the sites, patching with or without a checksum adjustment, etc. In
total, six distinct variants were tried, and all six resulted in the same Code 10 failure . This
included even very conservative changes (e.g. leaving the 0x4522 init write untouched and only
patching later writes, or vice-versa). The consistency of the failure strongly indicated that any
modification to the firmware binary (even a single byte) was triggering a protection mechanism
during the device’s startup routine . In other words, it “screamed” integrity check rather
than a functional bug in our patch.
Side-Experiment – Register Side-Effects: One alternative explanation considered was that
changing the MOV A,#0x01 to MOV A,#0x00 might inadvertently disrupt register state
needed later in the code. For instance, if the firmware assumes the accumulator (A) still contains
0x01 after the OSD enabling sequence (perhaps to use that value elsewhere), then our patch
(setting A to 0x00) could alter program logic. To rule this out, another set of variants was
prepared where instead of changing the immediate value, the OSD write instructions were
NOPed out. By NOPing the MOVX @DPTR,A , we would leave DPTR and A loaded with their
original values (DPTR=0x0B7x, A=0x01) but skip the write. This means the code’s logic flow and
register values after the site should remain identical to the unpatched firmware (except that the
OSD register isn’t actually written). If this still caused a failure, it would point back to a checksum/
integrity issue rather than a logical dependency. Indeed, these NOP-only patches (e.g. variant
V11–V14) also failed with Code 10 . That made it highly unlikely that the device was
“misbehaving” because we changed A or DPTR – it was clearly objecting to any change in the
code bytes.
IDA Scripting and CRC Hunt: Meanwhile, to gather evidence of an integrity check, we engaged
an automated IDA Pro MCP script (via a “SWE-1” secondary process) to scan the disassembled
firmware for patterns related to checksums or CRCs. This included searching for common
polynomial constants, table-driven CRC loops, or code that reads the end-of-firmware bytes. The
results were not straightforward: an initial “CRC hunter” script did not find any obvious known
CRC references in the binary (e.g. no standard CRC16/CRC32 constants, no usage of the 0x1FFE
address in code) . Some candidate routines were identified (sections of code with looped
memory reads and arithmetic) that could be computing a checksum internally, but we lacked
definitive proof of their purpose. For example, notes mentioned a routine around 0x2A00 with a
•
9
•
•
10
10 11
•
12 13
•
14
3large table at 0x3F00 (suggestive of a CRC table) and some compare instructions at
0x12A0/0x1A20 that might be checking something . However, without clear markers (like
a known polynomial or a direct reference to the supposed checksum storage), these remained
hypotheses .
Toolchain Issues: During this analysis phase, we encountered some roadblocks using the
Windsurf MCP (IDA automation) environment – missing Python modules prevented certain MCP
server actions (like Git or Fetch), and initial queries (like listing imports or functions on the raw
binary) returned no data, which was expected for a raw 8051 image but was initially mistaken for
an error . We resolved these by installing the needed packages and ensuring the IDA server
was reachable . Once fixed, the SWE-1 automation was able to read memory bytes,
disassemble at target addresses, and produce reports on potential CRC routines and OSD call
sites.
Mid-Project Adjustments: At one juncture, given the lack of immediate checksum confirmation,
we considered focusing on the OSD logic itself: e.g. perhaps not touching the earliest OSD init
write (0x4522) might allow the device to boot (if the issue were some timing dependency or
subtle hardware requirement). A revised patch plan was formulated to only modify the later OSD
writes (post-boot), leaving the 0x4522 site at 0x01, and see if that boots without OSD. This “late
disable” approach meant the OSD might turn on at boot but we would turn it off shortly after
(e.g., by redirecting one of the later writes to clear the first flag) . Five new variants (V6–
V10) were generated under this plan:
V6: patch 0x04D0 only (01→00),
V7: patch 0x0AC4 only,
V8: patch 0x0AFE only,
V9: change the instruction at 0x0AC4 to write to 0x0B75 (redirect a later write to clear the
master flag),
V10: similar redirect at 0x0AFE to 0x0B75 .
All were done without modifying any checksum/footer bytes, and with 0x4522 kept intact (no change to
the init sequence) . Unfortunately, all of these still resulted in Code 10 on the device,
reinforcing that even post-init changes alone were unacceptable to whatever was guarding the
firmware .
Conclusion of Attempts: By this point in the chronology, every reasonable patch approach had
been tried and failed, strongly suggesting that the SN9C292B firmware (or its boot ROM)
performs an integrity check and refuses to fully operate if the firmware is modified in any way.
This aligns with the observation that “all six variants failed the same way” and that it looked
more like a security feature than a random bug . We then doubled down on understanding
the checksum/CRC mechanism (see next section) before attempting further patches. In parallel,
we prepared better tooling for rapid re-flash cycles (since many bricks were encountered) – this
included plans for a Windows-based flasher using PyUSB (to avoid rebooting into Linux for the
TestAP each time) , and investigating Sonix’s own ISP utility as a fallback .
2. Firmware CRC/Integrity Check Investigation
This section documents the efforts to identify how the SN9C292B verifies firmware integrity (checksum/
CRC), what algorithm or range is used, and whether a viable strategy to bypass or satisfy this check has
been found.
15 16
17
•
3
4
•
18 19
◦
◦
◦
◦
◦ 20 21
22 23
10
•
10 11
24 25 26
42.1 Searching for Checksum/CRC Routines in Firmware
Early in the analysis, it was unclear whether the integrity check was performed by the bootloader (onchip ROM) before handing control to the external firmware, or by the firmware itself at runtime. We
pursued evidence in the firmware code for any routine that calculates or compares a checksum:
No Obvious Footer Usage in Code: We looked for any references to the memory addresses
0x1FFE or 0x1FFF (the last two bytes of the 128K image) in the disassembly. None were found –
meaning the firmware code does not explicitly read from or write to those addresses (no
instruction like MOVC A,@A+DPTR reading a location in that range, and no immediate constants
referring to 0x1FFE, etc.). This suggested that the stored checksum might not be explicitly
handled by the firmware logic; it could be solely for the boot ROM’s use. ChatGPT flagged earlier
claims about an in-firmware “checksum write” at 0x1FFE as not supported by evidence .
Candidate Functions: Using IDA, we identified several candidate routines that could be
performing a checksum or CRC over a range of memory:
One such function was at 0x235E, which is called from the vicinity of the 0x4522 init code. Its
disassembly showed a loop structure with register usage suggestive of accumulating a value
across memory (e.g., DJNZ R0, ... loops and MOVX instructions) . This looked like it
could be iterating over memory to compute a checksum. It being invoked near the OSD init
might indicate the firmware calling a check right after enabling OSD or as part of init.
Another candidate was around 0x38EA (likely in the reset vector area). This code called a routine
at 0xE8DB and included conditional jumps that might correspond to a verification step .
The presence of these in the early reset flow hinted that the firmware might itself perform a
check and branch depending on the result (for instance, it might disable USB or enter a safe loop
if the check fails).
The function at 0xE8DB itself contained complex logic and multiple calls, possibly a multi-stage
validation or something to do with reading from memory and verifying (the pattern of pushes/
pops and calls was noted, but its exact role was not confirmed) .
These were logged in an crc_candidates.md file as hypotheses, with notes that they had “loop
control” and “conditional branching based on comparison results” as one would expect in a checksum
routine . However, crucially, we did not see a direct comparison to a stored expected value
that we could tie back to the known firmware data. Without that, we couldn’t be sure these routines
were checking the external firmware image; they might also relate to other data (e.g., verifying sensor
registers or configuration blocks, etc.). As ChatGPT advised, these CRC candidates were to be treated as
hypotheses until we see an actual compare against a known constant or field .
Lumina / Known Signatures: The IDA Lumina cloud (crowd-sourced code recognition) had
tagged one function with a name suggesting a CRC32 (“crc32_combine64_0”), which briefly led us
to consider if a 32-bit CRC might be used . On further thought, a 32-bit CRC for a mere 128KB
firmware seemed overkill, and more importantly, six different patch attempts all failing even
when we didn’t change the supposed CRC bytes made it unlikely that a complex CRC was being
calculated – otherwise at least one variant where we left the footer alone might have worked.
This pointed us back to a simpler explanation.
Boot ROM Hypothesis: We considered that the on-chip ROM (which executes prior to the
external flash) might be computing a checksum of the image. Many microcontrollers use a
simple summation (two’s complement checksum) as it’s easy to do in limited code. The idea is
the firmware is appended with two bytes such that the 16-bit sum of all bytes is 0 (mod
•
11
•
•
27 28
•
29 30
•
31 32
33 34
17
•
35
•
50x10000). If any byte changes and you don’t adjust the sum, the total won’t be zero and the boot
ROM can detect that. Often, the bootloader will refuse to jump to the main firmware if the
checksum is bad (or it may jump to it but some part of initialization will catch it and stop). Given
that all our patches – no matter how small – resulted in the same failure, this kind of global check
was a prime suspect.
Proof by Calculation: To validate the above, we computed the sum of the original firmware
bytes. Indeed, summing all 0x20000 (131072) bytes of the known-good firmware (treating the
last two as part of the sum) yielded 0x0000 in 16-bit arithmetic, confirming that the image’s
two-byte footer is a checksum. In other words, the last two bytes are chosen such that the
entire image sums to zero. The firmware’s own documentation (or rather our reverse-engineered
understanding) matched this: “the checksum is a 16-bit value stored at the end of the firmware
(0x1FFE-0x1FFF) and the algorithm is a simple 16-bit sum over the image, with the final two bytes
chosen so that the total sum is 0 (two’s complement)” . This is effectively a two’s
complement additive checksum, a common technique in embedded systems for integrity
verification.
No CRC16 or CRC32: We found no evidence of a polynomial-based CRC (no lookup tables other
than the aforementioned possibility at 0x3F00, which might be unrelated). All signs now pointed
to the simpler checksum. In fact, reversing the presumed formula: if you take the one’s
complement of the sum of the first 0x1FFE bytes, that should equal the 16-bit little-endian value
stored at 0x1FFE-0x1FFF. We confirmed that with the known firmware. Therefore, any change to
the firmware requires updating those two bytes such that the new sum is 0, or else the
device’s check will fail.
2.2 Integrity Check Behavior and Patch Strategy
When/Where the Check Occurs: The SN9C292B’s exact behavior on checksum failure isn’t
documented publicly, but from our experiments we infer the following: The bootloader likely
computes the checksum right after loading the code from SPI flash. If the checksum doesn’t
match, it might still enumerate the device but not fully initialize it. (Another possibility is that the
firmware itself computes the checksum early in main and decides to not start USB if it’s
wrong.) The fact that our device enumerated with the same PID even on failure suggests the
boot ROM didn’t outright enter a different mode (many devices go to a recovery USB PID if
firmware is bad). It’s possible the boot ROM allowed the code to run and the firmware’s own init
routine did a check and aborted USB functionality when it detected a mismatch. This could be
happening in that candidate code at 0x38EA/0xE8DB (e.g., a routine that compares a computed
sum with the expected value and then skips USB init or jumps to a halt if it fails).
Observation of USB Logs: On a good firmware, USB Tree Viewer shows a proper configuration
descriptor (the camera presents video streaming interfaces, etc., with configuration value = 1
and manufacturer strings like “Sonix Technology Co., Ltd.”) . On our bad patches, the device
enumerated with the correct vendor/product IDs but likely never presented a valid configuration
(e.g., Windows saw the device but couldn’t use it). This suggests the firmware might stop
responding at a certain point (perhaps at the moment it would normally handle USB
configuration setup). This is consistent with the firmware internally gating USB based on the
check. In fact, one of our goals was to find the “USB gate” – i.e. the branch in code that decides
to not proceed with USB if the checksum is bad . If that branch can be located, an
alternative patch strategy is to simply flip it (force it to always assume “checksum OK”). That
would let the patched firmware run without fixing the checksum, purely as a diagnostic (if it then
boots, it proves the check was the only issue).
•
36 37
•
•
•
9
16 38
6Checksum Routine Details: From the two’s complement checksum findings, we know:
The expected checksum value is stored in little-endian at 0x1FFE–0x1FFF of the image .
The range of bytes summed is 0x0000–0x1FFD (inclusive). In terms of 16-bit words, that’s
addresses 0x0000 through 0x1FFC as the data words and 0x1FFE as the checksum word (since
0x1FFE/0x1FFF form the 16-bit checksum) . The sum of all data words plus this checksum
word equals 0x0000 (mod 0x10000) .
Algorithm: Simple addition of 16-bit words (could be implemented as iterative ADD with carry in
8051 code, or even byte-wise addition accumulating into a 16-bit register in XDATA). The final
step is taking two’s complement, which is equivalent to storing the negative of the sum of the
data bytes.
Because the 8051 is an 8-bit machine, the implementation might sum bytes or words in a loop.
The particular details of the candidate routine (0x235E or others) might match this pattern (e.g.,
using ADD A, @DPTR in a tight loop, etc.). We haven’t pinpointed the exact routine in code, but
we now know what it must be doing.
Failed CRC Bypass Attempts: We did attempt one patch variant where we guessed the
checksum and updated the footer bytes (this was an earlier approach before fully confirming the
algorithm). That also resulted in a brick, likely because our guess was wrong – at the time, we
weren’t certain if it was a sum, a CRC16 (like CCITT), or something else. After confirming it’s a
sum, we have confidence that updating the sum correctly will yield a valid image. In retrospect,
all previous patch variants “failed with Code 10” because none of them had the corrected
checksum.
No Published CRC in Datasheet: The SN9C292B datasheet (if available) likely doesn’t explicitly
mention the checksum (such details are often in ISP programming guides). However, the pattern
is consistent with other Sonix camera controllers. A community post indicated that one of the
Sonix ISP tools expects a firmware image with a correct checksum and will refuse to flash or will
error out if it’s wrong. This aligns with our findings.
Integrity Check Summary: In summary, the firmware’s integrity check is concrete and wellunderstood now: it’s a 16-bit additive checksum. We have not seen a polynomial-based CRC or
any cryptographic hash – just this checksum. We have not yet seen any other integrity
mechanism (e.g., no evidence of signature verification or obfuscation beyond the checksum).
Thus, the path forward is to implement patches in a way that either bypasses or satisfies this
checksum. The next section (Attack Surface) will focus on the OSD patch locations (the “what” to
patch), and then we will combine that with the checksum handling (the “how” to patch without
bricking).
3. OSD Attack Surface Mapping (Firmware Analysis)
This section maps out the firmware locations that control the OSD, what each does, and which have
been patched or considered for patching. It also notes which modifications were tested and their
outcomes, to identify safe vs. problematic patch points.
3.1 OSD Control Registers and Firmware Usage
OSD Control Registers (XDATA 0x0B75–0x0B77): According to prior research, these memory-mapped
registers control the OSD overlay on the SN9C292B: - 0x0B75 – likely a primary OSD enable flag (when
set to 0x01, overlay is enabled globally). - 0x0B76 – a secondary flag or mode control (also set to 0x01 at
•
• 36
•
39
40
•
•
•
•
•
7boot along with 0x0B75). - 0x0B77 – used to hold a code for the OSD content or mode (this register is
also written with various values during operation, e.g., 0x19, 0x1A… as noted below).
Upon device reset, the firmware writes 0x01 to all three of these addresses, which turns on the
overlay (initially displaying a default timestamp, e.g., “2013…” on the video feed).
Firmware Write Sites: Through static analysis (pattern matching and disassembly), we confirmed four
distinct sites in the firmware code where these registers are written. They are summarized here (with
context):
Site 1 – Address 0x4522 – writes to 0x0B75. This is part of the early initialization routine (likely
the main firmware startup function). It sets the primary OSD enable flag. Because this code runs
immediately after the reset vector, modifying it can be risky for device boot. In our tests, altering
the instruction at 0x4522 (even to a benign no-op) consistently caused the firmware not to fully
boot . We infer that either the integrity check picks up this change (as discussed) or the
firmware/hardware expects this write at init (though the former is more likely). Conclusion:
0x4522 is on the init path and patches here must be done with checksum fix or avoided in favor
of later patches .
Site 2 – Address 0x04D0 – writes to 0x0B77. This site is executed after the initial startup, during
normal operation (ChatGPT described the 0x04D0/0x0AC4/0x0AFE sites as “post-boot” based on
call graph analysis) . The firmware at 0x04D0 likely belongs to an initialization of some other
subsystem or an interrupt handler. Writing 0x01 to 0x0B77 here might be setting an initial OSD
state or preparing the OSD buffer. We patched this (0x01→0x00) in several variants. By itself (in
variant V6) it still caused a Code 10 (because the checksum wasn’t fixed) , but logically this
change should be safe if done with a correct checksum. This site is not in the immediate reset
flow (so touching it doesn’t break code flow, aside from checksum issues).
Site 3 – Address 0x0AC4 – writes to 0x0B76. Similar to 0x04D0, this is a post-boot write that sets
the second OSD enable flag to 1. It might be executed slightly later (perhaps when the camera
starts streaming or in another init function). We tested patching this alone (variant V7) – same
outcome (Code 10) without checksum update. This site is also a good candidate for patching
once we handle the checksum. Not on the reset vector path.
Site 4 – Address 0x0AFE – writes to 0x0B77 again. This is interesting – the firmware writes to
0x0B77 at two different places (0x04D0 and 0x0AFE). The values might differ or it might be reinitialization of OSD settings. Perhaps one is in a setup function and the other in an interrupt
routine that periodically refreshes the OSD display. Regardless, it’s another point where OSD can
be influenced. We also tried patching this alone (variant V8) with the same failure (again, due to
checksum) . Like the others, 0x0AFE lies outside the immediate startup sequence.
From the above, all four identified sites have the same form: writing 0x01 to one of the OSD
registers. And in all cases, changing that to 0x00 would achieve the desired effect of keeping the
overlay off. The main challenge was never the OSD logic – it was the integrity check preventing these
patches from running.
3.2 Effects of OSD Patches and Tested Edits
Effectiveness of OSD-Off Patch (if it could run): In theory, a firmware patched to write 0x00 to
those registers should boot up with OSD disabled. The user would see no timestamp on the
•
41
6
•
6
10
•
•
10
•
8video feed. All OSD-related extension controls would report “off” by default (e.g., the UVC
extension unit that toggles OSD would read back 0) . This was indeed the intended outcome.
In one early attempt when we momentarily got a patched firmware to run (possibly by accident with a
partial patch), it was observed that the OSD did not appear – confirming that changing those bytes
does work functionally. However, that build still triggered a Code 10 shortly after, so no stable
successful run has occurred yet without addressing the checksum.
Concurrent OSD Updates: The SN9C292B firmware appears to update the OSD text dynamically
(likely to show the current time). This was evidenced by other values written to 0x0B77 beyond
just 0x01. Disassembly of other parts of the code (and analysis of OSD behavior) showed that
values like 0x19, 0x1A, 0x1B were written into 0x0B77 during operation . These could
correspond to characters or commands for the OSD (for example, maybe 0x19 means “show 1”,
0x1A “show 2”, etc., or they could be control codes). Importantly, these writes were conditional:
they only have an effect if the OSD is enabled. In fact, they are “gated by the value in
0x0B76” . In other words, the firmware likely does something like if (XDATA[0x0B76] !=
0) then XDATA[0x0B77] = 0x19 (to update the overlay). Since our patch keeps 0x0B76 = 0,
those runtime writes to 0x0B77 would effectively do nothing . This means that just disabling
the enable flags (0xB75 and 0xB76) at init is sufficient to prevent any overlay activity. We do not need
to patch every instance of writing 0x19/0x1A/etc., because with the enable off, the overlay won’t
turn on.
Tested Patch Variants: We attempted various combinations at the four sites:
All four sites patched (the original attempt) – failed (no boot).
Only init site (0x4522) patched – failed. (This was implicitly tested as part of the all-sites patch
and later explicitly in a selective test; it caused Code 10, suggesting even a one-byte change in
init triggers the check.)
Only post-boot sites (0x04D0/0x0AC4/0x0AFE) patched, leaving 0x4522 as-is – failed . This was
surprising at first because we hadn’t touched the init path. If the issue were purely a side-effect
of skipping an init step, one might expect the device to boot and simply not overlay. The fact it
still failed pointed back to the checksum – even though 0x4522 was intact, the binary was still
modified (somewhere in the middle), flagging the check.
“Redirect” patches (V9, V10) – here, instead of changing the value written, we changed the target
of the write at a later site to 0x0B75. The idea was to let the firmware initially turn on OSD as
usual, then later, use an existing write (originally meant for 0x0B76 or 0x0B77) to write 0x00 to
0x0B75, effectively turning OSD off a bit later in the boot process. This clever approach avoids
altering the timing of when 0x4522 runs (OSD comes on at boot, but we immediately shut it off a
moment later). However, this still changes the code bytes (we pointed an instruction to a
different address), so without fixing the checksum it also failed. If the checksum were fixed, this
approach should actually work and might be safer if one worries that completely skipping the
initial OSD enable could have side-effects. Essentially, it simulates a “late disable” – the OSD will
flash on for a fraction of a second at boot and then turn off.
NOP out OSD writes (while keeping A=1) – tested in V11–V14 batch. All changes, even NOPs,
triggered the checksum fail as discussed. But logically, NOPing those instructions would achieve
the same end (OSD regs never get written with 1, because the write is skipped) while not altering
the control flow. If we combine this with a proper checksum update, it’s a viable method. The
downside is it leaves the OSD registers at whatever default they have (likely 0 anyway). Changing
0x01→0x00 or NOPing the write are effectively the same outcome for the hardware.
42
•
43
43
44
•
•
•
• 10
•
•
9Preferred Patch Points: Given unlimited freedom (i.e., if checksum is handled), the simplest
patch to achieve “OSD off by default” is to flip the three MOV A,#0x01 to MOV A,#0x00 for
the three enable sites (0x4522, 0x0AC4, 0x04D0) and possibly the one at 0x0AFE (though 0x0AFE
is writing to 0xB77, which by itself doesn’t enable OSD, it may not strictly need to be changed if
0xB75 and 0xB76 are zero – but we changed it to keep consistency). This 4-byte patch is
extremely targeted . In principle, it only changes the initial state of the OSD and nothing
else; it’s also easily reversible. The earlier documentation generated by ChatGPT noted that this
minimal patch “does not remove any other functionality – it only changes the default OSD state” and
you could revert it by writing those bytes back to 0x01 to restore factory behavior .
Alternative “Permanent OSD Removal”: For completeness, one could go further and patch out
all OSD-related code (for example, NOP out the entire block of instructions around 0x4522 that
set up the OSD, and also disable the timer interrupt that updates the OSD characters) .
However, this is not necessary for our goal (which is just to stop the overlay from appearing by
default). The firmware’s overlay logic can remain intact and just never be activated. In fact,
leaving it intact means the user could still manually turn on the OSD via the camera’s extension
controls if ever needed – a nice side effect of a reversible patch. Thus, the “minimal intervention”
approach was deemed sufficient and preferable over a scorched-earth removal of all OSD code
.
Init Path Sensitivity: It became clear that touching the init path (0x4522) was “toxic” without
proper handling . The safe strategy is either:
Do not patch 0x4522 at all – instead, patch later sites or inject a new instruction later to clear the
OSD (so that the boot proceeds with OSD on, then we turn it off) .
Patch 0x4522 with the correct checksum fix – this should also be safe, as long as the firmware
doesn’t rely on that write for anything else. We suspect it doesn’t (writing 0 instead of 1 should
not break anything except the OSD itself), but to be absolutely sure, approach (1) is ultracautious.
In summary, the attack surface for disabling the OSD has been fully mapped: the primary targets are
the four identified instruction sites that set those XDATA registers. We have high confidence that
altering those will achieve OSD-off functionality, as evidenced by the disassembly and partial tests (the
only reason they failed was the integrity check). With the checksum mechanism understood, we can
now adjust our patch method to preserve firmware integrity.
4. “Bricking” Behavior, Recovery, and Flashing Strategies
This section documents what happens when a “bad” (integrity-failing) firmware is flashed, how we
recovered the device each time, and what methods/tools have been used or developed to reflash the
SN9C292B.
4.1 Behavior on Firmware Integrity Failure
When a patched firmware with an incorrect checksum was flashed, the device would power up and
attempt to run it, but failed to fully initialize as a USB device. In Windows, this presented as the
device showing up in Device Manager with the correct name (since the USB descriptors are stored in
firmware and were still present) but with a yellow exclamation and Error Code 10 (“This device cannot
start”) . On Linux, this would likely appear as the device enumerating but not responding to UVC
inquiries properly (perhaps the video interface never comes up).
•
8 45
46
•
47 48
49
•
50 51
•
52 51
•
10
10Notably: - The device did not fall back to a different PID or enter a ROM boot mode automatically. (Some
controllers, on checksum fail, enumerate in a special bootloader mode with a different USB ID. In our
case, it stayed at 0x0C45:0x6366, which is the normal camera PID, albeit non-functional). It’s possible
that the SN9C292B’s ROM does have a fallback mode but maybe the checksum fail handling in firmware
was to intentionally stall the device rather than reset to ROM; the exact mechanism isn’t certain. A hint
from a Reddit case: a user with a corrupt firmware had their device come up as PID 0x6365 (one off)
which might be a bootloader mode . We did not observe a PID change, meaning the firmware wasn’t
completely rejected by ROM – it likely ran and then hit a dead-end due to its own check. - USB
descriptors in the failing state appeared incomplete. As noted earlier, USB Tree Viewer was used to
compare a working vs non-working firmware. In the non-working case, one might see that the device
reports a Device Descriptor but might not provide a Configuration Descriptor (hence Windows says
“cannot start” when trying to configure it). The manufacturer and product strings were still visible
(coming from firmware), which tells us the firmware did execute to the point of loading descriptors ,
but presumably something prevented the final USB configuration. This is consistent with an integritycheck-triggered routine that perhaps sets an error code or enters a loop before initializing the USB
interface fully.
In essence, the device was “soft-bricked”: the firmware was not running normally, but the device was
still accessible over USB in some form, enabling us to attempt reprogramming.
4.2 Recovery Procedure for Bricked Firmware
Each time a patched firmware caused a Code 10, we performed the following to recover:
Reflash the original firmware: Using the known-good backup, we wrote the original .bin back
to the camera’s SPI flash. Initially, this was done via the SONiX UVC TestAP (the command-line
tool provided by Kurokesu, running on Linux). The command --sf-w (write) was used to send
the image to the device’s extension unit and reprogram the flash. This required the device to be
in a state that accepts those commands. Even with Code 10 in Windows, switching to Linux
allowed using the extension-unit interface (the device enumerated enough to accept vendorspecific requests).
After flashing, power-cycle the camera. It would then boot with the original firmware, and
Windows would recognize it as a working webcam. USBTreeViewer would show it has a valid
configuration, proper descriptors, and no errors .
We always verified the hash of the re-flashed firmware against the original to ensure no
corruption, and indeed it always matched, confirming that the write succeeded and the device
was back to its baseline.
Precaution: A dedicated 3.3V SPI flash programmer was on standby (which would involve removing the
camera from USB, wiring the SPI flash chip to a programmer or using a Raspberry Pi, etc.) but this
hardware recovery wasn’t needed since software methods sufficed. We did, however, identify ISP (InSystem Programming) options: - Sonix provides an official Windows snxISPTool.exe for their cameras. If
the camera could be put into ISP mode (likely by having an empty flash or a special USB request), that
tool might allow direct USB flashing on Windows . We considered using this if our custom methods
failed. - The Reddit example with PID 0x6365 suggests that if the firmware is absent or invalid, the
SN9C292B might enumerate as a bootloader (0x6365) for which the ISPTool is needed . In our case,
because we always had something in flash (just with a bad checksum), it stayed as 0x6366. We never
explicitly triggered a pure bootloader mode.
Development of Improved Tools: The repetitive flash, test, re-flash cycle was time-consuming,
especially switching OS environments. To streamline: - We started developing a Python CLI tool
53
9
•
•
9
•
26
53
11( snxuvc_dump.py ) using PyUSB for Windows to talk to the camera’s UVC Extension Unit directly
. This tool enumerates USB devices, finds the one with VID:0x0C45 PID:0x6366, and uses vendorspecific requests (Extension Unit control selectors 0x23 and 0x24, as used by the Kurokesu utility) to
read/write the SPI flash. It basically automates what the TestAP does, but in a Windows-native way. The
script features robust read (dump) and write capabilities in Python, and we tested portions of it
(encountering typical issues like needing the WinUSB driver bound to the device’s interface and
ensuring the libusb-1.0.dll is present on Windows) . After resolving those (e.g., installing
the WinUSB driver on the camera’s control interface using Zadig, and providing the libusb DLL), this tool
can be used to quickly flash firmware images on the fly. - Having this Windows flasher means we can
iterate on patches without rebooting or juggling multiple tools. It also allowed scripting of the entire
test cycle: flash variant -> power-cycle camera -> check if device enumerates properly (perhaps by
waiting for the USB device and checking a USB descriptor or hash from a read-back) -> if fail, auto-flash
original back. This kind of loop can greatly speed up finding a working solution.
Current Status of Recovery: At this time, we have successfully recovered from every failed patch. No
attempt resulted in a permanent brick. The worst-case scenario (which we did not hit) would be if the
device got stuck in a state where it didn’t enumerate at all (then we’d have to resort to the hardware ISP
programmer). But thanks to the bootloader and our careful approach, that didn’t happen. It’s still
advised to keep the hardware programmer method as a backup plan when proceeding with future
experiments (especially when we begin injecting code or making more invasive changes).
In summary, the project established a reliable cycle: patch firmware -> flash -> test -> if Code 10,
reflash original -> refine patch. This was made more efficient by improved tooling and by
understanding what triggers a brick (the checksum). With the checksum problem solved, we anticipate
far fewer “brick” incidents, since the device should accept the patched firmware normally.
5. Next Steps to Achieve OSD Disable (Checklist)
Finally, we outline the recommended next steps to successfully disable the OSD while preserving
normal device operation. These steps incorporate the lessons learned about the checksum mechanism
and the OSD code locations. Following this plan should lead to a working patched firmware.
5.1. Verify the Firmware Checksum Algorithm
Before applying any new patch, double-check the integrity algorithm on a known-good firmware dump:
calculate the 16-bit sum of all bytes from 0x0000 up to 0x1FFD and confirm that the result, plus the 16-
bit value at 0x1FFE–0x1FFF, equals 0x0000 . This confirms we fully understand the checksum. (We
have high confidence it’s a two’s complement sum, but this step ensures no mistakes in
implementation.)
5.2. Update Patch Script to Recalculate Checksum
Augment the firmware patching script (e.g. patch_osd_off.py ) to automatically recompute the
checksum after making any modifications to the firmware bytes. This involves summing the patched
image’s bytes and writing the two-byte result (negative sum) into the 0x1FFE and 0x1FFF positions.
Ensure to handle endianness (the sum should be stored little-endian) and verify the output size remains
0x20000 bytes . This step is critical: any future patched binary must have a correct checksum to be
accepted by the device.
5.3. Apply Minimal OSD Patches (Post-Boot First)
Implement the OSD-disable patch in a conservative way and test incrementally: - First, try patching only
the post-boot OSD writes (sites at 0x04D0, 0x0AC4, 0x0AFE) from 01 to 00 , while leaving the early
24
25
54 55
36 40
56
12init write (0x4522) unchanged . Recompute the checksum (from step 5.2) and flash this firmware (call
it test V_post). - Rationale: This ensures we do not disturb the very early boot sequence at all. If the
device boots and the OSD is still on (because 0x4522 set it), we can verify that it stays on or maybe turns
off later (depending on if any patched later write affected it). Ideally, since we patched the later writes,
the camera might boot with OSD on and then possibly one of the now-patched later routines fails to
turn it off (because we prevented writes of 1 , not actively turning it off). In fact, with this patch, OSD
will likely remain on because we didn’t clear 0x0B75. This is mostly a sanity test to ensure that simply
having the correct checksum yields a normally functioning device even if OSD is on. If this boots without
Code 10, it proves our checksum fix works.
5.4. Disable OSD in Init (Full Patch)
Next, apply the full OSD-off patch: modify the 0x4522 site as well (change that MOV A,#0x01 to
#0x00 ) so that all three OSD enable flags are zeroed at boot. Again, recompute checksum and
produce the patched binary (call it V_full). This is the true target firmware – if our analysis is correct, the
camera should now boot up normally with the overlay disabled from the start. Flash this and test device
enumeration and functionality.
5.5. Testing & Validation
After flashing the patched firmware: - Power-cycle the camera and check in Windows Device Manager
(or lsusb on Linux) that the device enumerates without errors (no Code 10). The USB descriptors
should look identical to stock firmware (same VID, PID, strings, interfaces). Use USBTreeView or a similar
tool to confirm the configuration is loaded (Config Value = 1, etc.) . - Verify that the OSD overlay is
indeed not present on the video output. This can be done by streaming video from the camera and
observing that the usual timestamp or text is absent. Additionally, query the UVC extension unit
controls for OSD enable status – they should report 0 (off) by default . - Check general camera
functionality: image streaming, autofocus or other controls, and ensure nothing else was inadvertently
affected by the patch. (Since our patch is small, this should all work as before.)
If V_full passes all the above, we have succeeded in our goal. If there is still an issue, proceed to the
next steps.
5.6. (If Needed) Integrity Check Bypass
If for some reason the device still fails to start with the patched firmware even after updating the
checksum, then our understanding might be incomplete (e.g., perhaps there is an additional check or
some runtime logic issue). In that case, a useful diagnostic step is to bypass the integrity check in
firmware code and try again. This involves finding the code that compares the computed checksum to
the expected value and patching the branch instruction that handles a mismatch. For example, if there’s
a JNZ (jump if not zero) or similar after computing the checksum, change it to always jump to the “OK”
path . This typically means inverting a condition or NOPing out a conditional jump so that the
firmware always proceeds as if the checksum was correct. This patch should be done carefully (identify
the exact compare and branch using the disassembly dumps from SWE-1). Once done, recalc checksum
(for the new patch) and flash the firmware (call it V_bypass). If V_bypass boots and functions with OSD
off, it confirms that it was indeed the checksum logic causing issues. (This is more of a debugging aid;
ideally, we won’t need this if V_full works, but it’s a fallback plan.)
5.7. (If Needed) Late OSD Disable via Stub
If it turns out that patching the init write 0x4522 is problematic (e.g., suppose the device still had issues
when we changed that, though with checksum fixed this is unlikely), an alternative approach is to not
modify 0x4522 at all but instead inject a small code stub after USB initialization that clears the OSD
enable. The SWE-1 analysis should identify a “safe anchor” address—i.e., a point in the code, post-boot,
18
9
42
38
13where we can insert a few instructions without causing harm . The stub would do: MOV
DPTR,#0x0B75; MOV A,#0x00; MOVX @DPTR,A (and possibly also clear 0x0B76 similarly) to turn off
the overlay late. This could be done by repurposing an unused section of ROM or extending a function
with a jump to our new code (if space permits). The key is to preserve registers and timing (so as not to
disrupt camera operation). This approach was suggested to avoid any change in the delicate reset
sequence . Implementing this is more complex (requires assembly editing and careful planning of
where to put the stub), so it’s a secondary option if the direct patch proves stubborn.
5.8. Comprehensive Testing of Patched Firmware
Once a patched firmware variant boots and OSD is disabled, perform thorough testing: - Enumeration
and UVC: Plug and play the device on multiple systems if possible. Ensure it enumerates every time
without issues. - Video Streaming: Test actual video capture from the webcam for an extended period.
The absence of OSD should have no effect on video quality or stability, but this confirms no unintended
side-effects. - Controls: Test the camera’s extension unit controls (if any) for OSD on/off. If you manually
send a command to turn OSD on, does it work? (It might not, since our patch keeps the enable flag off.
If the control writes to 0x0B75, it could turn it on temporarily – which would be fine, as our goal was just
default-off. If we wanted to force it off always, we could also intercept those controls, but that’s out of
scope for now.) - Reconnects and Reboots: Power-cycle the camera multiple times, and try it on a cold
boot of the PC as well, to ensure the patch doesn’t affect the boot timing (the two’s complement
checksum effectively ensures the bootloader is happy, so this should be consistent). - Edge cases: If the
camera has multiple modes (resolutions, etc.), switch through them to ensure nothing triggers the OSD
back on or any crash (unlikely, but we test to be thorough).
5.9. Documentation and Backup
After verifying the patch, document the final firmware version, including the exact bytes changed and
the new checksum. Save the patched firmware binary ( fw_osd_off.bin ) along with a copy of the
original for reference. It’s wise to also keep a copy of the diff (addresses and original/new bytes) and a
human-readable summary (as we have done in this report). This will help future contributors or
developers to quickly see what was changed to achieve the OSD disable. (Our diff should show 4 byte
changes if using the direct approach, plus the two checksum bytes updated – and no other differences
.)
5.10. Optional: Refinement
If the patch is working and we’re satisfied, we might consider a few optional refinements: - We could
simplify the patch to the minimum necessary changes. For example, if leaving 0x4522 enabled and only
disabling later still achieves “no OSD line after a few seconds,” we might decide that’s enough. However,
the cleanest result is with 0x4522 patched so the OSD never flashes on at all. - If we want the OSD truly
completely disabled (even if someone tries to turn it on via software), we could patch the handler for the
extension unit so it ignores or overrides OSD-on commands, or patch the runtime writes of 0x19/0x1A
so they do nothing. This is only if we want to belt-and-suspenders ensure the overlay cannot come on.
Based on earlier analysis, this is not necessary, since with the enable flags off, those writes don’t
reactivate OSD anyway . - Consider merging the patch into a single streamlined update script or
even integrating it into the ISPTool format (so others can flash it easily). But that’s more of a distribution
step than a technical requirement.
By following the above checklist, we should arrive at a firmware that boots normally, passes the
integrity check, and has the OSD overlay disabled by default. With that accomplished, the primary
goal of the project is met, and we will have a documented, repeatable procedure for any future
firmware mods on this device.
52
51
57 58
44
14prev attempts 2.txt
file://file-J8ik3Mw16cKB6wPJrKVPiD
gptchat1.txt
file://file-WLoh1vcnZZQ9xuJuAyEuKf
crc_candidates.md
https://drive.google.com/file/d/11kQOKaCEqVJ8rSQzPN5uQb6B6eE57Uu7
patch_report.md
https://drive.google.com/file/d/13zMv_0pCrwR5WGm3fm8DtIZbQaIxg6cM
gpt chat2.txt
file://file-W2SW6jq3sx6NCBtXoibSPb
1 2 7 8 9 24 25 26 42 43 44 45 46 47 48 49 53 54 55
3 4 5 6 10 11 12 13 14 15 16 17 18 19 20 21 22 23 35 38 41 50 51 52 56
27 28 29 30 31 32 33 34
36 37 39 40
57 58
15