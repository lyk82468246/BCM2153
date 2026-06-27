# Publication policy

This project is intended to hold public-safe research artifacts.

## Commit these

- Original notes, plans, diagrams, and hypotheses.
- Hashes, sizes, offsets, file names, and concise metadata.
- Small evidence snippets that identify firmware lineage or loading behavior.
- Scripts that analyze local samples without embedding vendor data.
- Manually written hardware maps, boot-chain diagrams, and loader notes.

## Keep local by default

- Raw firmware images and filesystem/resource dumps.
- NVRAM, calibration, IMEI, serial-number, SIM-lock, or RF calibration data.
- Complete string dumps.
- Long disassembly, decompiler output, or reconstructed C source from vendor
  firmware.
- Ghidra/IDA project databases that contain proprietary-derived bytes.

## Reverse-engineering boundaries

The near-term work should stay focused on owned-device recovery and operating
system bring-up:

- Map the boot chain.
- Identify RAM, UART, timer, interrupt controller, flash, and display basics.
- Build a RAM-only payload path before flashing anything.
- Avoid RF transmit experiments and avoid changing calibration data unless the
  hardware is isolated and backed up.

When in doubt, keep the artifact local and commit only a short summary.
