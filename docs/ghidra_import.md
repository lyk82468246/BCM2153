# Ghidra import workflow

This project keeps Ghidra projects and logs local-only under `out/ghidra`.
Do not commit generated Ghidra projects or raw firmware bytes.

## One-command import

```sh
cd /home/joe/BCM2153
tools/ghidra_import.sh
```

Defaults:

- Ghidra: `/opt/ghidra_12.1_PUBLIC`
- Firmware samples: `/home/joe/thing`
- Output project root: `/home/joe/BCM2153/out/ghidra`
- Processor: `ARM:LE:32:v5t`
- Compiler spec: `default`

Environment overrides:

```sh
GHIDRA_HOME=/opt/ghidra_12.1_PUBLIC \
FIRMWARE_DIR=/home/joe/thing \
PROJECT_ROOT=/home/joe/BCM2153/out/ghidra \
tools/ghidra_import.sh
```

## Images imported

| Program | File | File offset | Base address | Length | Reason |
| --- | --- | ---: | ---: | ---: | --- |
| `amss_80300000` | `amss.bin` | `0x0` | `0x80300000` | `0x58e2a4` | vector table starts at file offset zero; adjacent metadata points into `0x80300000` RAM |
| `bcmboot_28000000_from_0x40` | `bcmboot.img` | `0x40` | `0x28000000` | `0xab26` | first `0x40` bytes look like a loader/header prefix; ARM vectors begin at file offset `0x40` |

## ShpApp ELF Import

`ShpApp.app` is a FimBIN container rather than a plain binary. Use the separate
helper to cut the embedded ELF into ignored `out/` storage and import it with
Ghidra's ELF loader:

```sh
tools/shpapp_ghidra_import.sh
```

Defaults:

- Input: `/home/joe/thing/ShpApp.app`
- Embedded ELF offset: `0x192e`
- Output project root: `/home/joe/BCM2153/out/ghidra_shpapp`
- Project name: `BCM2153_ShpApp`
- Automatic analysis: disabled by default with `-noanalysis`

Set `RUN_ANALYSIS=1` to allow Ghidra automatic analysis after import. A first
full-analysis attempt was interrupted after several minutes because Ghidra was
spending time in decompiler/data-type analysis over a mixed code/resource image
and emitted a pcode/decompiler warning. The no-analysis import is the safer
starting point for manual Thumb entry setup and targeted analysis.

The ELF loader currently selects `ARM:LE:32:v8:default`. Treat this as a loader
choice to verify, not proof that the BCM2153 application core is ARMv8; the
entry bytes still disassemble as Thumb and the broader firmware evidence points
to an older ARM/Thumb-era platform.

## Post-import annotation

`tools/ghidra_scripts/AnnotateBcm2153.java` labels:

- the ARM vector table,
- vector handler targets reachable through `LDR pc, [pc, #imm]`,
- the expected `0xbabeface` metadata marker at runtime base + `0x20`.

The script adds bookmarks for vector targets and notes when a target is likely a
Thumb entry by checking bit 0 of the pointer value.

## Verification notes

The workflow was tested locally with Ghidra 12.1 on 2026-06-27. The first full
analysis pass took about 202 seconds for `amss.bin` and about 6 seconds for
`bcmboot.img`.

`arm-none-eabi-objdump` agrees with the vector-table interpretation:

- `amss.bin` at `0x80300000` starts with `ldr pc, [pc, #36]` vectors. The reset
  vector reads its target from `0x8030002c`, whose word is `0x803001fc`.
- `bcmboot.img`, imported from file offset `0x40` to `0x28000000`, starts with
  `ldr pc, [pc, #32]`. The reset vector reads `0x28000070`; most other vectors
  read `0x2800066c`.

## Current assumptions to revisit

- `ARM:LE:32:v5t` is a practical starting point because the image contains both
  ARM and Thumb-era Nucleus code. Confirm the exact ARM core later from silicon
  IDs, boot ROM behavior, or stable disassembly patterns.
- `amss.bin` base `0x80300000` is inferred from vector-adjacent address words.
- `bcmboot.img` base `0x28000000` is inferred from the vector table at file
  offset `0x40` and nearby `0x28000070` / `0x2800066c` words.
- `boot2.img` is intentionally not imported yet; first determine whether it is
  packed, encrypted, or copied/decoded by `bcmboot.img`.
