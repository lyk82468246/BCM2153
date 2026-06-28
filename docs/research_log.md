# Research log

## 2026-06-27 initial state

The working sample directory is `/home/joe/thing` in WSL. It contains a Samsung
GT-B5310/B5310U-style firmware package with boot, modem, app, resource, DSP,
filesystem, parameter, and NVRAM-like components.

Observed private sample components:

- `bcmboot.img`
- `boot2.img`
- `amss.bin`
- `apps_compressed.bin`
- `drom_dsp.img`
- `patch_dsp.img`
- `FactoryFs_B5310_China.ffs`
- `PFS_B5310_Open_China_Common.pfs`
- `Rsrc_B5310_China.rc1`
- `Rsrc2_B5310U(Low).rc2`
- `Rsrc2_B5310U(Mid).rc2`
- `ShpApp.app`
- `sysparm_dep.img`
- `sysparm_ind.img`
- `NVRAM6.bin`

Important early observations:

- `amss.bin` begins with an ARM little-endian exception vector table.
- `amss.bin` contains BCM2153, Hedge, Nucleus PLUS, CAPI2, RF calibration, and
  Samsung model/version strings.
- `bcmboot.img` contains NAND boot strings and transitions to `boot2.img` or
  download mode on failure.
- `boot2.img` and the beginning of `apps_compressed.bin` look high-entropy and
  need format/compression/encryption checks before static loading.

Near-term milestones:

1. Generate a reproducible firmware survey report.
2. Infer image load addresses and boot-chain handoff points.
3. Create Ghidra import notes for `bcmboot.img` and `amss.bin`.
4. Identify UART/download-mode memory read/write or RAM execution primitives.
5. Build a RAM-only hello-world payload path before considering flash changes.

## 2026-06-27 repository setup

Created public-safe project scaffolding in `/home/joe/BCM2153`. The repository
contains scripts and manually filtered notes only; raw firmware and generated
local reports remain ignored.

Added the first durable fact store, boot-chain hypothesis page, and initial
survey summary.

## 2026-06-27 Ghidra bootstrap

Added a reproducible Ghidra headless import path for `amss.bin` and
`bcmboot.img`.

Validated imports:

- `amss.bin`: raw ARM little-endian, base `0x80300000`, file offset `0x0`.
- `bcmboot.img`: raw ARM little-endian, base `0x28000000`, file offset `0x40`.

Installed WSL helper packages `bubblewrap` and `binutils-arm-none-eabi` so the
Codex sandbox and quick ARM objdump checks work directly inside WSL.

## 2026-06-28 TkTool trailer survey

Added `tools/tktool_tail_survey.py` to locate short Samsung/TkTool trailer
markers without copying firmware bytes.

High-confidence observation: `bcmboot.img`, `boot2.img`, `amss.bin`, and
`apps_compressed.bin` all have a final `cd ab cd ab` marker exactly 1024 bytes
before EOF. This makes the final KiB a likely packaging/tooling metadata block.

`boot2.img` also has a visible `MID_*` module-name table before its final
trailer, starting around `0x0004c000`.

## 2026-06-28 architecture pass

Added a first architecture map covering the boot/packaging layer, Nucleus modem
stack, Samsung SHP/native application layer, IMRC resources, FAT16 FactoryFs,
and parameter/calibration images.

Important new observations:

- `FactoryFs_B5310_China.ffs` is FAT16 and contains `Exe`, `Media`, `Security`,
  `Settings`, and `SystemFS` root directories.
- `Exe/Java` contains preinstalled J2ME `.jad` / `.jar` applications; `Exe/Mocha`
  is also present.
- `ShpApp.app` contains an embedded ARM ELF at file offset `0x192e` and many
  Samsung SHP/Web/widget-related source-path strings.
- `Rsrc_B5310_China.rc1` starts with `IMRC` and contains XML, PNG, zlib, bitmap,
  and other UI/media resources.

## 2026-06-28 ShpApp ELF pass

Added `tools/shpapp_elf_survey.py` and `docs/shpapp_analysis.md`.

Confirmed that `ShpApp.app` is a `FimBIN` container with an embedded ARM ELF at
offset `0x192e`. The ELF entry is `0x0e00ad0c`, the LOAD segment starts at VMA
`0x0e000034`, and sections use ARM toolchain-style names `ER_RO`, `ER_RW`, and
`ZI`.

## 2026-06-28 resource layer pass

Added `tools/resource_magic_survey.py` and `docs/resource_layer.md`.

`Rsrc_B5310_China.rc1` is confirmed as a dense IMRC resource bank with PNG,
JPEG/JFIF, XML/BWFXML, ZIP, SWF, and zlib-like resources. `ShpApp.app` also
contains a small embedded resource set in addition to the native ELF. FactoryFs
shows many ZIP/JAR/widget-like resources, consistent with FAT16-hosted Java and
widget packages.

## 2026-06-28 IMRC probe pass

Added `tools/imrc_probe.py` to test resource-bank structure without extracting
assets.

New model: `Rsrc_B5310_China.rc1` starts with an `IMRC` header whose declared
`0x1000` header/table area is not a direct absolute offset/length table. Strict
resource span parsing shows that magic scans overcount real resource starts:
115/137 PNG hits currently parse as complete PNG files, while SWF hits are also
mixed between parseable and incidental matches.

`Rsrc2_B5310U(Low).rc2` and `Rsrc2_B5310U(Mid).rc2` are not IMRC files. They are
near-identical `CHN`-marked profile banks with a profile word difference at
`0x08` and a short differing tail region.

## 2026-06-28 ShpApp Ghidra import pass

Added `tools/shpapp_ghidra_import.sh` for a reproducible local-only import of
the embedded ELF inside `ShpApp.app`. The script extracts from file offset
`0x192e` into ignored `out/` storage and imports with Ghidra's ELF loader.

A full automatic-analysis attempt was interrupted after several minutes due to
slow mixed code/resource analysis and a decompiler warning. The workflow now
defaults to `-noanalysis`; manual or targeted analysis should start from the
Thumb entry region around `0x0e00ad0c`.

## 2026-06-28 ShpApp entry probe pass

Added `tools/shpapp_entry_probe.py` for metadata-only entry-region analysis.
The probe maps the ShpApp entry `0x0e00ad0c` to container offset `0xc63a`,
confirms the entry should be treated as Thumb, and records that the first block
stores the incoming context in a ZI global around `0x0e5e8c0c` before calling
through host-provided function pointers.

## 2026-06-28 FactoryFs survey pass

Added `tools/factoryfs_survey.py` and `docs/factoryfs_analysis.md` for a
metadata-only FAT16 filesystem map. The FactoryFs image has 608 visible entries,
with `SystemFS` as the dominant tree, 10 preinstalled `.jad`/`.jar` J2ME pairs,
3 widget `.wgt` packages, certificate-heavy `Security`, and hardware-support
files under `SystemFS/Driver`.

