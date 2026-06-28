# BCM2153 reverse-engineering notes

This repository collects public-safe notes, scripts, and reproducible metadata for
researching Broadcom BCM2153 feature-phone firmware.

The immediate target sample set is a Samsung GT-B5310/B5310U firmware package
with components such as `bcmboot.img`, `boot2.img`, `amss.bin`,
`apps_compressed.bin`, DSP images, resource images, and filesystem images.

## Current model

BCM2153 should be treated as a baseband-style ARM platform used to run a
feature-phone software stack, not as the BCM21553 Android/Windows Mobile
application processor family. Public BCM2153 chip documentation is scarce, so
the main evidence source is the firmware itself.

Initial firmware strings identify:

- `Hedge Platform: BCM2153_SI1_3_43_V70`
- `BCM2153\src\irqctrl.c`
- `Nucleus PLUS - THUMB ARM Version 1.7.G1.3`
- `GT-B5310U`
- `B5310U+ZC+JH2`

## Repository policy

Do not commit raw firmware images, calibration/NVRAM data, complete extracted
strings, or long decompiler/disassembly dumps. Keep this repository focused on
scripts, offsets, hashes, short evidence snippets, and original analysis.

See [docs/publication_policy.md](docs/publication_policy.md).

## Layout

- `tools/firmware_survey.py`: read-only scanner for firmware files.
- `tools/imrc_probe.py`: metadata-only probe for IMRC/resource-bank structure.
- `tools/ghidra_import.sh`: local-only Ghidra project builder for key images.
- `tools/shpapp_ghidra_import.sh`: local-only Ghidra importer for the ShpApp embedded ELF.
- `docs/firmware_facts.md`: durable facts and offsets.
- `docs/system_architecture.md`: current firmware architecture map.
- `docs/boot_chain.md`: boot-chain hypotheses and evidence.
- `docs/bcmboot_analysis.md`: first-stage loader disassembly notes.
- `docs/shpapp_analysis.md`: Samsung ShpApp/FimBIN native ELF notes.
- `docs/resource_layer.md`: IMRC/ShpApp/FactoryFs resource observations.
- `docs/ghidra_import.md`: reproducible Ghidra headless import workflow.
- `docs/tktool_tail.md`: Samsung/TkTool trailer observations.
- `docs/analysis/initial_survey.md`: manually filtered survey summary.
- `docs/research_log.md`: running research notes and milestones.
- `docs/publication_policy.md`: what is safe to publish here.
- `docs/tooling.md`: WSL-only workflow and local tool notes.

## First command

From WSL, with the private firmware samples in `/home/joe/thing`:

```sh
python3 tools/firmware_survey.py /home/joe/thing --out out/initial_survey
```

To create the local Ghidra project for the two first-priority ARM images:

```sh
tools/ghidra_import.sh
```

The tool writes JSON and Markdown reports to the selected output directory.
Review the generated report before copying any selected, sanitized findings into
`docs/`.
