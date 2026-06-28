# Tooling notes

## Working mode

The project is maintained in WSL only:

- Repository: `/home/joe/BCM2153`
- Private firmware samples: `/home/joe/thing`
- Ghidra: `/opt/ghidra_12.1_PUBLIC`

Do not maintain a Windows-side repository clone, and do not place generated
analysis outputs under `/mnt/c`.

## Local survey

```sh
cd /home/joe/BCM2153
python3 tools/firmware_survey.py /home/joe/thing --out out/initial_survey
```

TkTool/Samsung trailer survey:

```sh
python3 tools/tktool_tail_survey.py /home/joe/thing --out out/tktool_tail_survey
```

Source-path architecture survey:

```sh
python3 tools/source_path_survey.py /home/joe/thing/source_files.txt --out out/source_path_survey
```

The default scan mode deeply scans boot/core images and shallow-scans large
resource/filesystem images. To force expensive scans on every image:

```sh
python3 tools/firmware_survey.py /home/joe/thing --out out/deep_survey --deep-all
```

## Installed tools observed

- `/opt/ghidra_12.1_PUBLIC`
- `/opt/.ZS-ISP-Client`
- `/usr/bin/binwalk`
- `/usr/bin/bwrap`
- `/usr/bin/arm-none-eabi-objdump`

Ghidra should be used first for decompilation. `arm-none-eabi-objdump` is useful
for quick raw-binary disassembly checks.

## Ghidra import

```sh
cd /home/joe/BCM2153
tools/ghidra_import.sh
```

See `docs/ghidra_import.md` for base-address hypotheses, loader offsets, and
the post-import annotation script.
