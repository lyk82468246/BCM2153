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

The default scan mode deeply scans boot/core images and shallow-scans large
resource/filesystem images. To force expensive scans on every image:

```sh
python3 tools/firmware_survey.py /home/joe/thing --out out/deep_survey --deep-all
```

## Installed tools observed

- `/opt/ghidra_12.1_PUBLIC`
- `/opt/.ZS-ISP-Client`
- `/usr/bin/binwalk`

Command-line ARM objdump/radare2 were not present during the initial survey.
Ghidra should be used first for disassembly and decompilation.
