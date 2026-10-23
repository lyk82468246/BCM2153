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

ShpApp/FimBIN embedded ELF survey:

```sh
python3 tools/shpapp_elf_survey.py /home/joe/thing/ShpApp.app --out out/shpapp_elf_survey
```

Resource/container magic survey:

```sh
python3 tools/resource_magic_survey.py \
  /home/joe/thing/Rsrc_B5310_China.rc1 \
  /home/joe/thing/ShpApp.app \
  /home/joe/thing/FactoryFs_B5310_China.ffs \
  --out out/resource_magic_survey
```

Public IMRC format comparison (metadata only; no extraction):

```sh
python3 tools/imrc_public_compare.py \
  /home/joe/thing/Rsrc_B5310_China.rc1 \
  --out out/imrc_public_compare/imrc_public_compare.json
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

## REA and bounded ShpApp analysis

REA CLI can use the existing Ghidra installation by setting
`GHIDRA_INSTALL_DIR=/opt/ghidra_12.1_PUBLIC` for that invocation. This does not
change the environment of an already-running MCP server. On this host REA's
Ghidra Unix-socket bridge required an approved run outside the sandbox.

Full ShpApp ELF analysis reached the 330-second REA startup deadline both with
default analyzers and with `Decompiler Switch Analysis`, `Stack`, and
`Embedded Media` disabled. Avoid repeating those profiles unchanged. A bounded
ordinary Ghidra probe is available for six known Thumb functions:

```sh
mkdir -p out/rea_shpapp
/opt/ghidra_12.1_PUBLIC/support/analyzeHeadless \
  out/ghidra_shpapp/projects BCM2153_ShpApp \
  -process ShpApp_embedded.elf -noanalysis -readOnly \
  -scriptPath tools/ghidra_scripts \
  -postScript ProbeShpAppHostAbi.java \
    /home/joe/BCM2153/out/rea_shpapp/host_abi.ghidra.json
```

The destination must not exist; choose a new filename for a later pass. The
probe requires the documented ELF digest, supplies explicit Thumb ranges, and
keeps its full disassembly/pseudocode output local. On the restricted host the
validated invocation also used
`JAVA_TOOL_OPTIONS=-Duser.home=/tmp/bcm2153-ghidra-probe` with that directory
created beforehand, so Ghidra preferences and compilation caches stayed in a
writable temporary directory. These settings do not execute target code.

## Ghidra import

```sh
cd /home/joe/BCM2153
tools/ghidra_import.sh
```

See `docs/ghidra_import.md` for base-address hypotheses, loader offsets, and
the post-import annotation script.
