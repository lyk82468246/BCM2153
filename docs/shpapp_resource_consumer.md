# ShpApp browser resource consumer

A bounded static pass connects a ShpApp browser drawing path to six local IDs
in the indexed `System/Rsrc/Bmp/Black/SFBrowserRsrc.rbm`. This establishes a
consumer candidate with actual call arguments and return-value use. The host
implementation, theme/path resolution and execution on a device remain unknown.

## Identity and analysis boundary

The parent `ShpApp.app` SHA-256 is
`6f5a455adb73a22eef95f1c7f01ee4de6d4a2c812c394f43c791beb774dcbab1`.
The exact embedded ELF at parent offset `0x192e` has SHA-256
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
For the examined PT_LOAD region, ELF offset `0x34` maps to `0x0e000034`.
The filename at parent offset `0xa7d6` therefore maps to VMA `0x0e008ea8`.

The analyst-selected Thumb function has two code islands:
`[0x0e008c52,0x0e008e52)` and `[0x0e008f80,0x0e008fc0)`.
Intervening strings and literal pools are excluded from its body. ARM objdump
and Ghidra 12.1 agree on the examined instructions; the read-only Ghidra probe
decoded 279 instructions and completed decompilation. Function boundaries and
the probe label are analyst inputs. Saved language `ARM:LE:32:v8:default` does
not identify the physical CPU. This is ordinary Ghidra evidence, not a REA
function dossier; the previously timed-out full-ELF analysis was not repeated.
No firmware code was executed.

## Resource selection calls

Let `C = read32(0x0e5e8c0c)`, the context saved by the module entry. The
function calls `read32(read32(read32(C+0x23c))+0x18)`. At each call:

- `r0` points to `SFBrowserRsrc.rbm`.
- `r1` is the local-ID candidate below.
- `r2` points to `Src\SHP\SFBalZoomUISHP.c` at `0x0e008aec`.
- `r3` increases from `0x8f` to `0x94`, consistent with source line numbers.

The filename uses Thumb ADR instructions, so an absent raw u32 pointer to its
address did not imply an absent consumer. All six returns are stored in
consecutive words starting at `B = 0x0e5e8b0c`.

| Call VMA | r1 / RBM local ID | Stored at | Indexed body offset | Bytes | Role inferred from later use/logs |
| --- | ---: | --- | --- | ---: | --- |
| `0x0e008ca6` | 20 | `B+0x00` | `0x2b66474` | 1,508 | Zoom in |
| `0x0e008cc4` | 21 | `B+0x04` | `0x2b66a58` | 1,432 | Candidate dimmed zoom in; not drawn in this function |
| `0x0e008cde` | 22 | `B+0x08` | `0x2b66ff0` | 1,468 | Zoom out |
| `0x0e008cf8` | 23 | `B+0x0c` | `0x2b675ac` | 1,380 | Candidate dimmed zoom out; not drawn in this function |
| `0x0e008d12` | 24 | `B+0x10` | `0x2b67b10` | 144 | Zoom bar |
| `0x0e008d2c` | 28 | `B+0x14` | `0x2b69050` | 1,824 | Conditional additional bitmap; exact role unknown |

Body offsets are in the decompressed resource bank. The directory identifies
the 20,952-byte RBM at `0x2b65398`, with 30 records. All six selected bodies
have matching table/body IDs and exact indexed extents. Their complete hashes
are retained locally in `out/imrc_resource_index/browser_selected.json`;
ID 20 hashes to
`74e1ce26539c09eb859c61cfcf9738f37d3010df359d6513fac4e99e54d7fe9a`.

## Drawing and limits of the link

Calls at `0x0e008dee`, `0x0e008e16` and `0x0e008e3e` use the context's
`+0xe4` interface, table slot `+0x18c`, with register arguments
`(graphics_handle, x, y, returned_bitmap)`. Their bitmap arguments are the
saved returns for IDs 20, 22 and 24 respectively. A zero return logs a failure
string naming `SFBalDrawBitmap` and `m_pBmpZoomIn`, `m_pBmpZoomOut` or
`m_pBmpZoomBar`. The branch at `0x0e008f86` gates the same interface call
at `0x0e008f9e` using ID 28. Success reaches two additional internal calls and
returns one; checked graphics-call failures return zero.

Layout arithmetic reads returned-object fields `+8` and `+0xc`, suggesting
width/height. These are host-created object fields, not demonstrated offsets
inside the encoded RBM body. The resource-selection returns are dereferenced
without local null checks on these paths; their allocation/error contract is
unknown.

Matching filename, ordinal arguments and body IDs strongly supports this RBM
as the browser resource source. The host callback has not been followed, so
the exact root/theme resolution and any ID transformation inside it remain
unverified. No application-wide ID scheme follows from these six local IDs.
The wider native menu, Rsrc2 mapping, pixel conversion and TkTool tail internals
remain separate questions.

## Reproduce

After the existing ShpApp ELF import, run the probe with an absent output path:

```sh
XDG_CONFIG_HOME=/tmp/bcm2153-ghidra-config \
XDG_CACHE_HOME=/tmp/bcm2153-ghidra-cache \
/opt/ghidra_12.1_PUBLIC/support/analyzeHeadless \
  "$PWD/out/ghidra_shpapp/projects" BCM2153_ShpApp \
  -process ShpApp_embedded.elf -noanalysis -readOnly \
  -scriptPath "$PWD/tools/ghidra_scripts" \
  -postScript ProbeShpAppBrowserResources.java \
  "$PWD/out/rea_shpapp/browser_resources.ghidra.json"

python3 tools/imrc_resource_index.py /home/joe/thing/Rsrc_B5310_China.rc1 \
  --rbm-id System/Rsrc/Bmp/Black/SFBrowserRsrc.rbm 20 \
  --rbm-id System/Rsrc/Bmp/Black/SFBrowserRsrc.rbm 21 \
  --rbm-id System/Rsrc/Bmp/Black/SFBrowserRsrc.rbm 22 \
  --rbm-id System/Rsrc/Bmp/Black/SFBrowserRsrc.rbm 23 \
  --rbm-id System/Rsrc/Bmp/Black/SFBrowserRsrc.rbm 24 \
  --rbm-id System/Rsrc/Bmp/Black/SFBrowserRsrc.rbm 28 \
  --extract-dir out/imrc_resource_index/files \
  --out out/imrc_resource_index/browser_selected.json
```

The two XDG variables only redirect temporary tool preferences/cache away from
the read-only home configuration. The project is opened read-only and changes
are discarded; reports and extracted bytes remain in ignored `out/`.
