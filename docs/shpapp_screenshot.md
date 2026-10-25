# ShpApp screenshot and bitmap descriptor path

A bounded static pass follows a ShpApp debug screenshot save routine. It gives
independent evidence about the object returned by a host bitmap callback and
the fields used by the JPEG encoder. It does not decode RBM mode 2 or prove the
host callback's implementation.

## Identity and method

The parent `ShpApp.app` SHA-256 is
`6f5a455adb73a22eef95f1c7f01ee4de6d4a2c812c394f43c791beb774dcbab1`.
The embedded ELF at parent offset `0x192e` has SHA-256
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
The read-only Ghidra 12.1 probe uses two analyst-selected Thumb islands:
`[0x0e00069a,0x0e000824)` and `[0x0e000924,0x0e000986)`. Ghidra decoded 231
instructions and completed the bounded decompilation. ARM objdump 2.45.50
independently corroborates these instructions. The saved loader language does
not identify the physical CPU; this is ordinary Ghidra evidence, not a REA
function dossier. No firmware code ran.

## Capture and descriptor fields

The routine first calls a context callback at `+0x0c`, table slot `+0x58`, and
requires a positive result. It then calls the incoming host interface at
context `+0xe4`, table slot `+0x170`, with `(0, 0, 0, 0, &"Src\\SHP\\SFBalDebugShp.c", 0x300)`.
Let `S = read32(0x0e5e4964)` be the screenshot state, `E = read32(S+0x2c)`
and `D = read32(E+8)` its nested image descriptor. The returned pointer is
treated as a bitmap/capture object. On success the
routine reads these object fields and writes them into a host image descriptor
at `D`:

| Returned object field | Destination descriptor field | Observed use |
| --- | --- | --- |
| `+0x08` | `+0x1c` | copied dimension-like value |
| `+0x0c` | `+0x20` | copied dimension-like value |
| `+0x24` | `+0x34` | copied format/stride-like value; exact type unknown |
| byte `+0x10` | byte `+0x0d` | copied flags/channel-like byte |
| `+0x14` | `+0x00` | copied pointer/data-like field |
| `+0x18` | `+0x30` | copied size/stride-like value |

The earlier browser resource pass observed the same returned-object offsets
`+8` and `+0xc` in layout arithmetic. This screenshot path is stronger evidence
that those two fields are dimension-like, but it does not establish their
meaning inside an encoded RBM body. The descriptor's complete type and host
allocation contract remain unknown.

Immediately before the copies, a host callback at context `+0x04`,
table slot `+0x24` receives `(D, 0, 0x3c, 4, &"Src\\SHP\\SFBalDebugShp.c", 0x30a)`.
Clearing a 60-byte descriptor is a plausible interpretation; the provider's
implementation is unknown.

## Encode and file write

The routine calls another host interface at context `+0x20c`, table slot
`+0x14`, with `(8, S, &encoded_buffer, &encoded_length, 5)`.
The roles of the two output words follow from their subsequent use as the
file-write buffer/length and the conditional buffer-release argument:

1. A path is formatted as `"/User/Br_ScreenShot/"` plus `"%s%05d.jpg"`.
2. `SFBalFileCreate` failure is logged at string VMA `0x0e0008b0`.
3. A file write receives the returned file handle, the encoded buffer/size
   pair, and logs failure at `0x0e0008e8`.
4. The handle is closed. A successful path logs
   `SFBalDebugSaveScreenShot: Save Screen to file.[%s][Size:%d]` at
   `0x0e000a50`.

The quality-like value passed to the encoder is `5` in the bounded instruction
sequence. This supports the function's role as a JPEG screenshot adapter; it
does not establish the host encoder's ABI or JPEG quality scale. Cleanup paths
release the encoded buffer, close a nonnegative file handle and release the
captured object through context `+0xe4`, table slot `+0x1c0`.

## Consequence for RBM work

The screenshot path confirms a host-owned descriptor between capture and file
encoding. It does not call the browser RBM selector directly and does not expose
the mode-2 decompressor. Therefore the two fitting mode-2 hypotheses remain
ambiguous. The dimensions-like fields at `+8/+0xc` should not be confused with
the 40-byte RBM header's width/height words until the host callback is traced.

## Reproduce

After the existing read-only ShpApp project import:

```sh
XDG_CONFIG_HOME=/tmp/bcm2153-ghidra-config \
XDG_CACHE_HOME=/tmp/bcm2153-ghidra-cache \
/opt/ghidra_12.1_PUBLIC/support/analyzeHeadless \
  "$PWD/out/ghidra_shpapp/projects" BCM2153_ShpApp \
  -process ShpApp_embedded.elf -noanalysis -readOnly \
  -scriptPath "$PWD/tools/ghidra_scripts" \
  -postScript ProbeShpAppScreenshot.java \
  "$PWD/out/rea_shpapp/screenshot.ghidra.json"
```

The exact local report and console/script logs remain ignored under
`out/rea_shpapp/`. The probe guards the ELF SHA-256, writes only to an absent
absolute output path and discards read-only project changes.
