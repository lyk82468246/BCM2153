# ShpApp graphics adapters and the host boundary

Eight small Thumb adapters and two callers make the browser drawing interface
more concrete. They still dispatch into host tables: this pass does not locate
an RBM decoder or identify the host implementation.

## Identity and method

Parent `ShpApp.app` SHA-256:
`6f5a455adb73a22eef95f1c7f01ee4de6d4a2c812c394f43c791beb774dcbab1`.
The ELF begins at parent offset `0x192e`, SHA-256
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
For the initialized sections used here, ELF offset is VMA minus `0x0e000000`.

`ProbeShpAppGraphics.java` selects ten explicit function ranges, decodes 203
instructions and completes all ten Ghidra 12.1 decompilations. ARM objdump
2.45.50 independently supplies the bounded instructions and call-site checks.
The project is read-only; changes are discarded. This is ordinary Ghidra
evidence, not REA Evidence, and no target code ran. Function labels are analyst
inputs; inferred pseudocode signatures sometimes omit live register arguments
or return values at indirect tail calls. The observations below follow registers.

Let `C = read32(0x0e5e8c0c)` and
`G[k] = read32(read32(read32(C+0xe4))+k)`.
The shared literal at `0x0e0033c0` points to the saved context word.
`F` denotes `"Src\\SHP\\SFBalGraphicsShp.c"` at VMA `0x0e0033a4`,
parent offset `0x4cd2`.

## Observed adapters

| Thumb entry | Host slot | Register/data behavior |
| --- | --- | --- |
| `0x0e003016` | `G[0x3b4]` | Tail call `(incoming_r0,F,0x2e)`; browser saves returned `r0` as its drawing handle and rejects `-1` |
| `0x0e00302e` | `G[0xb0]` | Calls with incoming `r0`; writes returned object's word `+0x34` to incoming `r1` |
| `0x0e003048` | `G[0xb0]` | Same, reading word `+0x38` |
| `0x0e0030c8` | `G[0x38]` | Tail call preserves incoming `r0`; callers compare returned `r0` to `1` |
| `0x0e0030d6` | `G[0x3d0]` | Tail call `(incoming_r0,0,F,0x5a)` |
| `0x0e0030f6` | `G[0x38]`, then `G[0xb0]` | If first result is `1`, writes second result's word `+0x308` to incoming `r1`, returns `1`; otherwise returns `0` without writing |
| `0x0e003132` | `G[0x3dc]` | Tail call preserves incoming `r0` |
| `0x0e003146` | `G[0x3e0]` | Forwards four registers and fifth stack argument |

The browser call at `0x0e008c74` supplies its incoming fourth argument to
`0x0e003016`. The resulting handle is used by the previously established bitmap
drawing slot `G[0x18c]`. On its successful return path, it calls
`0x0e003132(handle)` and then `0x0e0030d6(handle)` at `0x0e008fb2/8`.
Acquire/commit/end are useful candidate roles for these wrappers, but a flush,
release or transaction contract cannot be inferred from this order alone.

## Coordinates and format candidate

At `0x0e0114c2`, a caller checks the `G[0x38]` predicate. When it returns `1`,
calls at `0x0e0114ce/0x0e0114d6` obtain the `+0x34/+0x38` words through the
adapters. At `0x0e0114da..0x0e0114e8` those words are added to the first two
words of a local layout value. Another caller repeats the pattern at
`0x0e011682/0x0e01168a`. Thus a coordinate-offset role is supported;
these fields are not established as bitmap width/height. The independent
[screenshot descriptor](shpapp_screenshot.md) copies bitmap-like fields `+8/+0xc`
from a different returned object. The two layouts must remain separate.

The complete caller `[0x0e298b7e,0x0e298c1a)` reads the `+0x308` word via
`0x0e0030f6`, divides it by eight with signed rounding toward zero, and multiplies
it by incoming `r1`. When the predicate fails it uses `2` instead. One inspected
caller at `0x0e298c64..0x0e298c6e` supplies a product of two dimensions-like
words as `r1`. Bits-per-pixel and bytes-per-pixel in an allocation-capacity check
are therefore plausible interpretations, not recovered types. The comparison
providers at `0x0e003e00/0x0e003e0e/0x0e003e22` themselves dispatch to another
host table; their units and complete semantics are unknown.

The complete caller `[0x0e01eb40,0x0e01eb6a)` calls its object's table slot
`+0x40` to fill four stack words, then forwards the object's word `+4` and those
four words through `0x0e003146`. This supports a rectangle-operation candidate
for `G[0x3e0]`. The operation's purpose and coordinate/extent convention remain
unknown.

## Reproduce and remaining boundary

Use a new absent output path if the report already exists:

```sh
XDG_CONFIG_HOME=/tmp/bcm2153-ghidra-config \
XDG_CACHE_HOME=/tmp/bcm2153-ghidra-cache \
/opt/ghidra_12.1_PUBLIC/support/analyzeHeadless \
  "$PWD/out/ghidra_shpapp/projects" BCM2153_ShpApp \
  -process ShpApp_embedded.elf -noanalysis -readOnly \
  -scriptPath "$PWD/tools/ghidra_scripts" \
  -postScript ProbeShpAppGraphics.java \
  "$PWD/out/rea_shpapp/graphics.ghidra.json"
```

The probe guards the ELF hash and requires an absent absolute output path.
Local reports include `graphics.ghidra.json`, `graphics.console.log`,
`graphics.provenance.json`, `graphics_wrappers.objdump.txt`, and the bounded
`callsite_e011492.objdump.txt` / `callsite_e298b7e.objdump.txt` listings under
`out/rea_shpapp/`. A whole-section forced-Thumb listing was used only to find
candidate direct calls; embedded data and ARM islands make it unsuitable as a
complete call graph or proof of absent references.

All eight adapters reach incoming host callbacks. They do not expose compressed
RBM bytes. Mode-2 literal origin and flagged commands, global resource IDs,
Rsrc2 mapping, host table providers and native-menu ownership remain unresolved.
The next independent filesystem question is the metadata and entry paths inside
the three indexed FactoryFs widget packages; no package execution is required.
