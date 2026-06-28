# ShpApp / FimBIN notes

`ShpApp.app` appears to be a Samsung FimBIN container with an embedded native ARM
ELF payload.

Generated locally with:

```sh
python3 tools/shpapp_elf_survey.py /home/joe/thing/ShpApp.app --out out/shpapp_elf_survey
```

The entry region can be probed without opening Ghidra:

```sh
python3 tools/shpapp_entry_probe.py \
  /home/joe/thing/ShpApp.app \
  --out out/shpapp_entry_probe
```

The generated `out/` files are local-only. This page keeps the public-safe
summary.

## Container header observations

- File starts with UTF-16LE-like magic `FimBIN`.
- File size is `0x5e7078` bytes.
- Header word at offset `0x78` is `0x005e6bf8`, close to total file size.
- Header area includes UTF-16LE path-like string `\Exe` at offset `0x8c`.

## Embedded ELF

The first ELF header starts at file offset `0x192e`.

| Field | Value |
| --- | ---: |
| Class | ELF32 |
| Endian | little |
| Type | executable |
| Machine | ARM (`0x28`) |
| Entry | `0x0e00ad0c` |
| Flags | `0x4000016` |
| Program headers | 1 |
| Section headers | 6 |

Program header:

| Type | File offset | VMA | File size | Memory size | Flags | Align |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `LOAD` | `0x34` | `0x0e000034` | `0x5e4930` | `0x5fe188` | `0x80000007` | `0x20` |

Sections:

| Name | Address | Offset | Size | Flags |
| --- | ---: | ---: | ---: | ---: |
| `ER_RO` | `0x0e000034` | `0x34` | `0x5dee84` | `AX` |
| `ER_RW` | `0x0e5deeb8` | `0x5deeb8` | `0x5aac` | `WA` |
| `ZI` | `0x0e5e4964` | `0x5e4964` | `0x19858` | `WA` |

## Entry code

The entry address `0x0e00ad0c` disassembles as Thumb code, even though the ELF
entry value itself is even. The first instructions are a normal Thumb prologue
and argument save sequence:

```text
0e00ad0c: b570  push {r4, r5, r6, lr}
0e00ad0e: 4605  mov  r5, r0
0e00ad10: 4c18  ldr  r4, [pc, #96]
```

The nearby code uses `blx` through pointers loaded from object/function tables,
which suggests the payload is entered by a Samsung/SHP host runtime and calls
back into host services.

## Entry Probe Findings

`tools/shpapp_entry_probe.py` maps the ELF entry `0x0e00ad0c` to ELF offset
`0xad0c` and `ShpApp.app` container offset `0xc63a`. A small window before the
entry contains data/text bytes, so automatic linear analysis should not be
trusted without seeding the real Thumb entry.

The entry block is strongly Thumb-only. Forced ARM decoding produces mostly
undefined or implausible instructions, while forced Thumb decoding gives a normal
prologue and host-callback sequence.

Important entry literals and effects:

- `0x0e00ad10` loads `0x0e5e8c0c`, which falls in `ZI+0x42a8`; the entry stores
  incoming `r0` and `r1` there. Treat this as an early global runtime-context
  slot.
- `0x0e00ad1c` loads `0x0e3bbc00`, an `ER_RO` string/log literal near the text
  "Webkit's DllBaseInit called".
- After an internal call at `0x0e311eec`, the entry walks through the incoming
  object and calls a function pointer reached through offset `0x24`, passing
  selector-like value `0xb8`, the `ER_RO` literal pointer, and the original
  context pointer.
- The nearby routine at `0x0e00ad30` reuses the saved globals and calls further
  host/runtime function pointers at offsets that include `0x3c`, `0x20`, and a
  pointer after adding `0xc0`.

This supports the current model that `ShpApp.app` is loaded by a host Samsung/SHP
runtime and receives a service table or context object, rather than running as a
standalone firmware image.

## Interpretation

The `ER_RO`, `ER_RW`, and `ZI` names look like ARM ADS/RVCT-style image regions,
and the entry code is Thumb. That suggests `ShpApp.app` carries a native ARM
application/runtime payload for the Samsung SHP layer rather than only script or
resource data.

Strings inside the image reference Samsung SHP platform code, Web/widget/RSS/XML
components, networking resource handlers, and UI manager classes. Treat this as
one of the primary native UI/runtime targets.

## Local Ghidra Workflow

Use `tools/shpapp_ghidra_import.sh` to create a local-only Ghidra project from
the embedded ELF. The helper extracts bytes from `ShpApp.app` offset `0x192e`
into `out/ghidra_shpapp/work/ShpApp_embedded.elf` and imports that ELF into
`out/ghidra_shpapp/projects/BCM2153_ShpApp.gpr`.

The script defaults to `-noanalysis`. This preserves a fast, stable import while
we decide how to seed the Thumb entry point and which memory ranges should be
analyzed as code versus bundled resources.

## Next questions

1. Is the embedded ELF loaded directly at `0x0e000000`, or relocated by the
   FimBIN loader?
2. Which image or loader consumes `FimBIN` containers?
3. How does this payload call into CAPI2/modem services?
4. Which `Rsrc*.rc*` resource IDs are consumed by this payload?
