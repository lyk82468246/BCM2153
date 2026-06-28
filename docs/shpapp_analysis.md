# ShpApp / FimBIN notes

`ShpApp.app` appears to be a Samsung FimBIN container with an embedded native ARM
ELF payload.

Generated locally with:

```sh
python3 tools/shpapp_elf_survey.py /home/joe/thing/ShpApp.app --out out/shpapp_elf_survey
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
