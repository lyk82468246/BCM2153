# Registered control factory and event-bridge ownership

The registered outgoing interface has a control-creation entry at table slot
`+0x34`. It reaches a factory that distinguishes `Browser`, `Widget` and
`Messenger`, initializes geometry, and creates the event-name bridge from the
preceding pass. The returned control exposes that bridge through its own table
slot `+0x20`. This establishes static interface ownership; it does not demonstrate
a widget launch or an actual host-supplied event name.

## Input and verification

The embedded ShpApp ELF has SHA-256
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Parent identity/address conversion are documented in
[listener wrapper](shpapp_widget_listener.md). The hash-guarded
`ProbeShpAppControlFactory.java` covers six Thumb functions, with explicit code
islands excluding literal pools. All six decompiled in Ghidra 12.1, with 413
instruction addresses matching independently bounded ARM objdump 2.45.50 output.
Five pointer words and three category literals were checked. The physical ELF
hash matched and read-only project changes were discarded.

These are ordinary Ghidra/objdump observations, not REA Evidence or runtime
execution. Analyst labels and inferred signatures are inputs/interpretations.
Long inferred parameter lists in pseudocode are not a recovered interface ABI.
Register and stack flow take precedence.

## From the registered interface to the factory

The [entry/registration pass](shpapp_host_abi.md) established a 20-slot outgoing
table at `B = 0x0e5e8bbc`, referenced by the registered object at `B-0x0c`.
At `0x0e00aba0`, registration stores `read32(0x0e00ac44)` at `B+0x34`.
That literal is `0x0e28d791`, the Thumb pointer to entry `0x0e28d790`.
This follows the existing registration instructions; the runtime BSS table is
not stored as an initialized array in the input ELF.

The factory entry consists of `[0x0e28d790,0x0e28d824)` and
`[0x0e28d868,0x0e28d884)`. It performs conditional global setup and distinguishes
the incoming name against Browser/Messenger for a separate helper selector.
It also accepts an optional incoming object, calls one of its table methods
when nonnull, and obtains a token-like value through `0x0e0c67a6`. A raw `-1`
result selects raw failure `-2`; other values are passed onward with the caller's
arguments to `0x0e28ce98`. Meanings of the token and selector remain unknown.

The outer output pointer is loaded from entry stack `+8` (argument index 6 when
register arguments are indices 0..3). The outer function writes zero through it
for signed results `<=0`. On positive results it calls `0x0e2916b8` and copies
the local created-object pointer to the output. It returns the inner raw result.
The post-create helper's full effects were not recovered. A positive static
return branch is not evidence of successful allocation or launch on a device.

## Named creation and category byte

`[0x0e28ce98,0x0e28cf36)` clears its output pointer, allocates `0x128` bytes
through `0x0e003fdc`, and calls `0x0e28cde4`. It compares incoming register r0's
string against three literals, then writes control byte `+0x28`:

| Input name | Literal VMA | Stored byte |
| --- | --- | --- |
| `Browser` | `0x0e28d0c4` | `0` |
| `Widget` | `0x0e28d0cc` | `1` |
| `Messenger` | `0x0e28d0d4` | `2` |
| Other | No match | `3` |

Calls go to `0x0e311898`, an ARM byte/string comparison routine. A bounded
listing shows byte/word comparison, zero-byte handling and a difference return.
The probe checks exact literal bytes; it does not execute any comparison.
The ARMv5T objdump decoder makes its `bx lr` instructions explicit. This decoding
choice does not establish the chip's physical instruction-set revision.

The routine then calls `0x0e28cbdc`. A signed result `<=0` calls the object's
table slot `+4` and leaves the output cleared. A positive result stores the
object pointer in the caller's output. The caller can therefore request a
Widget category through this factory, but the default-widget installer and
packaged `.wgt` launch path have not been linked to that request.

## Construction and initialization share one control

`[0x0e28cde4,0x0e28ce98)` installs final tables at control offsets `+0`, `+4`
and `+8`. At `+0` it writes `0x0e58c1c0` through literal `0x0e28d0bc`; the other
two are that base plus `0x180` and `0x260`. It clears control words `+0x2c`,
`+0x30`, `+0x78`, `+0x7c`, `+0x80` and selected other fields, and sets words
`+0x34/+0x38/+0x3c/+0x50` to `0xffffffff`. These selected writes do not define
the full object layout or multi-interface casting rules.

The initializer has main prefix `[0x0e28cbdc,0x0e28cc72)` and continuation
`[0x0e28ccdc,0x0e28cde4)`. The intervening bytes include literals and belong
outside the selected function body. It stores caller values into control
`+0x34`, `+0x40..+0x4c`, and `+0x54`. It constructs a subordinate object through
`0x0e1524a2` at control `+0x2c` and calls `0x0e294516(control,control+0x30)`.
Zero from the former, or signed `<=0` from the latter, takes failure exits.
Their full constructors/provider selection are not examined in this probe.

After those gates, on the same control pointer it:

1. Calls `0x0e28ea42` at `0x0e28cd78`, forwarding the stored surface/geometry
   arguments into the [graphics-to-resize path](shpapp_event_bridge.md).
2. Allocates `0x308` bytes and calls `0x0e297282`, storing the returned object
   at control `+0x78`.
3. Allocates 100 bytes and calls the known event-name bridge constructor
   `0x0e29257a(allocation,control,read32(control+0x78))`, storing the returned
   bridge at control `+0x7c`.
4. Creates additional helpers, clears selected flags, and returns raw `1`.

There is no category-byte branch around those three calls in the examined
initializer. They are shared control setup, not evidence of a Widget-only
implementation or a distinct widget event source.

## Returned control exposes the name bridge

The control's table word at `0x0e58c1e0` is raw Thumb pointer `0x0e28ca4d`.
It is slot `+0x20` relative to constructed table `0x0e58c1c0`.
`[0x0e28ca4c,0x0e28ca50)` simply returns `read32(control+0x7c)`.
The returned bridge uses table `0x0e58c50c`, whose slot `+0x128` reaches
the previously verified incoming-name method `0x0e2941ea`.

The static connection is therefore registered table `+0x34` → created control
→ control slot `+0x20` → bridge slot `+0x128` → generic named-event construction.
This resolves ownership of the two previously separate native paths. The later
[document probe](shpapp_document_receiver.md) resolves the constructed receiver's
self-link. Host callers, concrete strings and custom widget event delivery
remain unknown.

## Reproduce and next boundary

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with `ProbeShpAppControlFactory.java` / `.class` and an absent JSON destination.
Keep `-noanalysis -readOnly`. Local reports are
`out/rea_shpapp/control_factory.ghidra.json`, `.console.log`, `.objdump.txt`,
`.verification.json`, `control_factory_registration.objdump.txt` and
`control_factory_string_compare.objdump.txt`. Candidate searches are
`webcontrol_init_candidates.json`, `webcontrol_factory_candidates.json`, and
`webcontrol_expose_candidates.json`; they are not complete call graphs.

The subsequent [provider probe](shpapp_control_provider.md) resolves control
`+0x30` construction and the frame/geometry fields. Document construction,
assignment and the self-link are followed in the [document probe](shpapp_document_receiver.md).
How the external host uses the exposed name bridge remains open. A physical
orientation change, native main-menu ownership, RBM mode 2, global IDs and Rsrc2
remain unresolved. Cellular/baseband
paths remain excluded.
