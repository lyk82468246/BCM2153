# Widget script names and native adapters in ShpApp

The FactoryFs packages' window and event API names also occur in ShpApp records
that contain native callback pointers. A bounded pass follows three callbacks
and three helpers. This connects the package-facing names to native adapters;
it does not prove runtime registration, event delivery or the final method targets.

## Identity and table records

Parent `ShpApp.app` SHA-256:
`6f5a455adb73a22eef95f1c7f01ee4de6d4a2c812c394f43c791beb774dcbab1`.
Embedded ELF starts at parent `0x192e`, SHA-256
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Within the initialized sections examined here, parent offset is
`VMA - 0x0e000000 + 0x192e`.

Ten consecutive 16-byte records span `[0x0e532754,0x0e5327f4)`. Each contains
an ASCII name pointer, a word valued `0x14` or `0x18`, a Thumb callback pointer,
and a zero word. The last two non-pointer fields' meanings remain unknown.

| Name | Record VMA | Callback pointer |
| --- | --- | --- |
| `setPreferenceForKey` | `0x0e532754` | `0x0e0ed5ef` |
| `preferenceForKey` | `0x0e532764` | `0x0e0ed6db` |
| `openURL` | `0x0e532774` | `0x0e0ed821` |
| `maximizeWindow` | `0x0e532784` | `0x0e0ed8b1` |
| `resizeWindow` | `0x0e532794` | `0x0e0ed93d` |
| `setScroll` | `0x0e5327a4` | `0x0e0ed997` |
| `checkIdleStatus` | `0x0e5327b4` | `0x0e0ed9db` |
| `getCurrentDirection` | `0x0e5327c4` | `0x0e0eda31` |
| `getWidgetInfo` | `0x0e5327d4` | `0x0e0eda87` |
| `addEventListener` | `0x0e5327e4` | `0x0e0edadf` |

The next four words are zero. A nearby descriptor at `0x0e532744` points to
`"widget"`; a word at `0x0e5e1ecc` points to the first record. The common
diagnostic-source string at `0x0e0ed800` is
`..\\..\\runtime\\WidgetObject.cpp`. These corroborate a widget-binding role;
the record lookup/installation consumer has not yet been traced.

## Resize arguments and indirect object

`resizeWindow` selects Thumb entry `0x0e0ed93c`. Incoming `r0` is retained as
an execution-context candidate; incoming `r3` supplies an argument-list object.
The helper at `[0x0e338aec,0x0e338b00)` checks the requested index against its
word `+4`, then reads from `read32(list)+index*8`. An out-of-range index returns
the raw value `10`. The callback requests indices 0 and 1 and converts each
through `0x0e338db4`. That helper has a shifted/tagged integer path and object
conversion fallback; complete conversion semantics remain unproven.

The callback obtains a value via `0x0e323488` then `0x0e339a88`. Let the latter
result be `R`, and `W=read32(R+0x44)`. It returns raw value `10` when `W` is zero.
The three-instruction helper at `0x0e14593c` returns
`N=read32(read32(W+0x10))`. The callback then obtains
`H=read32(read32(N+4)+8)` and dispatches through `read32(read32(H)+0x20)`,
passing `(H, converted_arg0, converted_arg1)`.

This is consistent with width/height from the packaged calls such as Baidu's
`resizeWindow(188,86)`. The callback ignores the indirect method's register result
and converts its own constant `1` through `0x0e3236f6`. The raw values `10`, `2`
and converted `1` must not be labeled native error/success codes without recovering
the JavaScript value ABI.

`H` is an object found through this chain, not the saved context `C+0xe4`
interface from the [graphics adapters](shpapp_graphics.md). Its method may be
implemented inside ShpApp or supplied externally; this pass establishes neither.

## Direction and event registration

`getCurrentDirection`, Thumb entry `0x0e0eda30`, uses the same `W/N/H` chain
and calls `read32(read32(H)+0x54)` with `H` in `r0`. A zero result returns raw
value `2`. A nonzero result is passed to a string-construction candidate at
`0x0e0feaf2`, then to the release wrapper `0x0e003e86` with source-file/line
arguments (`WidgetObject.cpp`, `0xfe`). The temporary string is converted through
`0x0e322fc4` and cleaned up. This supports a string-valued direction adapter,
but does not prove the provider returns exactly `horizontal` or `vertical`.

`addEventListener`, Thumb entry `0x0e0edade`, obtains argument 1 first and
passes it through a callback-wrapper candidate at `0x0e27de86`. If that wrapper
and the subsequent target from `0x0e145634(W)` are nonzero, it obtains argument 2
through conversion helper `0x0e338ff2`, and argument 0 through the string path
`0x0e338f18`/`0x0e1b3542`. The resulting values reach `0x0e1e5f12`, followed by
cleanup. This ordering fits event name, listener and flag from the packaged
calls. The [event-registry follow-up](shpapp_widget_events.md) now follows matching
entry replacement, record construction and listener dispatch. Supported Widget
event names, event origins and JavaScript callback invocation remain unresolved.

An exact ASCII/UTF-16LE search of this ELF found no `WidgetDefault.ini`,
`WidgetCount`, `DEFAULT_WIDGET_`, `widgetmodechange`, `widgetendkey`, or the
selected Baidu package name/ID. These are bounded negative searches, not proof
that ShpApp cannot consume them indirectly or that another module owns them.

## Reproduce and limits

```sh
XDG_CONFIG_HOME=/tmp/bcm2153-ghidra-config \
XDG_CACHE_HOME=/tmp/bcm2153-ghidra-cache \
/opt/ghidra_12.1_PUBLIC/support/analyzeHeadless \
  "$PWD/out/ghidra_shpapp/projects" BCM2153_ShpApp \
  -process ShpApp_embedded.elf -noanalysis -readOnly \
  -scriptPath "$PWD/tools/ghidra_scripts" \
  -postScript ProbeShpAppWidgetBindings.java \
  "$PWD/out/rea_shpapp/widget_bindings.ghidra.json"
```

The hash-guarded script records all ten name/callback records and six selected
functions, requiring a new absolute output path. Ghidra 12.1 completed all six
decompilations, 198 instructions total, and discarded project changes. ARM
objdump 2.45.50 independently corroborates the Thumb sequences. Untyped
pseudocode omits live register arguments and invents some helper parameters;
register traces take precedence. This is ordinary Ghidra evidence, not REA
Evidence, and no native code ran. The loader language does not prove a CPU model.

Full reports, seed search and listings remain in `out/rea_shpapp/`. The preceding
[package pass](factoryfs_widgets.md) separately retains REA JavaScript Evidence.
The registry at `0x0e1e5f12` is partially covered by the follow-up. The construction
of `H` remains a separate target; there is no evidence that the earlier graphics
table implements its methods.
