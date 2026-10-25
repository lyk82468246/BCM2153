# Widget-reachable event registration and dispatch

The `WidgetObject` add-listener adapter reaches a general event registry at
`0x0e1e5f12`. Registration removes a matching entry before appending a new one;
dispatch shares the listener list and calls matching listener objects. This
establishes a native registration/dispatch path, while the origin and delivery
of `widgetmodechange` and `widgetendkey` remain unknown.

## Identity and method

Parent `ShpApp.app` SHA-256:
`6f5a455adb73a22eef95f1c7f01ee4de6d4a2c812c394f43c791beb774dcbab1`.
Embedded ELF starts at parent offset `0x192e`, SHA-256
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Within initialized sections, parent offset is `VMA - 0x0e000000 + 0x192e`.

The hash-guarded read-only `ProbeShpAppWidgetEvents.java` selects eight complete
Thumb ranges. Ghidra 12.1 completed all eight decompilations, 289 instructions;
ARM objdump 2.45.50 independently corroborates the bounded instructions.
Names and boundaries are analyst inputs. Register traces take precedence over
untyped pseudocode signatures. No target code ran; project changes were
discarded. These are ordinary Ghidra/objdump observations, not REA Evidence.

## Registration and record layout

Let `D` be the registry receiver from the previously examined
[WidgetObject adapter](shpapp_widget_bindings.md). Its listener container is at
`D+0x298`. `0x0e1e5f12` receives `(D, name_object, &listener, flag)`:

1. It compares the name with two canonical registry names and invokes separate
   bookkeeping helpers when either matches.
2. It calls `0x0e1e5e52(D, name_object, listener, flag)`. That routine walks
   entries and removes the first matching name/listener/flag triple, returning
   immediately after removal. It does not remove every listener of that name.
3. It takes the incoming listener pointer, clears the caller's pointer word,
   allocates 24 bytes and calls the constructor at `0x0e1f906c`.
4. It allocates a 12-byte list node holding the record pointer, then appends it
   to `D+0x298` through `0x0e1a47f2`.

The append helper links a new node after the previous tail, initializes its next
link to zero and increments the list count. Re-registering an existing triple
therefore replaces it at the end of the observed list order; it does not simply
return on finding a duplicate. This says nothing about concurrent callers or
failure handling inside the allocator.

The record constructor `[0x0e1f906c,0x0e1f909a)` writes:

| Offset | Written value / observed role |
| --- | --- |
| `+0x00` | `1`; reference-count-like word |
| byte `+0x04` | `0`; lifecycle role not established |
| `+0x0c` | `read32(name_object+4)`; pointed word incremented when nonzero |
| `+0x10` | listener pointer taken from caller's word |
| byte `+0x14` | incoming flag |
| byte `+0x15` | `0`; dispatch later skips records where this is nonzero |

This is not a complete recovered C struct. The constructor does not initialize
every byte. The name comparator at `0x0e336ae6` compares words `+4` of its two
arguments. Record comparisons pass `record+8`, so the effective comparison uses
`record+0x0c`: identity comparison of a shared string representation, not a
byte-by-byte event-name comparison. Its complete interning contract is unknown.

## The two special names

`0x0e1ed8d0` reads the name-registry pointer stored at `0x0e5fc834`.
The registration/removal code compares names at registry offsets `+0x1b4`
and `+0x24`. A bounded initialization trace maps them as follows:

| Registry offset | Literal VMA | Literal | Initializer call site |
| --- | --- | --- | --- |
| `+0x24` | `0x0e1ed45c` | `beforeunload` | `0x0e1ed072` |
| `+0x1b4` | `0x0e1ed648` | `unload` | `0x0e1ed2c0` |

Initialization calls `0x0e32a646`, which stores the constructed string
representation at destination `+4` and returns the destination. This supports
tracking the constructor's accumulated registry offsets. The full name registry
and its initialization timing are outside this pass.

Registration uses helpers `0x0e1e5eea/0x0e1e5efe` for these names; matching removal
uses `0x0e1e5e2a/0x0e1e5e3e`. Their full bookkeeping effects were not recovered.
These document-event names show why this should not be called a dedicated
Widget-only registry. The examined registration path shows no allowlist that
rejects other names.

## Dispatch and its limits

`[0x0e1e5d76,0x0e1e5e2a)` receives `(D, event_object, flag)` and returns early
when the container is empty. Otherwise it obtains a local shared container:
the copy helper `0x0e354812` copies its backing pointer and increments the backing
word. Deep-copy and mutation guarantees depend on helpers not fully examined.

The loop reads each record through a node's `+8` pointer and checks:

- Name identity between `record+8` and `event_object+0x0c`.
- Record byte `+0x14` equals the dispatch flag.
- Record byte `+0x15` is zero.

When all three hold, it calls
`read32(read32(listener)+8)(listener, event_object, 1)`.
This is the concrete native callback boundary. A nonzero `+0x15` excludes a
record, but how and when that byte changes remain unresolved. The loop also
updates a context obtained through `D+0xd0`, then restores selected context
fields; complete timing/reentrancy semantics are unknown.

The package calls with third argument `false` fit the stored flag and dispatch
filter. Standard capture/bubbling semantics are plausible but unproven here.
There is still no demonstrated chain from a hardware event or window orientation
change to this dispatcher. A subsequent [listener-wrapper probe](shpapp_widget_listener.md)
resolves the constructed object's slot +8 into handleEvent/direct-call selection
and a script-call bridge; execution of a particular JavaScript body is unproven.

## Reproduce and next boundary

```sh
XDG_CONFIG_HOME=/tmp/bcm2153-ghidra-config \
XDG_CACHE_HOME=/tmp/bcm2153-ghidra-cache \
/opt/ghidra_12.1_PUBLIC/support/analyzeHeadless \
  "$PWD/out/ghidra_shpapp/projects" BCM2153_ShpApp \
  -process ShpApp_embedded.elf -noanalysis -readOnly \
  -scriptPath "$PWD/tools/ghidra_scripts" \
  -postScript ProbeShpAppWidgetEvents.java \
  "$PWD/out/rea_shpapp/widget_events.ghidra.json"
arm-none-eabi-objdump -d -M force-thumb \
  --start-address=0xe1ed040 --stop-address=0xe1ed430 \
  out/shpapp_elf/ShpApp_embedded.elf
```

The second command deliberately prints only the constructor prefix needed for
the two mappings, not its complete function. Use a new output path for repeated
Ghidra runs. Full reports stay in `out/rea_shpapp/`: `widget_events.ghidra.json`,
console log, `widget_events.provenance.json`, `event_name_init.objdump.txt` and
`widget_event_seed.objdump.txt`.

Registration/removal/dispatch mechanics are now partially answered. The
[constructed listener slot +8](shpapp_widget_listener.md) has since been resolved.
Remaining targets are callers of `0x0e1e5d76` and the separate resize/direction
receiver construction. The default-widget installer,
global resource IDs, RBM mode 2, Rsrc2 and native-menu ownership remain unknown.
