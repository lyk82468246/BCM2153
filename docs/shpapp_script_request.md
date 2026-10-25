# Script src routing into document resource requests

Two bounded paths connect the initialized `src` attribute to script resource
requests: an owner method reads it and calls the input router, while an
attribute-update method compares the interned name and conditionally starts a
request. The request carries src and charset separately into a document-owned
loader, then a shared resource manager. This is a static path; no widget,
network request or package member was executed or opened by the target.

## Input and verification

Embedded ShpApp ELF SHA-256:
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Parent identity/address conversion are in the
[listener report](shpapp_widget_listener.md). Original hash-guarded probe
`ProbeShpAppScriptRequest.java` selects thirteen functions with explicit code
islands, including a separate src getter adapter. All decompiled; all 697
instruction addresses matched independent bounded ARM objdump 2.45.50 listings.
Ten expected words, one ASCII
literal, physical hash and Ghidra 12.1 read-only discard are checked locally.
These are ordinary local observations, not REA Evidence. Lifecycle, loader and
manager names are analyst descriptions; original types remain inferred.

## Owner methods obtain the src input

Owner O, helper `X=O+0x48` and interface `I=O+0x44` are defined in the
[input report](shpapp_script_inputs.md). The initialized owner table is
`V=read32(0x0e21bb4c)=0x0e5aa0c8`. Three verified slots are:

| Slot | Word address | Stored Thumb pointer | Role in this path |
| --- | --- | --- | --- |
| `V+0x120` | `0x0e5aa1e8` | `0x0e21b819` | owner route method |
| `V+0x1fc` | `0x0e5aa2c4` | `0x0e21b7d1` | attribute-update method |
| `V+0x230` | `0x0e5aa2f8` | `0x0e21be51` | direct owner src getter |

`0x0e21b818(O)` first calls its base helper, then invokes O's +0x230 getter
at `0x0e21b830`. That getter is `0x0e21be50`, already connected to `src` in
the [registry report](shpapp_script_registry.md). The method passes its output
temporary to `0x0e1f951e(X,&src)` at `0x0e21b838`. This completes the previously
unknown link from the src getter to the router's incoming name_value.

`0x0e21b7d0(O,record)` compares `read32(record+0x0c)` to the intern pointer
stored through `read32(0x0e21bb54)=0x0e5fb72c`, the initialized src registry
slot. Equality passes `record+0x14` to `0x0e1f971c(X,value)`. That handler calls
`0x0e1f96ea(X)` and, when it returns zero and the value predicate returns zero,
starts `0x0e1f94a6(X,value)` directly. The gate returns zero only when:

- X+0x11 is clear;
- the resource-state helper on X+0x0c returns -1;
- X+0x10 is clear;
- owner byte +0x20 has bit 6 set.

This proves a conditional src-update request path, not that a concrete document
was parsed, inserted, mutated or evaluated at runtime. The other attribute
comparison in this method is outside the recovered spelling result.

## The document owns the resource loader

Use D from the previous owner/document chain. The already bounded document
constructor allocates 0x74 bytes, calls `0x0e15e6f4(R,D)`, and stores R at
D+0xd4. The newly bounded constructor writes D at R+0x38 and the shared manager
M at R+0. Thus `read32(read32(D+0xd4)+0x38)=D` for this constructed loader.
This R differs from the frame loader L used in earlier reports.

Manager getter `0x0e15c6f2` lazily allocates 0x248 bytes through its constructor
and stores the result at `read32(0x0e15c798)+4`, with the literal pointing to
`0x0e5fc0c4`. This is a static singleton construction, not a physical-file read
of that BSS destination.

The existing request starter calls `0x0e15edcc(R,src,charset,X)`. That wrapper
passes `0x0e15ea32(R,2,src,charset,0,X)`. Class 2 selects the guarded `SCRIPT`
literal at `0x0e15eb34`; class 3 shares this diagnostic label, so the string
alone is not a unique type ID.

## Name preparation and shared manager boundary

Dispatcher `0x0e15ea32` prepares a resource-name object U through
`0x0e1e4782(&U,D,src)`. That helper first checks an input predicate. Its other
branches call `0x0e1a64b8` with D+0x128 or `0x0e1a64da` with D+0x128 and
`read32(D+0x470)+8`. These document-associated inputs support a name-resolution
role; complete URL/scheme/encoding semantics remain unknown.

After settings, bookkeeping and document gates, the dispatcher can substitute
a frame-associated document's loader for R. At `0x0e15ec34` it calls:

`0x0e15b97c(M,selected_R,2,&U,charset,0,X)`.

The three stack arguments are explicit at `0x0e15ec26..0x0e15ec2c`.
Pseudocode omits the last two at this call site; register/stack flow controls
the argument description. The bounded manager consumes the charset as its
fifth argument and zero as its sixth. No consumption of the seventh X is
established in this manager, so this call is not proof of callback registration.

Manager `0x0e15b97c` rejects an invalid/empty prepared-name predicate, calls
lookup `0x0e15b8fa`, applies additional gates, and either reuses an object or
calls `0x0e15b6de(2,&U,charset)` to construct one. The selected object must have
byte +0xe0 equal to class 2. It can be inserted into M+0x22c; dispatcher-level
tracking uses R+0x1c. A newly constructed object receives selected_R through
its virtual +8 method. The next scheduler/helper `0x0e15b6bc`, class factory,
transport callbacks and concrete bytes remain outside this probe.

## Reproduce and next boundary

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with `ProbeShpAppScriptRequest.java` / `.class`, an absent absolute JSON output,
and `-noanalysis -readOnly`. Final report/console use
`out/rea_shpapp/script_request_islands.*`; independent listing/checks use
`out/rea_shpapp/script_request.objdump.txt` and
`out/rea_shpapp/script_request.verification.json`.

Next: resolve class-2 resource construction and the manager's scheduling path,
then test whether any concrete package-member provider can supply the bytes.
Actual installed-widget execution, callback delivery, transport, host event
values, menus, orientation, RBM mode 2, global resource IDs and Rsrc2 remain
unknown. Cellular/baseband paths remain excluded.
