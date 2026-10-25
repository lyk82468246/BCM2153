# Named-event construction and bounded source paths

ShpApp contains concrete native paths that construct `resize`, `focus`, `blur`
and `beforeunload` events and reach the previously examined listener dispatcher.
These are generic document/window events. The specific production and delivery of
`widgetmodechange` and `widgetendkey` remain unknown.

## Evidence and scope

Input ELF SHA-256 is
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`;
parent identity and address conversion are in
[listener wrapper](shpapp_widget_listener.md). The new hash-guarded
`ProbeShpAppEventSources.java` covers nine functions, including two explicit
shared-epilogue islands. Ghidra 12.1 completed every decompilation, 405 instruction
addresses matched bounded ARM objdump 2.45.50 output, the physical hash matched,
and read-only project changes were discarded. The probe also checks four event
name literals. This is ordinary local-tool evidence, not REA Evidence or target
execution. Names, ranges and inferred types remain analyst inputs.

A candidate search of the full forced-Thumb listing found five direct calls to
`0x0e1e5d76`: `0x0e14722e`, `0x0e1edc8a`, `0x0e1eddc0`, `0x0e1ee248`,
`0x0e1ee252`. This is a seed list, not a complete call graph: the listing also
contains data and ARM islands, and does not enumerate indirect callers. This
pass validates the first and last two sites within complete bounded functions;
the other two belong to a larger propagation candidate outside this probe.

## Canonical names

Bounded initialization through `0x0e32a646` maps these offsets from the name
registry returned by `0x0e1ed8d0`:

| Offset | Name | Literal VMA | Initializer call |
| --- | --- | --- | --- |
| `+0x24` | `beforeunload` | `0x0e1ed45c` | `0x0e1ed072` |
| `+0x2c` | `blur` | `0x0e1ed46c` | `0x0e1ed07c` |
| `+0xc4` | `focus` | `0x0e1ed520` | `0x0e1ed13a` |
| `+0xec` | `load` | `0x0e1ed464` | `0x0e1ed16c` |
| `+0x16c` | `resize` | `0x0e1ed5f4` | `0x0e1ed242` |

The initializer returns its destination, allowing the observed add/subtract
sequence to track offsets. The names are verified bytes plus initialization
flow, rather than guesses from neighboring strings.

## Generic named-event path

`0x0e334830(out,name,flag_a,flag_b)` allocates 56 bytes, calls `0x0e1ecfce`,
and stores the resulting pointer through `out`. The constructor writes the
shared name representation to event `+0x10`, incoming flags to bytes
`+0x14/+0x15`, clears bytes `+0x16..+0x19`, word `+0x1c`, halfword `+0x20`,
and selected other fields. Timestamp-like calls are present but not interpreted.
This partial field map does not define the complete event ABI. Its main range
is `[0x0e1ecfce,0x0e1ed030)` with the shared epilogue
`[0x0e1ecfca,0x0e1ecfce)`.

`0x0e1ee268(T,name,flag_a,flag_b)` constructs an event and calls `0x0e1ee1f6`
with the temporary pointer's address. It also has separate `load` bookkeeping
that can construct another event and call `0x0e1edbe0`; the full propagation
semantics of that branch remain unresolved. Its shared return sequence is
`[0x0e1edbc4,0x0e1edbc8)`, included explicitly with the main range
`[0x0e1ee268,0x0e1ee312)`.

`[0x0e1ee1f6,0x0e1ee268)` first tests `0x0e1ed9da`. A supplemental bounded
trace shows this helper returns whether the signed word at `0x0e5fc838` is
positive; how that word changes remains unknown. When the gate permits dispatch,
the function consumes the incoming event pointer and sets the caller's word to
zero. It obtains `R = read32(T+0x10)`, retains it, and supplies `R+0x24`
through the event's target-assignment helper `0x0e1ecee2`. That helper moves a
pointer into event `+0x24`, releases the old target and conditionally invokes an
event virtual method. Then it calls, in order:

1. `0x0e1e5d76(R,event,1)` at `0x0e1ee248`.
2. `0x0e1e5d76(R,event,0)` at `0x0e1ee252`.

The caller runs both stored-flag groups. This supports a two-phase interpretation
without proving all DOM capture/bubbling rules. In particular, `R` is a distinct
observed expression from the Widget adapter's registration receiver `D` returned
by `0x0e145634(W)`. Whether `read32(D+0x10)` equals `D` for the relevant document
object has not been shown. This path cannot yet prove delivery to that widget's
registered listener list.

## Bounded producers

| Entry | Verified behavior | Remaining limit |
| --- | --- | --- |
| `0x0e146d38` | Sets receiver byte `+0x90` to 1, obtains `D` through `0x0e145634`, calls `0x0e1ee268(D,registry+0x16c,0,0)` when nonnull, clears byte `+0x90` | Upstream callers and actual geometry/orientation trigger unknown |
| `0x0e1949ba` | On a change to receiver byte `+0x4c`, calls `0x0e194902`, obtains `D` through receiver word `+0x40`; nonzero state selects focus, zero selects blur; both flags passed as 0 | This proves named state-dependent events, not physical keyboard/focus behavior |
| `0x0e13ff96` | Obtains a target through `0x0e13f228`; forwards caller-supplied name to `0x0e1ee268` with both flags 0 | Incoming name/host entry provenance not yet established |

Separately, `[0x0e14717c,0x0e1472c6)` conditionally allocates a 56-byte object
and calls `0x0e1ded5c`. That constructor selects registry `+0x24`, hence
`beforeunload`, passes flags `0,1` to the event base constructor and installs a
different event table. The source assigns a target derived from `D+0x24` and
calls `0x0e1e5d76(D,event,0)` at `0x0e14722e`. Unlike the generic named-event
path, this call directly uses `D`. Afterwards it reads event byte `+0x17` and
the derived event's word `+0x34` before additional host calls. The script
listener's result handling can write event byte `+0x17`, but complete cancellation,
prompting and navigation semantics have not been recovered.

## Reproduce and next question

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with source/class name `ProbeShpAppEventSources` and an absent output such as
`out/rea_shpapp/event_sources_verified.ghidra.json`. Keep `-noanalysis -readOnly`.
Local full reports are `event_sources_verified.ghidra.json`, its console log,
`event_sources.objdump.txt`, `event_sources_names.objdump.txt`, and
`event_sources.verification.json`. Candidate searches remain in
`widget_dispatch_call_candidates.json` and `widget_event_source_candidates.json`.

A subsequent [bridge/geometry probe](shpapp_event_bridge.md) connects an incoming
name to the generic forwarder and one geometry update to the resize producer.
Their upstream ownership and construction/identity of the document receiver
were followed through the [control factory](shpapp_control_factory.md) and
[provider](shpapp_control_provider.md): provider ownership and document pointer
storage are now resolved, while the document's construction and receiver
identity remain unresolved. The evidence does not connect a physical orientation change,
widget startup or host-supplied custom event to a particular callback body.
RBM mode 2, global resource IDs and Rsrc2 remain unknown; cellular/baseband paths
remain excluded.
