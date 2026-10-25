# Native event-name bridge and geometry-to-resize path

Two additional native connections are bounded: a constructed object's table
slot forwards an incoming name into generic event construction, and a geometry
update function reaches the known `resize` producer after a graphics adapter
call. Host entry ownership, actual custom widget names and physical orientation
remain unresolved.

## Verification

`ProbeShpAppEventBridge.java` checks the documented ShpApp ELF SHA-256
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511` and
three pointer words. Ghidra 12.1 completed nine functions, 248 instruction
addresses matching bounded ARM objdump 2.45.50 output. Physical hash and
read-only discard were checked. These are ordinary tool observations, not REA
Evidence or target execution. Names/ranges and inferred types are analyst inputs.
See [event sources](shpapp_event_sources.md) for the preceding event path and
[listener wrapper](shpapp_widget_listener.md) for input identity/address mapping.

## A constructed object's name-forwarding method

`[0x0e29257a,0x0e2925c6)` writes table `0x0e58c50c` through literal
`0x0e29295c` into the constructed object's first word. It stores constructor
argument 1 at `+4`, argument 2 at `+8`, and `read32(argument1+0x2c)` at `+0xc`.
The table's slot `+0x128`, at `0x0e58c634`, contains raw Thumb pointer
`0x0e2941eb`.

At entry `0x0e2941ea`, let `O` be the receiver and `S` the incoming register r1.
The method obtains
`W = read32(read32(read32(O+4)+0x30)+4)`. If nonnull, it preserves incoming `S`
as the second argument to `0x0e1b43e4`, producing a local string-like wrapper.
That helper initializes an output word to zero and, for nonnull input, invokes
`0x0e1b5ca2` and a shared-representation helper. Exact input encoding and
validation remain unknown.

The method then calls `0x0e32a70e` to obtain a name representation, calls
`0x0e1459f2(W)`, and passes its result plus that name to the previously verified
forwarder `0x0e13ff96`. Afterwards a separate object from
`read32(0x0e14593c(W)+0x30)` receives virtual slot `+0x4c` with argument zero.
The purpose of that final notification is unknown.

`0x0e1459f2` lazily creates a 120-byte associated object through `0x0e13ffb8`
and stores it at `read32(W+0x10)+0x440`. The target helper `0x0e13f228` then
reads associated-object word `+0x44`, checks it, and calls `0x0e145634`. The
forwarder calls this helper twice and reaches `0x0e1ee268(target,name,0,0)`.
Thus the incoming-name connection is explicit, but table construction alone
does not show who obtains this interface or invokes slot `+0x128`. Neither the
incoming string value nor delivery to the Widget registration receiver has
been demonstrated. A raw pointer/call-candidate search is not an interface ABI.

## Geometry update reaches the resize producer

`[0x0e28ea42,0x0e28eaec)` receives six observed arguments, labeled
`(U,surface,a,b,c,d)` only for tracking register/stack flow:

1. If word `U+0x50` is not `0xffffffff`, it passes that value to the known
   graphics end/commit candidate `0x0e0030d6`, then writes the sentinel.
2. It stores `surface` at `U+0x34`. Unless `U+0x54 == 1`, it calls
   `0x0e003062(surface,a,b,c,d)` and saves the result at `U+0x50`.
3. It gets `W` through `0x0e28c0ae(read32(U+0x30))` and obtains
   `G = read32(read32(W+0x10)+0x460)` through `0x0e1459e6`.
4. It calls `G`'s slot `+0xc` twice with aggregate-result storage. The subsequent
   code preserves the first two returned words, builds a four-word value
   `[old_word0,old_word1,c,d]` through `0x0e335bca`, and passes it to slot `+8`.
5. It calls `0x0e14a526(G)`, then `0x0e146d38(W)`, the verified `resize` producer.
   A separate optional observer receives `G` through slot `+4`, followed by
   `0x0e00c39e`; the routine returns raw `1`.

The four-word helper directly stores its four input words. Treating the final
two as size is a geometry inference, not a recovered type declaration. Aggregate
return conventions obscure arguments in untyped pseudocode; the instruction
trace establishes which words are preserved. No actual dimensions, pixel format,
surface ownership or observer class has been recovered here.

The graphics adapter `[0x0e003062,0x0e003090)` resolves a concrete host interface.
With `C = read32(0x0e5e8c0c)`, it calls
`read32(read32(read32(C+0xe4))+0x3bc)` with the five incoming arguments,
the diagnostic source pointer at `0x0e0033a4` and raw line value `0x41`.
This is the same context slot used by the earlier
[graphics adapters](shpapp_graphics.md), although the target provider and method
contract remain unknown. This connection does not establish that the Widget
resizeWindow target's separate indirect object is the graphics interface.

## Reproduce and next boundary

Use the precompiled-class commands in the listener report with
`ProbeShpAppEventBridge.java` / `.class` and a fresh output destination. Full
reports are ignored under `out/rea_shpapp/event_bridge.*`; the instruction/hash
checks are in `event_bridge.verification.json`. Candidate searches are retained
in `event_host_forward_candidates.json` and are separate from validated ranges.

The subsequent [control-factory probe](shpapp_control_factory.md) resolves the
owner above the name-forwarding table and the initialization call at `0x0e28cd78`.
The [provider](shpapp_control_provider.md) and
[document](shpapp_document_receiver.md) probes then resolve provider/frame
construction and the document receiver self-link for the examined family.
Script-context frame identity, external host use, custom widget event values,
window-direction provider, RBM mode 2, global IDs and Rsrc2 remain
unknown. Cellular/baseband paths remain excluded.
