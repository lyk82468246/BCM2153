# Script resource bytes, text and completion linkage

The class-2 request constructs a resource whose byte acceptance, error handling,
client notification and decoded-text access connect back to the previously
bounded script evaluator. Its +8 method starts loading through a shared service
at `0x0e16a260`. The earlier `0x0e15b6bc` scheduling candidate instead performs
cache counter/list bookkeeping. Concrete byte acquisition remains unresolved.

## Input and verification

Embedded ShpApp ELF SHA-256:
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Parent identity/address conversion are in the
[listener report](shpapp_widget_listener.md). Original hash-guarded
`ProbeShpAppScriptResource.java` covers twenty-two functions and two explicitly
partial factory slices. Twenty-two functions decompiled; both slices intentionally
report disassembly only. All 747 instruction addresses matched independent
bounded ARM objdump 2.45.50 output, with one explicitly ARM switch helper and
Thumb elsewhere. Fourteen words, inline switch arithmetic, physical hash and
Ghidra 12.1 read-only discard were verified. Mode selection is not CPU evidence.
These are ordinary local observations, not REA Evidence or target execution.

## Class 2 selects the script resource constructor

Factory prefix `0x0e15b6de` preserves input class in r3 and name/charset in
r4/r5, then calls ARM helper `0x0e3120e0` through BLX at `0x0e15b6ea`.
The raw return address is **`LR=0x0e15b6ef`**, including its Thumb bit.
The ARM helper reads count 5 at LR-1 and a byte offset at LR+class, using index
5 for classes >=5, then branches to `LR+2*offset`. Class 2 reads byte `0x13`
at `0x0e15b6f1`, producing raw target `0x0e15b715`, Thumb entry `0x0e15b714`.
That case allocates 0x1b0 bytes and calls `0x0e15e130(Z,name,charset)`.

The count/default and five case offsets are guarded as two words starting at
`0x0e15b6ee`. These inline bytes are not code. Early prefix pseudocode followed
them as fall-through code and produced an incorrect constructor path. The final
probe skips decompilation for the prefix and selected case; the arithmetic and
independent ARM/Thumb listings establish the connection. Other case semantics
remain outside the result.

Constructor `0x0e15e130` calls base `0x0e15d668` with class 2, then installs
table `read32(0x0e15e4e4)=0x0e595514`. Selected fields for this fresh Z are:

| Field | Observed construction/use |
| --- | --- |
| `+0x20` | name copied by base constructor |
| `+0xd8` | byte-buffer pointer, initially zero |
| `+0xe0` | class byte, set to 2 |
| `+0xe2` | error byte, initially zero |
| `+0xe8` | accepted byte count, initially zero |
| `+0x10b` | pending flag: set by start, cleared by acceptance/error |
| `+0x154` | cached decoded text, initially zero |
| `+0x158` | charset-related object constructed from incoming charset |

## Loading starts through a different path from cache bookkeeping

Table +8 at `0x0e59551c` contains raw `0x0e32bd99`. The manager's previously
bounded new-object branch invokes this method with selected document loader R.
Adapter `0x0e32bd98` calls `0x0e15d842(Z,R,0,0,1)`. That method gets shared
manager M and calls **`0x0e16a260(M+0x20,R,Z,0,0,1)`**, then sets Z+0x10b to 1.
Its shared epilogue `[0x0e15d758,0x0e15d75c)` is explicit in the probe.

In contrast, `0x0e15b6bc(M,Z)` calls `0x0e15b652`, increments Z+0xf0, then
calls `0x0e15b60a`. Those helpers remove/add Z through paired links at +0x11c
and +0x120 and a selected manager bucket. This establishes bookkeeping rather
than a transport-start call. Bucket selection, cache policy and the new loading
service's implementation remain outside this probe.

## Accepted bytes notify the registered script client

The [request/input route](shpapp_script_inputs.md) conditionally registers X
through resource virtual +0x1c. For constructed Z, word `0x0e595530` selects
`0x0e15e2d8(Z,X)`. It calls base registration `0x0e15d86e`, which inserts X
into the container rooted at Z+8. If Z+0x10b is already clear, it immediately
calls X's +0x1c callback. Thus late attachment has a separate immediate path.

Resource +0x14 selects `0x0e15e388(Z,&buffer,flag)`. When flag is nonzero,
it moves the supplied buffer pointer into Z+0xd8 and clears the source pointer,
releases the old buffer, obtains a byte count through `0x0e0167be`, and stores
it at Z+0xe8 through bounded setter `0x0e15dba6`. It clears Z+0x10b and calls
`0x0e15e33e(Z)`. The zero-flag branch does not perform this transfer.

The notifier snapshots clients through `0x0e15dfb4(&snapshot,Z+4)`, whose
underlying table starts at Z+8. Iterator `0x0e15e072` returns snapshot entries
only while they remain present in that table. Each surviving client receives
its virtual +0x1c call with Z. X's constructor-selected table is
`0x0e5ac2d4`; word at +0x1c (`0x0e5ac2f0`) is raw `0x0e1f97e3`, selecting
the [already bounded completion handler](shpapp_script_inputs.md).
That handler checks Z+0xe2, builds cached input and calls the common evaluator
on its clear branch; its other branch reaches the owner's error interface.

Resource +0x18 selects `0x0e15e3da`, which clears pending, sets Z+0xe2 to 1
and tail-branches to the same notifier. This establishes the structural
success/error route, not runtime delivery or a particular transport status.

## The cached input reads this resource's decoded text

Input factory `0x0e32782c` allocates 24-byte source F, uses resource name Z+0x20,
installs `read32(0x0e3278a8)=0x0e5bcbb8`, and retains Z at F+0x14 through
bounded `0x0e3ac504`: it writes the pointer and calls `0x0e32bd68`, which
increments Z+0x12c and performs further reference bookkeeping. It attaches
F+0x10 as another resource client and builds the span through `0x0e31e682`.
Source table +0x10 selects length adapter `0x0e33d286`; +0x0c selects data
adapter `0x0e33d278`. Both read Z from F+0x14 and call `0x0e15e24a(Z)`.

That getter lazily converts the buffer at Z+0xd8, with count Z+0xe8 and the
charset object Z+0x158, through `0x0e1b91de`. It stores the resulting text at
Z+0x154 and returns that field's address. Length/data adapters then call
`0x0e1b459a` / `0x0e1b45b2` respectively. Together with the prior input span
and completion probe, this connects accepted bytes to the evaluation input.
Complete charset/encoding behavior and subsequent resource mutations remain
unknown; this is not evidence that any package script ran.

## Reproduce and remaining boundary

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with `ProbeShpAppScriptResource.java` / `.class`, an absent absolute JSON path,
and `-noanalysis -readOnly`. Final report/console are
`out/rea_shpapp/script_resource_retained.*`; bounded listings and checks are
`out/rea_shpapp/script_resource.objdump.txt` and
`out/rea_shpapp/script_resource.verification.json`.

The [service follow-up](shpapp_resource_service.md) resolves queue selection,
transfer construction and the constructed frame-provider dispatch target.
Next: trace the provider's bridge and calls supplying the accepted buffer.
Package-member acquisition, installation,
actual script/callback execution, transport, host event values, menus,
orientation, RBM mode 2, global IDs and Rsrc2 remain unknown. Cellular/baseband
paths remain excluded.
