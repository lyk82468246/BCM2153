# Request submission, pending queue and acquisition handoff

The [lower requests](shpapp_lower_requests.md) enter a lazily constructed
0x70-byte manager. Submission can acquire immediately or enqueue an 8-byte
pending node for later processing. Acquisition distinguishes an inline `data`
branch from a parameter/callback handoff to `0x0e02fbb2`. Neither that handoff
nor the callback table alone proves local package access or a network transfer.

## Input and verification

Embedded ELF SHA-256:
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Original hash-guarded `ProbeShpAppRequestManager.java` bounds 13 Thumb functions,
including acquisition's code island after its literal pool. All decompiled;
all 555 instruction addresses matched independent bounded ARM objdump 2.45.50.
Twenty-one expected words, the `data` literal, physical hash and Ghidra 12.1
read-only discard matched. These are ordinary local observations, not REA
Evidence or execution. Original types, helper contracts and status meanings
remain inferred or unknown.

Use Mgr for this manager and L for the 0x38-byte lower request; L+8 points to
the converted request. This Mgr differs from the earlier resource cache M.

## Construction and pending submission

Getter `0x0e289d62` reads a global pointer through initialized literal
`0x0e289e80 -> 0x0e5fcab0`, and if absent allocates 0x70 bytes and invokes
`0x0e289d2e`. That constructor builds a timer-like helper at Mgr+8, clears
pending head/tail Mgr+0x5c/+0x60 and initializes the scheduling value pair at
Mgr+0x68/+0x6c from initialized literals. No BSS initial state is read from
physical ELF offsets, and timing units are unresolved.

Submit **`0x0e28a892(Mgr,L)`** derives a name component from
`read32(L+8)+0x24` and checks it through `0x0e33e5c6` against `data`.
The exact component/exactness of this different string helper is not bounded
here. A nonmatching result attempts `0x0e28a4ea(Mgr,L,&status)` immediately.
A nonzero acquire result returns 1. Otherwise, if the low status byte is 0
or 0x84, it allocates `[L,next]`, appends it through Mgr+0x60, initializes
Mgr+0x5c if needed, conditionally arms the helper and returns 1. Other status
bytes return 0. A match skips immediate acquisition and enters this pending
decision with the initialized zero status.

The submission status byte is an observed control value, not a decoded error
enum. In particular, return 1 can mean a queued request, not completed I/O.

`0x0e28a9ea` walks pending nodes, saving next before calling acquire. On
nonzero acquire it removes the node through `0x0e28a96a`; on zero it adjusts
the scheduling pair and stops this pass. Timer helper `0x0e28aa28` calls this
processor and conditionally rearms. Removal updates head/tail, unlinks and
frees the matching node. Cancellation `0x0e28a9b2` first tries pending removal,
otherwise obtains a started-request handle through L virtual +0x0c and passes
it to `0x0e0302c6` before clearing through L+0x10 when the handle is nonnegative.
Complete cancellation/ownership and synchronization contracts remain unknown.

## Acquisition builds parameters and a concrete callback table

Acquire **`0x0e28a4ea`** derives the same name component. A `data` match calls
`0x0e28a18e(Mgr,L)` and returns 1. The
[follow-up](shpapp_acquisition_callbacks.md) bounds that callee and connects
synthetic header creation and payload delivery to concrete request
slots; transformation helpers remain unresolved.

Other names allocate a 0x38-byte parameter object P, copy text from converted
request+0x1c/+0x24, copy request+0x50 to P+0x2c, and map request byte +0x36
values 1/2/3 to P+0x1d, using 0 otherwise. It sets P+0x20=1. Additional
preparation depends on request byte +0x34: examined branches are 0 and 1;
other values leave an unresolved local-result path in the inferred pseudocode.
No supported-input claim is made for those other values.

It allocates a separate 0x30-byte callback structure C. The observed branch
values and initialized literals determine these raw Thumb targets:

| C offset | Target / condition |
| --- | --- |
| +0 | `0x0e28944a` |
| +4 | `0x0e289050` |
| +8 | `0x0e2896cc` |
| +0x0c | `0x0e289b8a` for request+0x34==1, otherwise zero |
| +0x10 | zero |
| +0x14 | `0x0e2897c6` |
| +0x18 | zero in one control branch, otherwise `0x0e289778` |
| +0x1c | `0x0e289bc6` |
| +0x20 | `0x0e289c18` |
| +0x24 | conditional `0x0e289afe` for request+0x34==1, otherwise zero |
| +0x28 | `0x0e289804` for request+0x34==1, otherwise zero |
| +0x2c | `0x0e289c32` in one request+0x34==0 branch, otherwise zero |

After control-associated gates it calls:

`0x0e02fbb2(read32(control+0x60),P,L,C,selected_flag,&status)`.

The selected flag is 0 or 1, depending on control fields and a text comparison.
If the returned handle differs from -1, acquire invokes L virtual +0x10 with
that handle. It then releases parameter strings, P and C, and returns whether
the handle differs from -1. Whether the callee copies structures, invokes
callbacks synchronously or retains any pointers remains unknown. No transport
ABI or safe lifetime reconstruction follows merely from these calls.

The [callback follow-up](shpapp_acquisition_callbacks.md) resolves
`0x0e28944a`, `0x0e289050`, `0x0e289196`, `0x0e2896cc` and the inline
`data` handoff to concrete request slots. A separate
control getter `0x0e28aa56` follows converted request+0x60 and invokes its
virtual +0x9c; the control's complete type is unresolved.

## Data-description getters complete the pointer/length connection

The lower request's 24-byte description table is `0x0e58af98`. Newly bounded
methods resolve +0 to `0x0e337f3a` (H+4 pointer), +4 to `0x0e337f32` (H+8
length), and +8 to `0x0e337f36` (H+0x0c response-related pointer). Thus the
[request wrapper](shpapp_request_bridge.md) data callback's virtual +0/+4 reads
the pointer/length fields populated by the lower request's preparation method.
The description destructor's ownership rules and acquisition-side field writes
are still outside this result.

## Reproduce and next boundary

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with `ProbeShpAppRequestManager.java` / `.class`, an absent absolute JSON path
and `-noanalysis -readOnly`. Report, console, listing and independent verification
remain under `out/rea_shpapp/request_manager*`.

The [acquisition callback follow-up](shpapp_acquisition_callbacks.md) bounds
the header/data/error and inline `data:` paths. It shows local
header parsing, bounded callback handoff and `data:` conversion, while leaving
the lower helper `0x0e02fbb2`, callback timing and provider return values
unresolved. Package-member access, installation, actual scripts/callbacks,
transport, host events, menus, orientation, RBM mode 2, global IDs and Rsrc2
remain unknown. Cellular/baseband paths remain excluded.
