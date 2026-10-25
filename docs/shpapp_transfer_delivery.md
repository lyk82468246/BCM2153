# Transfer buffers reach script-resource acceptance

The [request callback wrapper](shpapp_request_bridge.md) reaches concrete
transfer methods which forward to the constructed loading queue. Queue
completion obtains T's buffer and calls resource virtual +0x14 with flag 1.
For class 2 this is the previously verified byte acceptance and script-client
notification path. This closes the static connection from delivered callback
bytes to script input; lower-provider acquisition and actual execution remain
unresolved.

## Input and verification

Embedded ELF SHA-256:
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Parent identity and address conversion are in the
[listener report](shpapp_widget_listener.md). Original hash-guarded
`ProbeShpAppTransferDelivery.java` bounds 23 Thumb functions with explicit
shared return islands. All decompiled; all 1,055 instruction addresses matched
independent bounded ARM objdump 2.45.50 listings. Sixteen expected words, two
literal locations, physical hash and Ghidra 12.1 read-only discard matched.
These are ordinary local observations, not REA Evidence or target execution.
Inferred types/signatures and opaque helper contracts remain limited.

Notation follows the [service report](shpapp_resource_service.md): T is the
0x268-byte transfer, Q=`read32(T+0x260)` its queue, Y its tracked job,
Z=`read32(Y+0x10)` the resource and R=`read32(Y+0x14)` the document loader.

## The transfer calls the constructed queue

The earlier constructors install T table `0x0e5ac3b4` and Q table
`0x0e5c74d4`. Guarded words resolve their callback calls:

| Transfer method | Queue slot / target |
| --- | --- |
| response `0x0e16d13c` | +0x10 / `0x0e16a7b0` |
| data `0x0e16d204` | +0x14 / `0x0e16a8e2` |
| complete `0x0e16d258` | +0x18 / `0x0e16a99a` |
| error `0x0e16d2aa` | +0x1c / `0x0e16aa7c` |

Data first calls base method `0x0e16c95a`, then invokes Q+0x14 when Q is
nonnull and byte T+0x264 is clear. Base-data invokes T virtual +0x58, passing
the final incoming stack flag as its fourth argument. Completion and error
check T+0x179, call the corresponding queue method when Q is nonnull, and
perform separate transfer cleanup/reporting. Base finish also checks T+0x17a
and sets it before a conditional frame-associated notification. These gates
prevent interpreting every callback as successful resource completion.

Queue response/data look up Y using T and the collection at Q+0x40 through
bounded `0x0e3b14ea`. Completion/error find and remove the corresponding entry.
Collection internals and concurrency guarantees are outside this probe.

## T stores and exposes a byte buffer

T virtual +0x58 resolves to **`0x0e16c792(T,data,length,final_flag)`**.
Base constructor `0x0e16cb9a` clears T+0x170 and sets byte T+0x17d to 1.
The wrapper's previously described buffered branch checks this same byte.
Subsequent mutation and actual runtime values remain unknown.

When T+0x17d is set, store handles two paths:

- A nonzero flag calls `0x0e32aefa(&buffer,data,length,1)` and installs the
  resulting reference at T+0x170.
- A zero flag applies allocation/mode gates, then creates a buffer with flag 0
  or appends through `0x0e0167f0`. Failed gates can leave storage unchanged.

Factory `0x0e32aefa` allocates 32 bytes and calls `0x0e0166d8`. With flag 1,
that constructor stores the incoming pointer at buffer+0x18 and length at
buffer+0x1c. With flag 0 it forwards data/length to a collection helper at
buffer+8. The bounded data/count getters `0x0e01678a` / `0x0e0167be` select
these external-pointer fields when present, otherwise use the other storage
fields. Append enters the collection helper after checking the external field.
This records storage choices; it does not prove all ownership/lifetime rules.

T virtual +0x5c resolves to **`0x0e16c844(&out,T)`**. Its main available-buffer
branch reads T+0x170, writes it through out and increments the buffer's first
word when nonnull. A mode-specific fallback uses T+0x14 through another helper;
otherwise out is zero. The fallback and allocation policy remain unresolved.

## Completion supplies the resource's accepted buffer

Queue completion `0x0e16a99a(Q,T)` removes the tracked T entry, obtains Y,
marks byte Q+0x64 during processing and reads Z and R. If Z+0xe2 is clear:

1. It calls a document-loader helper with `(R,1)`.
2. It calls T virtual +0x5c into a temporary buffer reference.
3. At `0x0e16aa3e`, it invokes **Z virtual +0x14 `(Z,&buffer,1)`**.
4. It releases the temporary reference and calls `0x0e15d988(Z)`.

It then destroys Y, performs document-loader bookkeeping, attempts queue
dispatch and clears Q+0x64. Helper effects, null-buffer behavior and reentrant
callback values are not fully established.

For class 2, guarded word `0x0e595528` is raw `0x0e15e389`, selecting
**`0x0e15e388`** from the [script-resource report](shpapp_script_resource.md).
Its nonzero-flag branch moves the buffer into Z+0xd8, obtains the count,
clears pending and notifies registered clients. The previously constructed X
client reaches `0x0e1f97e2`, whose clear-error branch builds input from this
resource and reaches the common evaluator. No script execution was observed.

Queue-data `0x0e16a8e2` has additional paths. A response-derived helper result
of 4 invokes resource +0x18. Otherwise Y+0x19 can select newly constructed
chunk acceptance with flag 1, or Y+0x18 can select T's current buffer with flag
0. Both bytes start at zero on the examined script request. Response handlers
can set Y+0x19 when comparing against `multipart/x-mixed-replace`, so those
initial values are not a universal deferral guarantee. The type-specific
class-2 receiver acts on a nonzero flag.

## Error completion reaches the same resource's error entry

Queue error adapter `0x0e16aa7c(Q,T,error)` passes `(Q,T,0)` to
`0x0e16a368`. That common helper clears T+0x260, removes its tracked entry,
obtains Z/R and, with its third argument zero, invokes resource virtual +0x18.
It then performs job/cache/document cleanup and resumes queue dispatch.
For class 2, word `0x0e59552c` selects `0x0e15e3da`, which sets Z+0xe2,
clears pending and uses the already verified client notifier. The incoming
error description is not decoded by this queue adapter; its numeric contract
and later transfer reporting remain unknown.

## Reproduce and next boundary

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with `ProbeShpAppTransferDelivery.java` / `.class`, an absent absolute JSON
destination and `-noanalysis -readOnly`. Report, console, independent listing
and verification remain under `out/rea_shpapp/transfer_delivery*`.

Next: lower-provider start targets `0x0e28b326` / `0x0e28b8da`, the concrete
acquisition object and its invocation of the request-ID routing routines.
Package-member access, installation, actual scripts/callbacks, transport,
host events, menus, orientation, RBM mode 2, global IDs and Rsrc2 remain
unknown. Cellular/baseband paths remain excluded.
