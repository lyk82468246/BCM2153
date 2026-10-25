# Lower requests and adjusted provider callbacks

The lower providers selected by the [request bridge](shpapp_request_bridge.md)
construct concrete 0x38-byte requests, start them through another manager and
provide adjusted callback interfaces into the same request-ID registry.
The request's data/completion/error methods now connect to the previously
verified wrapper, transfer and resource acceptance chain. Acquisition beneath
the manager remains unresolved; no firmware request was executed.

## Input and verification

Embedded ELF SHA-256:
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Original hash-guarded `ProbeShpAppLowerRequests.java` bounds 34 Thumb functions.
All decompiled; all 376 instruction addresses matched independent bounded ARM
objdump 2.45.50 listings. Thirty words, the `#` literal, physical hash and
Ghidra 12.1 read-only discard matched. These are ordinary local observations,
not REA Evidence or execution. Tail-call signatures in pseudocode can omit
preserved arguments; instruction registers determine the connections below.

## Both sides use the registry constructed by the frame helper

Frame helper constructor **`0x0e288980(F,N)`** writes N at F+0x0c, allocates a
20-byte registry G through `0x0e28b048` and stores it at F+4. It allocates a
24-byte selector A through `0x0e28b36c(A,F,G)` and stores A at F+8.
The selector writes F at A+0x10 and G at A+0x14. Its earlier lower-provider
constructors receive G and store it at provider+8 via `0x0e28b7b8`.
Thus provider+8 and F+4 identify the **same constructed G**; this is more than
matching collection layouts. Wrapper registration uses G, as do lower-provider
callback routers. Registry construction clears its collection fields and
initializes G+0x10 to 1; full reference/lifetime semantics remain unknown.

## Provider start constructs and starts a request

Let B denote either selected lower provider, distinct from the service B in
earlier reports. Shared provider start `0x0e28b326` calls `0x0e28b8da`, also
the file provider's direct start. That method invokes B virtual +0x28:

| Provider table | Factory | Request constructor / table |
| --- | --- | --- |
| shared `0x0e58a434` | `0x0e28b34a` | `0x0e288dd4` / `0x0e58ac6c` |
| file branch `0x0e58a3e4` | `0x0e28b2be` | `0x0e288ce0` / `0x0e58abec` |

Each factory allocates 0x38 bytes and calls its constructor with the converted
request and **I=B+4**, an interior callback interface. Base constructor
`0x0e28aea8(L,request,I)` writes request at L+8, I at L+0x0c, state byte
L+4=0, and creates a 24-byte data description H at L+0x18. It obtains the
owning provider through I virtual +0x10 and increments provider+0x18.
It also has a `#` search/copy branch on request+0x24; full URI normalization
and allocation handling are outside this report.

`0x0e28b890(B,L)` appends L to the collection rooted at B+0x0c and invokes
L virtual +8. Both concrete request tables map +8 to `0x0e28af8e`, which
dispatches L virtual +0x2c:

- Shared request: `0x0e288fdc` calls getter `0x0e289d62`, then
  `0x0e28a892(manager,L)`; nonzero helper result becomes return 0, zero becomes 1.
- File-branch request: `0x0e288db6` calls the same manager/helper and returns 0.

A nonzero result from request-add makes provider-start remove the tracked L
by request ID through `0x0e28b862`. A null factory result returns 0 directly.
These raw return branches are not a recovered host success-code specification
or proof that acquisition occurred. Manager internals and scheduling are next.

## The callback interface adjusts B+4 back to B

Provider constructors install a secondary table at B+4, equal to primary
table+0x34. Its slots contain Thumb adjustment entries:

| I slot | Shared target | File target | Main-object action |
| --- | --- | --- | --- |
| +0 | `0x0e28b336` | `0x0e28b95c` | subtract 4; response adapter `0x0e28b952` |
| +4 | `0x0e28b96a` | same | subtract 4; data adapter `0x0e28b960` |
| +8 | `0x0e28b9a2` | same | subtract 4; completion `0x0e28b96e` |
| +0x0c | `0x0e28b9dc` | same | subtract 4; error `0x0e28b9a6` |
| +0x10 | `0x0e28b9e2` | same | subtract 4; return B |

The shared response adjustment additionally traverses adapter `0x0e28b32e`.
Response/data main-object methods read G from B+8 and call
`0x0e28b1c0` / `0x0e28b1dc`, preserving incoming request/payload arguments.
Completion/error derive ID from `read32(L+8)+0x2c`, temporarily increment G+0x10,
call registry completion/error routers `0x0e28b1f8` / `0x0e28b226`, remove L
from the provider collection, and perform further cleanup/release calls.
Exact destruction ordering under runtime reentrancy remains unresolved.

## Request notification methods reach those interfaces

`0x0e28b01e(L,data,length)` stores data at L+0x10 and length at L+0x14,
then invokes L virtual +0x30. Both request tables select `0x0e28b016`, which
sets state byte L+4=1 and branches to **`0x0e28afca`**. In state 1 the latter
calls L virtual +0x34 (`0x0e28b028`) to prepare H, then invokes
**I virtual +4 `(I,L,H)`**. Preparation moves L+0x10 into H+4, clears L+0x10
and writes length to H+8. Bounded H construction is `0x0e28bed4`; its full
interface and ownership behavior remain next.

`0x0e28affe` sets state 2 and enters the same notifier; state 2 invokes
**I virtual +8 `(I,L,H,flag)`**. Error method `0x0e28b004` invokes
**I virtual +0x0c `(I,L,error)`** directly. These slots resolve through the
adjustment table above to the registry and wrapper. The
[transfer-delivery report](shpapp_transfer_delivery.md) already connects that
wrapper's calls to resource acceptance/error and cached script input.

The [acquisition callback follow-up](shpapp_acquisition_callbacks.md) connects
header/data/completion/error calls to these concrete request slots and resolves
the shared response notification; the file response slot is a no-op.
Static notification paths do not establish callback timing or actual bytes.

## Reproduce and next boundary

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with `ProbeShpAppLowerRequests.java` / `.class`, an absent absolute JSON path
and `-noanalysis -readOnly`. Final report/console use
`out/rea_shpapp/lower_requests_retained.*`; bounded independent listing and
verification use `lower_requests.objdump.txt` and `lower_requests.verification.json`.

The [request-manager follow-up](shpapp_request_manager.md) resolves manager
submission/pending handling, acquisition's callback structure and the
data-description pointer/length methods. The [callback follow-up](shpapp_acquisition_callbacks.md)
resolves inline data preparation and concrete request notification calls.
Next: the lower acquisition handoff at `0x0e02fbb2`. Package-member access,
installation, actual scripts/callbacks, transport, host events, menus, orientation, RBM mode 2,
global IDs and Rsrc2 remain unknown. Cellular/baseband paths remain excluded.
