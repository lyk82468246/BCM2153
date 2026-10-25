# Request providers and callbacks into the transfer

The constructed frame provider from the [service report](shpapp_resource_service.md)
selects one of two lower providers by a text prefix test, and registers a
request-ID callback wrapper. Bounded callback handlers can pass response data,
bytes, completion and errors into the transfer's concrete virtual methods.
The lower provider's acquisition mechanism and its calls into the callback
routing routines remain the next boundary. No transfer or script was executed.

## Input and verification

Embedded ELF SHA-256:
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Parent identity and address conversion are in the
[listener report](shpapp_widget_listener.md). Original hash-guarded
`ProbeShpAppRequestBridge.java` bounds 22 Thumb functions, excluding literal
pools and an unreachable branch at `0x0e28841c`. It includes explicit shared
return islands for two functions and the register entry's branch veneer.
All 22 decompiled; all 1,286 instruction addresses matched independent bounded
ARM objdump 2.45.50 listings. Seventeen expected words, seven ASCII literals,
physical hash and Ghidra 12.1 read-only project discard matched.
These are ordinary local Ghidra/objdump observations, not REA Evidence.
Names describe structural roles; inferred types and signatures are not an ABI.
In particular, raw instructions determine stack arguments and flags where
pseudocode loses ARM comparison results or invents extra parameters.

## Provider selection is a prefix test

Let F=`read32(N+8)`, where N is the constructed frame provider. The earlier
dispatch `0x0e288b4c(F,request,T)` calls `0x0e28b5b6(A,request,&provider,...)`
with A=`read32(F+8)`. It assigns a counter value to `request+0x2c`; the
initialized literal at `0x0e28b7ac` points to counter storage `0x0e5fcab4`.
No initial BSS value was read as a physical ELF byte.

The start method converts text from `request+0x24`, then calls
`0x0e28b3ae(A,text)`. Its tests use `0x0e33e506`, which calls string-find
`0x0e1b66e8` at start index zero and returns true exactly when the result is
zero. The latter searches 16-bit characters and returns the match position or
-1. Thus these are **prefix tests**, not a recovered complete URI parser.

| Prefix/predicate | Selected object |
| --- | --- |
| `http`, `https`, `data`, `cid`, `about:blank` | cached A+8; allocate 0x20 bytes through `0x0e28b2e0` if absent |
| `file`, with `0x0e311b3c(text,"/User/Br/SavedPage")==0` | text transformation involving `file` and `http`, then the same A+8 object |
| `file`, with that helper returning nonzero | cached A+0x0c; allocate 0x1c bytes through `0x0e28b290` if absent |
| no matching prefix | null |

The complete saved-page predicate and text transformation are unresolved;
the literal alone does not establish filesystem or ZIP access.
Base provider construction `0x0e28b7b8` stores the incoming association at
provider+8 and clears provider+0x18. Derived constructors install:

| Constructor | Table | Table+0 target |
| --- | --- | --- |
| `0x0e28b2e0` | `0x0e58a434` | raw `0x0e28b327` -> `0x0e28b326` |
| `0x0e28b290` | `0x0e58a3e4` | raw `0x0e28b8db` -> `0x0e28b8da` |

With a nonnull provider, start prepares `request+0x60`, invokes provider
virtual +0, returns its raw result and stores the provider through the out
pointer. With null, a separate control-associated object's virtual +0x1c
can be queried; its -1 result becomes 5 and other examined results become 0.
A zero return therefore does not by itself prove provider creation or I/O.

## Registration keeps a wrapper under the request ID

The existing dispatch registers only when start returns zero **and** the
out-provider is nonnull. It allocates a 0x50-byte wrapper Cb through
`0x0e288070(Cb,F)`, retains T at Cb+8 using the earlier pointer helper, stores
the request ID at Cb+0x48 and calls:

`0x0e28b120(read32(F+4),request_id,Cb)`.

That entry branches to `0x0e28b0ca`; adjacent `0x0e28b122` is a separate
removal routine. Registration allocates an 8-byte pair `[request_id,Cb]`,
increments Cb+4 and appends its pointer to the collection rooted at registry+4.
`0x0e28b174(registry,id)` scans the collection and returns the matching pair;
removal compacts it and invokes pair cleanup. Full lifetime guarantees and
callback timing are unresolved.

Wrapper construction installs table `0x0e58b658`, stores F at Cb+0x0c and
clears buffer bookkeeping. Newly bounded base and pointer constructors verify
the object-relative fields despite incomplete inferred constructor signatures.

| Routing routine | Wrapper slot / concrete handler | Subsequent action |
| --- | --- | --- |
| `0x0e28b1c0` | +0x0c / `0x0e28810e` | build response description; T virtual +0x68 |
| `0x0e28b1dc` | +0x10 / `0x0e288314` | forward or buffer data; T virtual +0x6c on the forwarding branch |
| `0x0e28b1f8` | +0x14 / `0x0e2884f8` | conditional final data and T virtual +0x70; remove ID afterwards |
| `0x0e28b226` | +0x18 / `0x0e2885d0` | buffer cleanup and T virtual +0x74; remove ID afterwards |

The first three routing routines obtain the ID from
`read32(incoming+8)+0x2c`; the error route takes the ID directly and checks
lookup success. Static handlers exist, but their lower-provider invocation
and delivery ordering have not yet been established.

## Bytes have forwarding and buffered branches

Data handler `0x0e288314` checks byte T+0x17d. When clear, it obtains length
and data through incoming object's virtual +4 and +0, then invokes T+0x6c.
When set and length is positive, it increases Cb+0x38. One branch allocates
and copies chunks into parallel pointer/length collections; the other uses
Cb+0x28 as a contiguous buffer with offset at Cb+0x30/+0x34. Allocation-gate
failure routes an error with raw value 6 and invokes a cancellation helper.
The meanings of the configuration byte and allocation policy are unresolved.

Completion skips its main work when the fourth argument is 1. Otherwise,
the buffered path can combine saved chunks into a contiguous allocation or
reuse Cb+0x28, then call T+0x6c with the accumulated length and final stack
flag 1. If no reported allocation failure occurs, it calls T+0x70. The error
handler frees saved buffers and passes a constructed description to T+0x74.
This proves static byte-carrying calls, not that any bytes arrived.

The already verified T table `0x0e5ac3b4` resolves these slots:

| T slot | Raw word | Concrete method |
| --- | --- | --- |
| +0x68 | `0x0e16d13d` | `0x0e16d13c` |
| +0x6c | `0x0e16d205` | `0x0e16d204` |
| +0x70 | `0x0e16d259` | `0x0e16d258` |
| +0x74 | `0x0e16d2ab` | `0x0e16d2aa` |

These table words are guarded here; their bodies and the queue's calls into
resource acceptance are the next bounded analysis.

## Reproduce and limits

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with `ProbeShpAppRequestBridge.java` / `.class`, an absent absolute JSON
destination and `-noanalysis -readOnly`. Retained report/console use
`out/rea_shpapp/request_bridge_retained.*`; independent listing/checks use
`request_bridge.objdump.txt` and `request_bridge.verification.json`.

Lower-provider acquisition, package-member access, installation, actual
scripts/callbacks, host events, menus, orientation, RBM mode 2, global IDs and
Rsrc2 remain unknown. Cellular/baseband paths remain excluded.
