# Acquisition cache gates, queued messages and error teardown

The `file://`-selected branch in
[lower acquisition](shpapp_acquisition_backend.md) first enters cache lookup
and response preparation. It can return 2 to request a queued follow-up;
other results enter a client-state gate. The message helper constructs and
queues a message rather than completing I/O. A separate error path saves the
copied callback, removes the entity and then invokes that callback.
No package, firmware request or script was executed.

## Input and verification

Embedded ELF SHA-256:
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Original `ProbeShpAppAcquisitionDispatch.java` bounds 12 Thumb functions.
All decompiled; all 727 instruction addresses matched independent bounded ARM
objdump 2.45.50. Five initialized words, three literal locations, physical hash
and Ghidra 12.1 read-only discard matched. These are ordinary local
observations, not REA Evidence or execution. Inferred pseudocode signatures
sometimes include extra registers or omit preserved arguments; the assembly
establishes the calls described here.

Use E for the 0x78-byte registered entity, Q=read32(E+0x0c), and L for the
lower request retained at E+0x58. E+0x18 points to an eight-byte cache handle
A; E+0x10 can point to a separate 0x20-byte cache response D. These differ
from the lower request's data description H and browser response object O.

## The apparent file branch first searches cache records

**`0x0e024184(E,mode)`** obtains the client's cache configuration K through
`0x0e02fb7c`: client lookup, then client+0x2c. It stores K through the global
referenced by `0x0e0242fc -> 0x0e5efe98`, also used by cache request code
through literal `0x0e022fb4`. The original short strings
`SFBFindCacheRequest: Find and Request Cache`, `Cache\SFBCacheManager.cpp`
and `Cache\SFBCacheHandler.cpp` corroborate the cache interpretation.
They do not identify a physical backing store.

Absent K returns 0. Otherwise the method frees an old E+0x18 allocation,
allocates A size 8 and tests configuration fields K+0x0c/+0x10/+0x14.
Selector **`0x0e024168`** uses its third argument, Q byte +0x1d:
values 0/1/3 return read32(K), value 2 returns read32(K+4); other values
return K itself in the observed register flow. The passed Q text arguments
are not used by this selector. If a selection is available it stores it at
A+0 and enters **`0x0e022c58(E,mode)`**. The A allocation is not null-checked
before later dereferences; this observation is not a safe reconstructed ABI.

Cache request gates vary with mode and Q byte +0x1c. It calls
`0x0e026432(read32(A),read32(Q))` to find a record R, with fallback selections
from K+0 or K+8 in different branches. Record state R+0x18 must be 2 or 4.
It then calls **`0x0e022ba2(R,E,mode)`**. A zero result can produce return 2,
store R at A+4, set R+0x18=2, call `0x0e02643a(A)` and increment R+0x0c.
One nonzero preparation branch returns 3 and stores R at A+4; miss/other
branches commonly return 1. These raw values are not a general cache enum.
Lookup helpers, complete cache policy and record ownership remain unresolved.

Preparation calls **`0x0e02500e(R)`** for a copied header span. This helper
allocates R+0x24+1 bytes and copies R+0x24 bytes from R+0x50 when the record's
storage/count gates allow. Other paths call unbounded `0x0e026928`,
`0x0e02698c` and `0x0e026070`. It does not itself establish a filesystem read;
several failure branches return without a locally visible free of the initial
allocation, and allocator/ownership contracts are not recovered.

With a non-null span, preparation allocates D size 0x20 at E+0x10, creates a
second copy at D+4, records R+0x24 at D+8 and frees the temporary span.
Modes 2/3 or record R+0x44==1 return a zero preparation result directly;
other paths use `0x0e025798` / `0x0e02582c` and can free D again. The two
response allocations are not null-checked before use in the observed body.
This stage supplies response headers; resource-body acquisition remains next.

## Client state gates select start, message or wait

**`0x0e02a500(E)`** gets a client handle through `0x0e02f306`, which reads
client+0 after bounded client lookup and returns -1 when absent.
The dispatch gate then calls `0x0e0059b0(handle)`:

- Nonzero: enter unbounded `0x0e029ef4(E)`.
- Zero: test `0x0e005a00(handle)` then `0x0e005a50(handle)`; nonzero results
  return 0 without starting this path.
- When both are zero, pass `0x0e005034(handle)` to
  `0x0e005c7c(handle,value)`. A zero result queues `(0,5,0,0x20,id,0)` through
  `0x0e009a18`; nonzero calls `0x0e02f4ca(client_id,1)` and returns 0.

Names and return values of these opaque state helpers are not decoded here.
No claim of network readiness, open file or completed transfer follows from
this gate. The backend's other two previously observed message calls are
`(0,2,0,0,id,0)` and `(0,3,0,0,id,0)`.

## The common message helper only enqueues

**`0x0e009a18(owner,event,payload,extra,id,value)`** reads queue state through
`0x0e009cf4 -> 0x0e5e8aa0`. It rejects a signed existing count above 200 by
calling logging/assertion helpers. Otherwise it allocates M size 0x20 and
writes:

| M field | Source / observed value |
| --- | --- |
| +0 | next, initially zero |
| +4 byte | event |
| +8 | payload |
| +0x0c byte | ordering class derived from event |
| +0x0d byte | owner |
| +0x0e byte | incrementing global byte |
| +0x10 | extra |
| +0x14 | id |
| +0x18 | value |
| +0x1c | timestamp-like helper result, conditionally written |

Events 2/3/5 receive ordering class 2. Other values can select classes 0/1/3/4;
class 4 prepends and the other classes use comparison-based insertion.
Head/tail are global+0x14/+0x1c, count is global+0x20. The helper increments
the count and calls `0x0e0015f2`; it does not dispatch the request callback
in this body. Message-allocation failure frees a non-null payload. Bounded
`0x0e009b42(M)` likewise frees M+8 when non-null, then M. This records a
payload ownership behavior, not a safe interface for arbitrary borrowed data.

## Error callback uses saved values after removing the entity

**`0x0e02a588(E,error)`** saves client ID, entity ID, L, E state byte +0x14
and callback E+0x30. That callback is the backend copy of C+8, previously
resolved to `0x0e2896cc`. It calls **`0x0e02a2dc(id)`** first. Unless the
saved state byte was 0x11, it invokes the saved callback as
`(client_id,id,L,low_error_byte)`.

Removal unlinks the matching E from the same global entity list, calls
unbounded cache cleanup `0x0e024650(E)`, releases Q through `0x0e02a26a`,
releases D through `0x0e02a21e`, frees non-null E+0x60/+0x70, frees E and
decrements the entity count. Saved callback/context values therefore matter:
the notification is after entity cleanup. Full list invariants, ownership of
L, cancellation and reentrancy remain unresolved.

## Reproduce and next boundary

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with `ProbeShpAppAcquisitionDispatch.java` / `.class`, an absent absolute JSON
path and `-noanalysis -readOnly`. Final report/console are local under
`out/rea_shpapp/acquisition_dispatch_checked.*`; independent listing and
verification use `acquisition_dispatch.objdump.txt` and
`acquisition_dispatch.verification.json`.

Next: consume messages with owner 0 and events 2/3, identify their registered
handler and connect cache response/body delivery to the entity's copied
callbacks. Entry candidates are queue execution `0x0e009c54`, registration
`0x0e00a160` and request event dispatch `0x0e02cc28`; those candidates are not
included in this stable probe. Actual byte acquisition, cache backing store,
FactoryFs member access, transport, widget installation, script execution,
host events, menus, orientation, RBM mode 2, global IDs and Rsrc2 remain
unresolved. Cellular, AMSS, RF, SIM and baseband paths remain excluded.
