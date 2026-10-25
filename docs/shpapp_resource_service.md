# Resource loading queues and provider handoff

The loading entry from the [script-resource report](shpapp_script_resource.md)
constructs jobs, selects queues by scheme, builds a transfer object and can hand
the request to a constructed frame provider's virtual +0x0c method. The
provider converts it again and forwards it into another bridge; returned
bytes remain unknown. This does not establish
FactoryFs/ZIP access or an actual network transfer.

## Input and verification

Embedded ShpApp ELF SHA-256:
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Parent identity/address conversion are in the
[listener report](shpapp_widget_listener.md). Original hash-guarded
`ProbeShpAppResourceService.java` covers twenty-two bounded Thumb functions with
explicit islands excluding strings/literals. All decompiled; all 1,444
instruction addresses matched independent bounded ARM objdump 2.45.50 listings.
Fifteen words, four literals, physical hash and Ghidra 12.1 read-only discard
matched. These are ordinary local observations, not REA Evidence or execution.
Names such as queue, job, transfer and provider describe structural roles;
original types and opaque helper contracts remain inferred.

## The shared manager embeds the loading service

Manager constructor `0x0e15c3e8(M)` calls `0x0e169cc2(M+0x20)`, giving service
B=M+0x20. That constructor creates a generic queue at B+0x1c, clears its map,
and constructs a deferred-work object. Queue constructor `0x0e169c84` creates
three 20-byte queue areas at Q+4, Q+0x18 and Q+0x2c, clears bookkeeping and
stores incoming limit 0x2710 at Q+0x60. The limit's units/meaning are unknown.

`0x0e16a260(B,R,Z,0,0,1)` allocates a 28-byte job Y through `0x0e16c424`:

| Field | Value for this path |
| --- | --- |
| `Y+0x10` | resource Z |
| `Y+0x14` | document resource loader R |
| `Y+0x18` | 0 |
| `Y+0x19` | 0 |
| `Y+0x1a` | 0 |
| `Y+0x1b` | 1 |

The constructor also calls a resource/job association helper. Selected job
fields are not a complete transport ABI.

The enqueue method forms a name object from Z+0x20 and checks `http`/`https`
through bounded `0x0e1a685c`. That helper checks a scheme span and applies a
character-conversion helper before comparing ASCII. A positive match selects
a map at B+4 keyed by a derived name helper; an absent entry gets a new 0x68-byte
queue. Other schemes select Q=B+0x1c. Derivation of the map key is not yet
proved to be exactly a hostname or origin.

Priority helper `0x0e16a22e` returns constant 2 in this binary. Append helper
`0x0e16a206` uses Q+4+20*priority, then `0x0e16a1d8` drains from priority 2
down to the supplied threshold. Thus this examined path attempts its priority-2
queue immediately, subject to drain gates. An alternate deferred-work branch
exists in enqueue but its priority==0 condition is not selected by this helper.

## Draining builds a request and transfer

`0x0e169da2(Q,queue,&continue)` obtains Y from the queue, reads Z=Y+0x10 and
R=Y+0x14, and applies resource/document and queue-limit gates. It builds a
request using Z+0x20 and document data from R+0x38. The request contains
header-building paths including Referer and conditional cache headers; their
full policy is outside this report.

At `0x0e16a04e`, the drain calls:

`0x0e16cd26(&T,read32(read32(R+0x38)+0xd0),Q,&request,Y[0x1a],Y[0x1b],1)`.

The first data argument is the document's frame W. The remaining fields are
explicit register/stack arguments, despite incomplete inferred signatures.
A null T leads to resource virtual +0x18, which is the previously resolved
script error/notification entry for class 2. A nonnull T enters a per-queue
tracking container and marks resource byte +0x109. Runtime gate values and
completion timing remain unknown.

Creation helper `0x0e16cd26` checks W and settings, prepares a request copy,
handles document-associated restrictions and allocates 0x268 bytes. It calls
`0x0e16ccf0(T,W,Q,flag,flag)`, then invokes T's +0x40 method. Construction
installs `read32(0x0e16d0e8)=0x0e5ac3b4`, whose +0x40 word at `0x0e5ac3f4`
is raw `0x0e16cffb`, selecting `0x0e16cffa`.

The creator has a separate branch comparing a name against guarded `file`
at `0x0e16d0f0`. This is a scheme-specific gate, not evidence that a file or
ZIP member is actually read.

## The transfer reaches the frame's constructed provider

Base constructor `0x0e16cb9a` writes W at T+0x18 and initializes bookkeeping.
The derived constructor writes incoming Q at T+0x260. Start method
`0x0e16cffa` performs frame-associated preparation, then calls
`0x0e16c554(T,&request)`.

The base-start method stores request-name data at T+0x180, makes a local copy,
and invokes T's virtual +0x60 preparation hook. It checks a request predicate:
one branch invokes an error/reporting method and returns zero. Another branch
can save the request at T+0x1b8 when byte T+0x1b4 is set. Otherwise it reaches
an indirect provider call at `0x0e16c5f2`:

`N = read32(read32(read32(T+0x18)+0x18)+8)`

followed by `N.table[+0x0c](N,T,incoming_request)`.

For T+0x18=W, this is `N=read32(read32(W+0x18)+8)`. This is distinct from
page-like H returned by `0x0e14593c(W)=read32(read32(W+0x10))=read32(K)`.
The document helper `0x0e1e2f14` reaches H through D+0xd0=W; the creator uses
H-associated methods for additional gates, not for this start call.

The [provider construction probe](shpapp_control_provider.md) already bounds
allocation `0x0e334852` and frame constructor `0x0e145f28`. Their fifth argument
is N, created in the provider initializer through `0x0e288668`. The frame
constructor allocates a 12-byte bridge V and calls `0x0e1a2aec(V,W,N)`, storing
V at W+0x18. Newly bounded bridge construction writes W at V+4 and N at V+8,
then calls N's +0x1c method with V.

Newly bounded `0x0e288668` installs
`read32(0x0e288938)=0x0e58a764` at N+0 and constructs its helper at N+8.
Table +0x0c word at `0x0e58a770` is raw `0x0e2887d9`; therefore the examined
constructed frame's start call selects **`0x0e2887d8(N,T,&request)`**.
It allocates a 0x6c-byte converted request, copies/prepares name, method,
request fields and control-associated values, then calls
`0x0e288b4c(read32(N+8),converted,T)` at `0x0e2888d0`.

The bounded dispatch helper invokes T+0x54, forwards through `0x0e28b5b6`, and
has a conditional callback-wrapper construction path leading to `0x0e28b120`.
The contracts of these two callees, callback ownership and accepted-byte
connection are the next boundary. This resolves the indirect start target for
the constructed frame without proving actual transport or package access.

A zero provider return leads to base-start return 1; nonzero leads to return 0.
These are branch values, not a recovered host success-code specification.
The hook, saved-request path and provider side effects prevent claiming that
every request performs that external call or that it succeeds.

## Reproduce and next boundary

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with `ProbeShpAppResourceService.java` / `.class`, an absent absolute JSON path,
and `-noanalysis -readOnly`. Local report, console, bounded listing and
independent verification are under `out/rea_shpapp/resource_service*`; final
report/console use `resource_service_provider.*`.

The [request-bridge follow-up](shpapp_request_bridge.md) resolves prefix-based
provider selection, request-ID registration and wrapper callbacks into T's
concrete byte/completion slots. Next: provider acquisition and transfer/queue
delivery to resource acceptance. Transport,
package-member acquisition, installation, actual scripts/callbacks, host events,
menus, orientation, RBM mode 2, global IDs and Rsrc2 remain unknown.
Cellular/baseband paths remain excluded.
