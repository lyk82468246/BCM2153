# Lower acquisition, callback copies and entity registration

The lower handoff `0x0e02fbb2` allocates a separate parameter structure and
registers a 0x78-byte entity containing copies of all twelve callback pointers.
That resolves the manager's temporary callback-table lifetime question for
this registration path. It also identifies two raw dispatch branches involving
`file://` and a queued-message helper. Actual storage reads, transport and
external callback execution remain unresolved.

## Input and verification

Embedded ELF SHA-256:
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Original `ProbeShpAppAcquisitionBackend.java` bounds seven Thumb functions,
including three separated code islands for `0x0e02fbb2`. All decompiled;
all 547 instruction addresses matched independent bounded ARM objdump 2.45.50
listings. Four initialized words, two `file://` literal locations, physical
hash and Ghidra 12.1 read-only discard matched. These are ordinary local
observations, not REA Evidence or execution. Helper types and status semantics
remain partly inferred.

Use P and C for the temporary parameter and callback structures from
[manager acquisition](shpapp_request_manager.md), L for its lower request,
Q for the new parameter structure and E for the registered entity. The lower
routine receives `(client_id,P,L,C,flag,&status)`.

## Validation and parameter preparation

**`0x0e02fbb2`** tests P, C, C+0/+4/+8 and P+0/+4 for non-null values.
Failed assertions return 0 if the assertion helper returns; these are not
uniform -1 failures and do not write status in the observed paths.
Client getter `0x0e02f2ec` accepts unsigned indices below 5 and reads a pointer
from a global array referenced by initialized literal `0x0e02f394`.
An unavailable client writes status 0x85 and returns -1. No BSS array contents
are read from the ELF's physical bytes.

The normal path allocates **Q size 0x38**. It copies scalar fields, duplicates
P+4 through length/allocation/copy helpers, obtains Q+0 through `0x0e02e796`
and, when present, duplicates strings at P+0x14/+0x18. Their exact encoding,
normalization and allocation contracts are unbounded here. It stores flag
at Q+0x30, copies P+0x2c/+0x34, byte fields +0x1c/+0x1d, and fields
+0x0c/+0x20/+0x24. It clears Q+0x10.

Q+8 initially receives P+8. With P byte +0x1c==0x60, a nonzero P+0x0c
instead allocates P+0x24 bytes and copies P+8 there; a zero P+0x0c clears Q+8.
Other byte values retain the initial pointer assignment. This is a conditional
copy, not proof of fully independent ownership for all parameter forms.
Cleanup `0x0e02a26a` frees non-null Q+8/+0x14/+4/+0/+0x18, clears those
fields and frees Q. Allocation-zeroing and source-pointer ownership remain
unresolved, so these routines are not a safe reconstructed public API.

## Entity registration copies the entire callback structure

**`0x0e029acc(Q,client_id,L,C)`** reads queue state through initialized literal
`0x0e029c10 -> 0x0e5f00dc`. It rejects a signed existing-count value above
0xbe and otherwise attempts a 0x78-byte allocation. Failure returns -1.
A successful entity receives:

| E field | Source / observed initialization |
| --- | --- |
| +0 | client_id |
| +4 | incremented global sequence value |
| +8 | -1 |
| +0x0c | Q |
| +0x14 byte | 1 or 2, selected through the `file://` predicate |
| +0x28..+0x54 | all 12 words C+0..C+0x2c, copied individually |
| +0x58 | L |
| +0x5c | result of `0x0e001666` |
| +0x68 | Q+0x2c sorting key |
| +0x74 | next, initially zero |

It increments the global count and inserts E into the list with head/tail
at global+4/+8. Key -1 appends; other keys use signed comparisons to insert
before a lower key. These are observed sorting branches, not a recovered
priority or scheduling specification. The returned value is the global
sequence. No wraparound or concurrency guarantees are established.

The twelve explicit assignments establish **function-pointer copying**, rather
than retention of the manager's C address. E also retains Q and L; that does
not prove safe lifetime of every object or pointer reachable through them.
Getter `0x0e029d24` reads this same head, and `0x0e029dba(id)` traverses
E+0x74 until E+4 matches the requested ID or the list ends.

## Return status and the two dispatch branches

The lower handoff calls registration with `(Q,client_id,L,C)`. A nonpositive
registration result frees Q, writes **status 0x84** and returns that result.
This explains one source of the manager's retry/queue status byte; it is not
a transport-error enum. On a positive ID the helper looks E up again, performs
a dispatch branch, writes status zero and returns the ID. Lookup-null handling
is absent in these immediate post-registration branches.

Both registration and dispatch call **`0x0e008596(text,"file://",7)`**.
The newly bounded adapter forwards its register arguments to an indirect
function at table slot +0x58, reached through the global referenced by
`0x0e00873c -> 0x0e5e8c0c`. Its true string-comparison rules are unknown.
Registration tests Q+0, while dispatch tests the original P+0; the normalization
helper has not been shown to preserve identical predicate results.

- Nonzero dispatch predicate: E+0x15=1 and E+0x14=3, then
  `0x0e024184(E,read8(Q+0x1d))`. Returned low byte 2 calls
  `0x0e009a18(0,2,0,0,id,0)`; other values set E+0x14=4 and call
  `0x0e02a500(E)`.
- Zero predicate: E+0x15=2 and
  `0x0e009a18(0,3,0,0,id,0)`.

The [dispatch follow-up](shpapp_acquisition_dispatch.md) bounds cache
selection/response preparation, client-state gates and message construction.
These calls do not establish a filesystem read, network access or FactoryFs
package-member acquisition. The positive ID is an entity-registration result;
calling it a completed transfer would overstate the evidence.

## Reproduce and next boundary

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with `ProbeShpAppAcquisitionBackend.java` / `.class`, an absent absolute JSON
path and `-noanalysis -readOnly`. Final report/console are local under
`out/rea_shpapp/acquisition_backend_checked.*`. Independent verification and
bounded listing use `acquisition_backend.verification.json` and
`acquisition_backend.objdump.txt`; earlier six-function candidate reports are
superseded.

The [dispatch follow-up](shpapp_acquisition_dispatch.md) resolves
`0x0e024184`, `0x0e02a500` and message queuing through `0x0e009a18`, plus
saved error callback invocation after entity cleanup. Next: message consumption
and cache body delivery into copied callback slots. Parameter ownership, host comparison implementation, external
callback timing and concrete package/transport remain unresolved. Widget
installation, script execution, host events, menus, orientation, RBM mode 2,
global IDs and Rsrc2 remain unknown. Cellular/baseband paths remain excluded.
