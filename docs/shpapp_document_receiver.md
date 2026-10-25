# Document construction and event receiver identity

The frame loader creates a document and installs it into the field used by
Widget listener registration. The examined base document constructor writes
`D+0x10=D`. For documents from these construction paths, this explains why the
generic named-event dispatcher loads `read32(D+0x10)` while registration uses
`D` directly: both expressions select the same constructed receiver. This closes
the structural pointer gap for the examined document family, without observing
a host event, a particular script context or callback execution.

## Input and verification

Embedded ELF SHA-256:
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
See the [listener report](shpapp_widget_listener.md) for parent identity and
address conversion. The original hash-guarded `ProbeShpAppDocumentReceiver.java`
selects twelve Thumb functions, with explicit islands for literal pools and
shared epilogues. Ghidra 12.1 completed all twelve decompilations; all 1,785
instruction addresses matched independently bounded ARM objdump 2.45.50 output.
Eight expected words, two type literals, the physical ELF hash and read-only
project discard were checked.

These are ordinary local Ghidra/objdump observations, not REA Evidence or target
execution. Analyst labels and decompiler types are interpretations. The probe
does not establish every document subtype or an immutable lifetime invariant.
Full constructor listings and pseudocode stay in ignored `out/`.

## Loader back-reference and creation

Use the [provider report](shpapp_control_provider.md)'s notation:
`K=read32(W+0x10)`, loader area `L=K+0x28`, and document field `K+0x464`.
The backing constructor calls `0x0e16064a(L,W,helper)`.
That constructor stores `W` at `L+0xb4` and the incoming helper at `L+0xb8`.
This supplies the back-reference used in the following calls.

The provider eventually calls `0x0e145884(W)`, which forwards `L` to
`0x0e164626`. Within this bounded start function:

1. An indirect method on the helper at `L+0xb8` supplies a temporary object
   through table slot `+0x144`; `0x0e161272` receives that object.
2. It initializes local request-like values and invokes
   `0x0e163110(L,&local_value,0,0)` at `0x0e164784`.
3. Subsequent bookkeeping obtains the current document via `W`.

This identifies a static initialization path. The indirect helper's full
contract and the actual initial document contents are not recovered.

`0x0e163110` maintains loader state and calls
`0x0e1ea1d0(out,L+0x1c0,read32(L+0xb4),0)` at `0x0e163232`.
It takes the returned pointer, retains a copy by incrementing `D+8` when
nonnull, then calls `0x0e1461a2(W,&document_copy)` at `0x0e163254`.
Other virtual calls and request/bookkeeping helpers in this function remain
outside the recovered interface contract.

## Type-dependent construction

The factory compares its type argument against verified literal `text/html`
at `0x0e1ea460`, among other strings. This branch calls `0x0e32a9ec(out,W)`.
That helper allocates `0xb68` bytes, enters `0x0e2094f6`, and stores the
returned pointer, incrementing its `+8` word when nonnull.

`0x0e2094f6` is a three-instruction entry adapter: it moves incoming `W` to
argument 2, sets argument 1 to zero, and branches to constructor `0x0e2093e0`.
The constructor calls the base document constructor `0x0e1e8de8` at
`0x0e209408`, then installs derived tables and additional fields.
Its descriptor at `0x0e595e4c` holds table `0x0e595b90`; the table's `-0x0c`
word is `0xb60`. Thus the descriptor-dependent write at `0x0e20941e` targets
`D+0xb60`, rather than the self-link field. These three words are probe guards.

A separate comparison with verified `application/xhtml+xml` at `0x0e1ea474`
can reach `0x0e335cc8(out,W)` at `0x0e1ea24e`, subject to the examined settings
gate. That helper allocates `0xad8` bytes and directly calls the same base
constructor with flag 1. Other factory branches select additional constructors;
their complete subtype behavior is not covered here. This is not evidence that
one of these type strings was actually supplied by the packaged widgets.

## Self-link and installation

The base constructor's selected writes are:

| Site | Observed field |
| --- | --- |
| `0x0e1e8e00` | Base table `read32(0x0e1e8ea0)=0x0e5c7c34` at `D+0` |
| `0x0e1e8e04` | Interface table `read32(0x0e1e8ea4)=0x0e5c7e4c` at `D+0x24` |
| `0x0e1e9212` | `D+0x10=D` (`str r5,[r5,#16]`) |
| `0x0e1e9224` | Incoming frame `W` at `D+0xd0` |

The complete constructor uses `[0x0e1e8de8,0x0e1e8e90)` and
`[0x0e1e8eac,0x0e1e9308)`, plus the shared epilogue chain at `0x0e1e8b48`,
`0x0e1e876e` and `0x0e1e804a`. The large field-initialization sequence and
balanced subobject offsets support identifying `r5` as the document base at the
self-store. Pseudocode independently renders a self-pointer assignment there.
Unexamined callees and later mutations prevent treating this as a universal
runtime invariant for arbitrary objects accepted by the setter.

`[0x0e1461a2,0x0e14625a)` computes its field offset using
`read32(0x0e14625c)-0xe0 = 0x544-0xe0 = 0x464`.
At `0x0e1461e2..0x0e1461ee`, it reads the old field, takes the pointer from
the caller's word, clears that word, and writes the pointer to
`read32(W+0x10)+0x464`. It conditionally releases the old pointer through
`0x0e3a2708`, performs other lifecycle-related virtual calls, and invokes a
helper on backing area `+0x468`. Its explicit stores do not set the incoming
object's `+0x10`; the observed self-link comes from the constructor.

Consequently, for the examined constructed documents:

`registration D = read32(K+0x464)` and
`generic dispatch R = read32(D+0x10) = D`.

The [named-event source report](shpapp_event_sources.md)'s two flag groups can
therefore address that same document's listener list. A particular Widget
script context's `W` still needs to be connected to the provider's `W` before
claiming delivery to a packaged widget. Gating, actual incoming names and
callback execution remain separate unresolved questions.

## Reproduction and next boundary

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with `ProbeShpAppDocumentReceiver.java` / `.class`, an absent output path,
and `-noanalysis -readOnly`. Final local outputs are
`out/rea_shpapp/document_receiver_verified.ghidra.json`, its `.console.log`,
`document_receiver.objdump.txt` and `document_receiver.verification.json`.
Candidate searches in `document_*_candidates.json` are mixed-listing seeds,
not complete writer searches or call graphs.

Next: connect the Widget adapter's script-context frame lookup to the constructed
provider frame, or resolve the external host's name-bridge use. Real custom event
values, default-widget installation, physical orientation, native-menu ownership,
RBM mode 2, global resource IDs and Rsrc2 remain unknown. Cellular/baseband
research remains excluded.
