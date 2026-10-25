# Script global construction and frame lookup

The examined frame constructs a script wrapper and global object using the same
associated object A returned by the native event-name bridge. The global lookup
used by Widget listener registration recovers A through a backing field, then
reads A+0x44 to obtain W. This resolves the construction relationship between
the provider frame and script-global frame. It does not establish which global
an actual packaged widget execution selects, or observe callback delivery.

## Input and verification

Embedded ShpApp ELF SHA-256:
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Parent identity and address conversion are in the
[listener report](shpapp_widget_listener.md). The original hash-guarded
`ProbeShpAppScriptFrame.java` selects twenty bounded Thumb functions. All twenty
decompiled; all 647 instruction addresses matched independently bounded ARM
objdump 2.45.50 output. Fifteen expected words, the physical ELF hash and the
read-only project discard were verified. Reports, full listings and pseudocode
stay in ignored `out/rea_shpapp/`.

These are ordinary local Ghidra/objdump observations, not REA Evidence or target
execution. Analyst labels describe pointer relationships, not recovered class
names. Inferred decompiler signatures include spurious void/64-bit returns;
register and stack flow determine the pointer transfers described below.
Unexamined callees, subsequent mutations and runtime context selection remain
outside this construction result.

## Frame-owned script state and associated object

Use the [provider report](shpapp_control_provider.md)'s
`K=read32(W+0x10)`. Its already verified backing constructor `0x0e145dfc`
calls `0x0e286bcc(K+0x468,W)` at `0x0e145e6e`. Call this embedded script area
J. The new bounded constructor confirms `J+0x0c=0` and `J+0x28=W`, the latter
at `0x0e286bec`. Accessor `0x0e14594e(W)` returns J.

`0x0e32e2ec(J)` returns `read32(J+0x0c)`. If that field is null, and two
additional state/resource gates permit initialization, it calls
`0x0e286d7e(J)`. A failed gate can leave the returned pointer null; this is not
unconditional script initialization. The initializer:

1. Requests `0x1c` bytes through `0x0e280896`.
2. Gets `A=0x0e1459f2(read32(J+0x28))` and retains a local pointer through
   `0x0e345eba`. That small helper stores A and increments A+4 when nonnull.
3. Calls `0x0e2807f8(allocation,&A_copy)`, producing wrapper C.
4. Stores C through `0x0e34236c(J+0x0c,C)` and performs further setup.

The lazy associated-object getter `0x0e1459f2(W)` uses `K+0x440`. On a null
field it allocates `0x78` bytes, calls `0x0e13ffb8(A,W)` and installs its result
there. The bounded constructor writes `A+0x44=W` at `0x0e13ffdc`; its table is
`read32(0x0e140014)=0x0e5c87b0`. This is the same getter used by the
[native name bridge](shpapp_event_bridge.md).

## Global backing pointer and associated-object field

Constructor `0x0e2807f8(C,&A_copy)` initializes C, clears C+0x18, consumes the
incoming A pointer, and calls `0x0e280734(C,&A_copy)`. The latter obtains a
`0x20`-byte object through `0x0e0e2888`, then calls
`0x0e10678c(allocation,&temporary_value,&A_copy,C)` at `0x0e2807ca`.
Call the resulting script-global object Q. The entry forwards to
`0x0e27f198`, then installs table `0x0e593868`.

`0x0e27f198` allocates `0x1d8` bytes for backing object S and calls
`0x0e27f166(S,&A_copy,C)`. That constructor first calls `0x0e27e12a`, then
consumes the incoming pointer and writes:

| Site | Observed write |
| --- | --- |
| `0x0e27f180` | `S+0x1b4=A` |
| `0x0e27f184` | `S+0x1b8=0` |
| `0x0e27f186` | `S+0x1bc=C` |

The register arithmetic is `S+0xff+0xb5=S+0x1b4`, followed by a subtraction
of `0x34` and stores at offsets `0x38`/`0x3c`. This avoids interpreting a
word-indexed pseudocode field as a byte offset.

Next, `0x0e27f198` passes S to `0x0e27dc5c(Q,&temporary_value,S,C)`.
The base constructor converts nonnull S to S+4 and writes that pointer to
Q+0x18 at `0x0e27dca0`. Later, `0x0e280734` calls `0x0e32dcf8(C,Q)`;
its explicit write at `0x0e32dd1a` installs Q at C+0x18. C+0x18 and Q+0x18
therefore refer to different levels of the construction.

## Widget lookup and remaining runtime boundary

The previously examined Widget adapter calls `Q=0x0e323488(exec)` and
`A=0x0e339a88(Q)`, then reads W from A+0x44. The bounded lookup chain is:

- `0x0e339a88` forwards to `0x0e33b8e8`.
- `0x0e33b898(Q)` returns `read32(Q+0x18)-4` when the stored word is nonnull,
  otherwise zero.
- `0x0e33b8e8` reads the returned address plus `0x1b4`. It has no additional
  null guard before that field access.

For Q from the construction above, these expressions recover S, then A, then
the same W used to create J. Together with the
[document installation and self-link](shpapp_document_receiver.md), this gives
an explicit static route from a provider-owned script global to the document
listener list addressed by native named-event dispatch.

`0x0e323488` still selects Q according to its input execution context:
`0x0e339258(exec)` walks the linked nodes beginning at `read32(exec-0x38)`
to the last node and returns its +4 word. The selector invokes this root
object's virtual slot +0xb8. If the result equals exec, it returns the root;
otherwise it returns `read32(read32(read32(exec-0x38)+8)+0x4c4)`.
The construction above does not identify the concrete exec, initialize all
these context-node fields, or prove that the alternate branch selects this Q.

## Reproduction and next boundary

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with `ProbeShpAppScriptFrame.java` / `.class`, an absent absolute output path,
and `-noanalysis -readOnly`. Final local outputs are
`script_frame_verified.ghidra.json`, `script_frame_verified.console.log`,
`script_frame.objdump.txt` and `script_frame.verification.json`.

Next: trace actual script evaluation/context setup or host use of the exposed
name bridge. Concrete host event values, packaged callback execution,
default-widget installation, physical orientation, native-menu ownership,
RBM mode 2, global IDs and Rsrc2 remain unknown. Cellular/baseband research
remains excluded.
