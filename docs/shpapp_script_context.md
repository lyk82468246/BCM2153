# Constructed script execution context and evaluation entry

The global constructor initializes a root execution state whose context node
points back to Q. For that constructed state, the Widget global selector takes
its root branch and returns Q, resolving the context-node gap left by the
[script-frame report](shpapp_script_frame.md). A separate bounded script-input
entry obtains this state and calls a compilation/evaluation bridge. This is a
static construction and call-path result; no packaged script was run.

## Input and verification

Embedded ShpApp ELF SHA-256:
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Parent identity/address conversion are in the
[listener report](shpapp_widget_listener.md). Original probe
`ProbeShpAppScriptContext.java` selects fourteen functions: thirteen Thumb
functions and one explicitly selected ARM copy helper. All decompiled; all 725
instruction addresses matched independently bounded ARM objdump 2.45.50 output.
Eight expected words, the physical ELF hash and read-only project discard were
verified using Ghidra 12.1.

These are ordinary local observations, not REA Evidence or target execution.
The explicit ARM/Thumb selections and objdump's armv5t option describe decoding,
not proof of a physical CPU model. Analyst labels and inferred pseudocode types
are interpretations. The decompiler removes some bridge branches as unreachable
because opaque callees have incomplete signatures; those removals do not prove
that exception paths are absent. Register/stack flow takes precedence.

## Global initialization creates the root node

Use the previous report's global Q, backing S and script wrapper C:
`read32(Q+0x18)=S+4`, `read32(S+0x1b4)=A`, `read32(C+0x18)=Q`.
Its global-base constructor calls `0x0e0e43ac(Q,C)` at `0x0e27dcb0`.
The bounded initializer has code islands `[0x0e0e43ac,0x0e0e4414)` and
`[0x0e0e44e0,0x0e0e4590)`; intervening literals are excluded.

The helper `0x0e3387d8(Q)` recovers S using the same Q+0x18 minus four
expression as the previous associated-object accessor. The initializer obtains
a shared-state pointer G and installs it at S+0x104, then allocates a 20-byte
context node N. Selected writes at `0x0e0e43f8..0x0e0e4404` are:

| Field | Observed value |
| --- | --- |
| `N+0` | `0`, terminating the root-node chain |
| `N+4` | `Q` |
| `N+8` | `read32(S+0x104)`, called G here |
| `N+0x0c` | incoming C |
| `N+0x10` | `1`, then incremented for a retained copy |

It installs N at S+0x20 at `0x0e0e44e2`, releases temporary/old references,
and calls `0x0e3234d6(E,0,0,N,1,0,0,0)` at `0x0e0e4510`, where
`E=0x0e0e289c(Q)=S+0x64`. The surrounding register/stack setup establishes
these eight arguments despite an incomplete inferred initializer call signature.

`0x0e3234d6` passes E and its fourth argument N to `0x0e323414`.
That helper places N and tag byte `0x0b` in a temporary and calls
`0x0e32357c(E-0x38,&temporary)`. The writer invokes ARM helper `0x0e311640`
with length five, then restores its destination return register.
For this length, the ARM path copies one word and one byte. Thus it writes
`read32(E-0x38)=N`, with the tag at E-0x34. The other state-initialization
stores do not overlap that pointer word. The copy helper is analyzed as ARM
on `[0x0e311640,0x0e3116ac)`; forcing Thumb there would give incorrect results.

## The constructed root state selects Q

Verified word `read32(0x0e593920)=0x0e27f14b` is slot +0xb8 of Q's final table
`0x0e593868`. Entry `0x0e27f14a(Q)` obtains A, optionally calls `0x0e1460b0`
on A+0x44, then returns `0x0e0e289c(Q)=S+0x64=E`.

For the constructed E and unchanged node links:

1. `0x0e339258(E)` begins at `read32(E-0x38)=N`.
2. Since N+0 is zero, it returns `read32(N+4)=Q`.
3. `0x0e323488(E)` invokes Q's +0xb8 method, obtaining E.
4. The equality test succeeds, so the selector returns the root Q.

The [script-frame lookup](shpapp_script_frame.md) then recovers A from S+0x1b4
and W from A+0x44, reaching the provider frame's document. This resolves a
specific constructed root-state path. Other execution frames, the selector's
alternate G+0x4c4 branch, later node mutations and indirect helper side effects
are not a universal lifetime invariant or proof of a concrete widget invocation.

## Script-input entry reaches an engine bridge

`0x0e32e32c(J)` ensures initialization through `0x0e32e33c`, then returns
`read32(read32(J+0x0c)+0x18)=Q`. State/resource gates still apply.

The script-input entry `0x0e286e46(out,J,input)` uses explicit islands
`[0x0e286e46,0x0e286fc0)` and `[0x0e287010,0x0e28709a)`.
After initialization and gates, it reads Q from the wrapper, invokes Q+0xb8
to save E, prepares input-related values, and temporarily updates J's state.
It repeats the global selector's root/alternate logic, recovers backing S,
and calls `0x0e0dbc70(&result,E,S+0x20,input,C)` at `0x0e287014`.
The fifth argument C is explicitly placed on the stack at `0x0e286fba`;
four-argument pseudocode at this call site omits that stack argument.

Bridge `[0x0e0dbc70,0x0e0dbe26)` calls `0x0e344758` with input and execution
state information at `0x0e0dbcb4`. A null result reaches an error construction
path. A nonnull result can reach `0x0e0fde3c` at `0x0e0dbd6c`, passing the
execution state, prepared object, and context node alongside other arguments.
Compilation/evaluation are role interpretations of this input-to-engine path;
the two engine helpers' complete contracts and bytecode semantics are outside
this probe. The entry also restores saved state and handles result tags; no
claim about successful script evaluation follows from its presence.

## Reproduction and next boundary

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with `ProbeShpAppScriptContext.java` / `.class`, an absent absolute output path,
and `-noanalysis -readOnly`. Local reports are `script_context.ghidra.json`,
`script_context.console.log`, `script_context.objdump.txt` and
`script_context.verification.json` under ignored `out/rea_shpapp/`.

Next: trace the script-input producer and its connection to document/package
loading, or examine external host name-bridge use. Actual packaged execution,
callback delivery, custom host event values, default-widget installation,
physical orientation, native-menu ownership, RBM mode 2, global IDs and Rsrc2
remain unknown. Cellular/baseband paths remain excluded.
