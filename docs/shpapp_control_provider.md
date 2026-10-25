# Control provider, frame and receiver fields

The control's `+0x30` provider constructs the object used by both the native
name bridge and geometry update. Its `+4` word holds that object, called `W`
below. Listener registration obtains its document receiver through
`read32(read32(W+0x10)+0x464)`. The backing constructor clears this field;
its later assignment and the generic dispatch receiver's identity remain open.

## Input and verification

Embedded ShpApp ELF SHA-256:
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Parent identity/address conversion are in the
[listener report](shpapp_widget_listener.md). The hash-guarded original probe
`ProbeShpAppControlProvider.java` selects eleven bounded Thumb functions.
Ghidra 12.1 completed all eleven decompilations; all 458 instruction addresses
matched independently bounded ARM objdump 2.45.50 output. Two expected words,
the physical ELF hash and read-only project discard were verified.

These are ordinary Ghidra/objdump observations, not REA Evidence or execution.
Labels such as provider, frame and geometry describe the observed relationships,
not recovered source class names. Register/stack flow takes precedence over
inferred pseudocode signatures, including spurious extra arguments and return
types. Balanced subobject add/subtract sequences support the field layout below;
the probe does not independently decompile every helper they call.

## Provider creation and ownership

The [control initializer](shpapp_control_factory.md) calls
`0x0e294516(U,U+0x30)`. This function allocates 16 bytes, calls constructor
`0x0e294508`, then initializer `0x0e294478(P,U)`. A positive initializer result
stores `P` through the output pointer. Signed nonpositive results destroy/free
the provider and return the failure value. The constructor clears words
`P+0`, `P+4`, `P+8` and byte `P+0x0c`.

The initializer performs these steps, with null-result gates:

1. Allocates 20 bytes, calls `0x0e29cf80(allocation,P)`, stores the result at
   `P+8`.
2. Allocates 12 bytes and calls `0x0e288668`. It passes that result as the
   fifth argument to `0x0e334852(out,read32(U+0x2c),0,read32(P+8),helper)`.
   The factory allocates `0x98` bytes and calls `0x0e145f28`; the returned
   pointer is transferred to `P+4` through `0x0e354b5e`.
3. Allocates `0x9c` bytes and calls `0x0e149cc4(allocation,read32(P+4))`,
   obtaining the geometry object `G`.
4. Calls control virtual slot `+0x9c`, then
   `0x0e147358(W,U,slot_result)`. This helper writes `W+0x88=U` and
   `W+0x8c=slot_result`.
5. Calls `0x0e145690(W,G)`, then `0x0e145884(W)`, writes `P+0=U`, and
   returns raw `1`.

Together with the previously verified getter `0x0e28c0ae(P)=read32(P+4)`,
this supplies the same expression
`W=read32(read32(U+0x30)+4)` used by the bridge and geometry path. It does not
establish that a particular script execution context holds this exact `W`.
The host's invocation and default-widget installation remain unknown.

## Frame backing and document field

Constructor `[0x0e145f28,0x0e14600a)` initializes the `0x98`-byte `W`, allocates
`0x738` bytes, calls backing constructor `0x0e145dfc`, and stores the result at
`W+0x10`. Call the backing base `K`. The backing constructor's selected writes
include:

| Field | Observed value/role |
| --- | --- |
| `K+0` | Incoming subordinate object from `U+0x2c` |
| `K+4` | `W` back-reference |
| `K+0x440` | Cleared; later lazy associated-object storage from the bridge report |
| `K+0x45c` | Incoming optional parent; zero on the examined provider path |
| `K+0x460` | Cleared geometry pointer field |
| `K+0x464` | Cleared document receiver field |

The accessor `[0x0e145634,0x0e145640)` loads literal
`read32(0x0e145930)=0x444`, adds `0x20`, and returns `read32(K+0x464)`.
This makes the listener-registration receiver's storage location explicit.
The constructor clear is an observed write, not proof that the field stays
zero through all later helper calls or through the entire initialization path.
The backing object's subordinate area at `K+0x28` is initialized through
`0x0e16064a`; `0x0e145884` later forwards this area to `0x0e164626`.
Their complete effects, including possible document creation, are not covered.

## Geometry installation

Constructor `[0x0e149cc4,0x0e149d1e)` installs table
`read32(0x0e14a030)=0x0e5c883c` at `G+0`, with table base `+0x84` at `G+0x24`.
It supplies `W` to helper `0x0e354b10` at `G+0x94`, allocates `0x188` bytes
through `0x0e32dac8(allocation,G)` at `G+0x98`, and invokes initialization
helpers. Complete lifetime semantics of the `W` link remain unresolved.

`[0x0e145690,0x0e14571c)` stores `G` at `K+0x460`, increments incoming
`G+0x7c` when nonnull, and releases the old field through `0x0e336506` when
nonnull. Its null-input branch performs additional document/geometry operations.
The provider takes the nonnull path after its allocation gate. This connects
the constructed `G` to the previously examined geometry getter and resize path;
it does not recover physical dimensions or orientation behavior.

## Remaining receiver boundary and reproduction

Registration uses `D=read32(K+0x464)`, while generic named-event dispatch uses
`R=read32(D+0x10)`. This pass resolves `W` construction and the location storing
`D`; it does not show the assignment of `D` or prove `R==D`. Do not infer delivery
to a Widget listener from the shared provider alone. Actual custom event names,
callback execution, resource IDs, RBM mode 2 and Rsrc2 remain unknown.

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with `ProbeShpAppControlProvider.java` / `.class`, an absent JSON destination,
and `-noanalysis -readOnly`. Local outputs are
`out/rea_shpapp/control_provider.ghidra.json`, `.console.log`, `.objdump.txt`
and `.verification.json`. The literal-reference candidate search in
`frame_document_field_candidates.json` is bounded to `0x0e145000..0x0e148000`
within a mixed full listing; it is not a complete writer search or call graph.

Next: follow the `K+0x28` subordinate initialization/start path to document
construction, then verify its `+0x10` field. Cellular/baseband work stays excluded.
