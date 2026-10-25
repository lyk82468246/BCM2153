# Document-owned script input routes

Two document-owned routes feed the previously bounded script evaluation entry:
collected child-node text and a resource-request completion path. A frame-loader
adapter can also prepare input and call that same evaluator. This connects
static document/input processing to the constructed script context; it does not
show a particular FactoryFs package loading or a callback executing.

## Input and verification

Embedded ShpApp ELF SHA-256:
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Parent identity/address conversion are in the
[listener report](shpapp_widget_listener.md). Original hash-guarded
`ProbeShpAppScriptInputs.java` selects seventeen bounded Thumb functions,
including explicit shared epilogues. All decompiled; all 817 instruction
addresses matched independently bounded ARM objdump 2.45.50 output. Seven
words, six language literals, physical ELF hash and Ghidra 12.1 read-only
project discard were verified.

These are ordinary local observations, not REA Evidence or execution. Labels
such as script element, text, request and completion describe the observed
relationships. Original source types, request transport and actual package-loading
behavior remain unresolved. The [registry follow-up](shpapp_script_registry.md)
resolves the script tag and four attribute spellings used by this interface.
Decompiler signature and unreachable-branch warnings do not override assembly.

## Document ownership and evaluation gate

Constructor `0x0e21b750` builds an owner object O, installs its tables and calls
`0x0e1f9740(O+0x48,O+0x44,O)`. Call the embedded helper X. Its constructor
stores interface `I=O+0x44` at X+4, owner O at X+8, and clears bytes X+0x10
through X+0x13. The helper table is
`read32(0x0e1f9854)=0x0e5ac2d4`. The owner is created with a registry reference
at `read32(0x0e21bb48)=0x0e5fb3c8`; the registry follow-up independently maps
this slot to `script` in the XHTML namespace.

`0x0e1f93f2(X,input)` returns without evaluation when X+0x11 is already set,
input+8 equals input+4, its type/language gate fails, the frame pointer is
null, or frame script settings disallow evaluation. It computes:

`D=read32(read32(X+8)+0x10)` and `W=read32(D+0xd0)`.

This matches the incoming W stored by the examined
[document base constructor](shpapp_document_receiver.md). After the gates it
sets X+0x11 to 1, obtains `J=0x0e14594e(W)`, and calls
`0x0e286e46(&result,J,input)` at `0x0e1f9446`. It then destroys the local result
and calls a further helper. The marker is set before the call, not conditional
on successful script execution.

The bounded frame gate `0x0e287238(J)` checks global state and a bit in a
frame-associated settings object. Its concrete runtime value remains unknown.
`0x0e1f936e(X)` obtains `type`/`language` through I slots +0x14/+0x18. One branch passes
a converted value to `0x0e1a7c50`; another calls `0x0e1f9182`; the default
branch returns 1. The language helper builds a set containing JavaScript
versions and other names, then queries it. Six guarded literals are
`javascript`, `javascript1.0`, `javascript1.7`, `livescript`, `ecmascript` and
`jscript`. This does not establish complete MIME/case-normalization semantics.

## Collected text and request branches

`0x0e1f951e(X,name_value)` updates D+0x70 from the type/language predicate.
When X+0x10 is clear, a predicate on name_value selects either:

- `0x0e1f94a6(X,name_value)`, which prepares a charset value via
  `0x0e1f9456`, passes X to `0x0e15edcc`, and stores the returned resource at
  X+0x0c through `0x0e15e0ac`; or
- `0x0e1f90cc(&text,X)`, then
  `0x0e32e3a0(&input,&text,D+0xf4,1)` and the common evaluation gate.

The registry follow-up corrects the earlier request-name interpretation of
`0x0e1f9456`: it reads I+0x10, which resolves to `charset`, and can substitute
a frame-associated default. The incoming name_value is separately passed as
the second argument to `0x0e15edcc`. I+0x0c reads `src`; the
[request follow-up](shpapp_script_request.md) resolves the owner getter and
attribute-update paths into this incoming value.

The text collector starts at `read32(O+0x2c)`, follows each node's +0x18 link,
and selects nodes through virtual slot +0x58. It obtains selected node values
through `0x0e33afc8`; one node has a direct result path, multiple nodes are
appended through `0x0e3359cc`. The node predicate's full class semantics remain
outside the probe, so this is a text-collection role inference.

The text-input factory allocates 20 bytes for a source object, calls base
constructor `0x0e31fe58`, installs table `0x0e5b4464`, and copies the text value
to source+0x10. Span constructor `0x0e31e682` consumes its source pointer,
clears input+4, obtains input+8 through source virtual +0x10, and stores
`max(line_argument,1)` at input+0x0c. Thus the nonempty check in the evaluation
gate concerns the constructed input span, not a bare text magic or filename.

Completion entry `0x0e1f97e2(X,resource)` sets X+0x13. It checks resource byte
+0xe2. On the clear branch it calls `0x0e32e380(&input,resource)`, which forwards
to `0x0e32782c` and the span-copy helper, then calls the common evaluator and
I slot +0x1c. The other branch calls I slot +0x20. Both perform cleanup.
Resource success/error names are interpretations of these branches; transport,
cache contents and the full completion-registration mechanism are not recovered.
The completion function includes the shared return island
`[0x0e1f97de,0x0e1f97e2)` and excludes adjacent hash/literal data.

## Frame-loader forwarding and remaining boundary

Loader adapter `0x0e163416(out,L,input)` reads W from L+0xb4, checks the frame
gate and J+0x35, then calls the same `0x0e286e46` at `0x0e16345e`.
It temporarily sets L+0x1bd, handles bookkeeping and moves the result to out.
Its shared epilogue is `[0x0e162d52,0x0e162d56)`.

`0x0e1634a4` prepares an input span through `0x0e3278ac` using incoming text
and loader-associated name data, then calls that loader adapter. This does not
establish every caller's data origin or prove that package ZIP members reach
this route. The [context report](shpapp_script_context.md) covers the next
construction/engine boundary.

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with `ProbeShpAppScriptInputs.java` / `.class`, an absent absolute output path,
and `-noanalysis -readOnly`. Reports, bounded listings and verification remain
in ignored `out/rea_shpapp/script_inputs.*`.

The request follow-up connects src to the request manager. Next: follow resource
construction/scheduling and package-member loading. Actual installed-widget execution,
callback delivery, host event values, native-menu ownership, physical
orientation, RBM mode 2, global IDs and Rsrc2 remain unknown. Cellular/baseband
paths remain excluded.
