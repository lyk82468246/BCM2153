# Acquisition callbacks and inline `data:` delivery

The [request manager](shpapp_request_manager.md)'s acquisition table now
connects header, data, completion and error callbacks to the concrete lower
requests. Its `data:` branch creates a Content-Type header, terminates the
headers with CR/LF and delivers a payload through those same callbacks. This
is a static connection to the existing provider/registry/transfer chain; no
firmware request, package or script was executed.

## Input and verification

Embedded ELF SHA-256:
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Original hash-guarded `ProbeShpAppAcquisitionCallbacks.java` bounds 11 Thumb
functions. All decompiled; all 1,008 instruction addresses matched independent
bounded ARM objdump 2.45.50 listings. Thirteen words, 17 literal locations,
physical ELF hash and Ghidra 12.1 read-only discard matched. These are ordinary
local observations, not REA Evidence or execution. Code islands exclude
literal pools; explicit seeds include two branch stubs without normal-entry
flow. Pseudocode can omit preserved register/stack arguments; the assembly
establishes callback arguments below.

Let L be the lower request, R=read32(L+8) its converted request,
H=read32(L+0x18) the data description and O its response object. Newly bounded
`0x0e31ba9c` obtains O through H virtual +8, matching the earlier H+0x0c getter.
Thus O is a response object, distinct from the control obtained through
`0x0e28aa56`. The callback functions obtain that control and surround their
work with `0x0e0c681c` / `0x0e0c6838`; the full guard contract is unresolved.

## Header lines and the acquired-header adapter

Acquisition C+0 selects **`0x0e28944a`**. Its first two code islands end at
`0x0e28949c` and resume at `0x0e28959c`; embedded strings are excluded. It
splits a non-null header string at CR/LF, copies each line into an allocation
of line-length+3, appends CR/LF, and calls **`0x0e289196`** with its pointer
and line-length+2. It then frees the copy. A missing delimiter or failed line
allocation returns early. After the loop it allocates a three-byte CR/LF
string and calls the line parser with length 2; this final allocation is not
null-checked in the observed body. This is not a recovered safe host ABI.

The line parser obtains O, calling L virtual +0x28 if O is initially null.
A leading CR/LF writes the incoming 16-bit value to O+0x20, conditionally
clears O+0x61 when R+0x64 is zero, and invokes L virtual +0x18 when O+0x61
is zero. Other lines are split at `:` and prepared as name/value strings.
Observed literal-based branches include:

- `X-SFB-RedirectedUrl`: sets O+0x5a and calls `0x0e28be66` with the value.
- `refresh`: calls `0x0e28bdc2` with the value.
- `content-type`: records fields through `0x0e28be40` and `0x0e28be9e`;
  with R+0x64 set, converts the value, calls `0x0e28bd6e`, and derives
  O+0x61 using an empty-value test and `0x0e28ac7c`.

Other parsed names also reach the field-recording helpers. Exact string-match
rules and helper contracts remain outside this probe. Header names do not
identify the request's underlying transport or source.

## Data, completion and error reach concrete request slots

Acquisition C+4 selects **`0x0e289050`**, receiving L as argument 3,
data pointer as argument 4, length as argument 5, and final flag as argument 6.
When O+0x61 is set it derives a text value from O virtual +0x18, substitutes
`text/plain` when empty, and for length at least 0x40 tries `0x0e28ab42` then
`0x0e28ab8e` over the first 0x40 bytes. It updates O through `0x0e28bd6e`
and `0x0e28be40` with `Content-Type`, clears O+0x61 and invokes L+0x18.
If the saved L+0x24 byte remains zero, it calls L virtual +0x1c with the
original data pointer/length; a nonzero final flag then calls L virtual +0x20
with zero if that byte is still zero.

The increments at L+0x20 protect callback lifetime. Newly bounded
`0x0e31baa4` decrements that field and dispatches L virtual +4 when the signed
result is nonpositive. The code saves L+0x24 before release and uses that saved
byte for subsequent gates; full destruction/reentrancy semantics remain unknown.

Guarded request table words resolve these calls:

| L slot | Shared request table `0x0e58ac6c` | File-branch table `0x0e58abec` |
| --- | --- | --- |
| +0x18 response | `0x0e288e16` | `0x0e288d28`, immediate return |
| +0x1c data | `0x0e288f44` | `0x0e288d2a` |
| +0x20 complete | `0x0e28affe` | same |
| +0x24 error | `0x0e28b004` | same |
| +0x28 prepare O | `0x0e288f4c` | `0x0e288d32` |

The shared response method reads `Content-type`, `Content-Location` and
`Content-Length`, updates O, and invokes I virtual +0 with `(I,L,H)`, where
I=read32(L+0x0c). Both data adapters forward preserved data/length arguments to
`0x0e28b01e`. Completion/error targets and I's adjustment into the provider and
request-ID registry are already established in the
[lower-request report](shpapp_lower_requests.md). O construction in the two
+0x28 methods remains outside this stable probe.

Acquisition C+8 selects **`0x0e2896cc`**, an error path. It forwards the low
error byte to L virtual +0x24. With R+0x34==1 and non-null R+0x68, it checks
L+0x28 against the collection count at that object's +8 before computing a
28-byte record offset. Record handling calls unbounded `0x0e28961c` and
`0x0e010b5e`; a returned -1 reports 0x82. This is an observed index comparison,
not proof that the externally populated collection or multiplication is safe
for arbitrary inputs. Other branches forward the original error byte.

## Inline `data:` uses the same handoff

**`0x0e28a18e(Mgr,L)`** converts R+0x24, checks `data:`, finds a comma,
slices the media description from index 5 to the comma, and takes the remainder
as payload text. Without a comma it clears the payload. A `;base64` match
removes seven characters from the media description and sets a flag. It then
calls `0x0e1a66d4` on the payload; that helper's transformation is unbounded
here. The flagged nonempty payload calls `0x0e1b390e` with pointer, length and
an output structure. The marker and call suggest base64 decoding; correctness
and malformed-input behavior have not been tested.

An empty media description becomes `text/plain;charset=US-ASCII`. A separate
predicate `0x0e1a7d9e` can select `application/octet-stream` and an error gate;
its complete validity rules are unknown. The function constructs
`content-type : ` plus the chosen description, converts it to a pointer/length
span, and calls the line parser with status 200. A second call passes CR/LF
and length 2. **These are synthetic headers, not the resource payload.**

After releasing its temporary L lifetime reference, it uses the saved L+0x24
byte to gate delivery: the predicate branch invokes error callback 0x7a;
otherwise it calls the data callback with either the output structure's
pointer/length or a converted text span, and final flag 1. These argument
connections come from the stack stores around `0x0e28a41c`, `0x0e28a45e` and
`0x0e28a4a8`, which are partly absent from inferred pseudocode signatures.

## Reproduce and remaining boundary

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with `ProbeShpAppAcquisitionCallbacks.java` / `.class`, an absent absolute JSON
path and `-noanalysis -readOnly`. Final local report/console use
`out/rea_shpapp/acquisition_callbacks_retained.*`; independent listing and
verification use `acquisition_callbacks.objdump.txt` and
`acquisition_callbacks.verification.json`. The source embeds only analyst
ranges, short literals and expected words; full pseudocode stays in `out/`.

The [lower-acquisition follow-up](shpapp_acquisition_backend.md) bounds
`0x0e02fbb2` and proves all 12 callback pointers are copied into a registered
entity. Next: the entity dispatch/consumption behind `0x0e024184`,
`0x0e02a500` and `0x0e009a18`. External callback timing, parameter ownership,
actual byte acquisition and transport remain unknown.
FactoryFs member access, widget installation, script execution, host events,
menus, orientation, RBM mode 2, global resource IDs and Rsrc2 remain unresolved.
Cellular, AMSS, RF, SIM and baseband paths remain excluded.
