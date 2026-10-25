# Script tag and attribute registry linkage

The document-owned object from the [input report](shpapp_script_inputs.md) is
constructed with the initialized `script` tag in the XHTML namespace. Its
interface exposes `src`, `charset`, `type` and `language` at distinct slots.
This resolves the name registry boundary and corrects an earlier interpretation:
helper `0x0e1f9456` prepares a charset value, while the request's incoming name
is a separate argument. Actual package-member loading and execution remain unknown.

## Input and verification

Embedded ShpApp ELF SHA-256:
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Parent identity and address conversion are in the
[listener report](shpapp_widget_listener.md). Original hash-guarded probe
`ProbeShpAppScriptRegistry.java` selects eight functions with explicit code
islands, excluding inline strings and literal pools. All decompiled; all
4,491 instruction addresses matched independent bounded ARM objdump 2.45.50
listings. Sixteen words, six ASCII literals, the physical ELF hash and Ghidra
12.1 read-only project discard were verified. These are ordinary local
observations, not REA Evidence or target execution. Analyst labels and inferred
signatures do not override assembly argument flow.

## Initialization writes the referenced slots

Initializer `0x0e12cb00` spans disjoint code islands ending at `0x0e13006c`.
It checks a first-use flag and uses tag base
`T=read32(0x0e12cdf8)=0x0e5fb280`. The ASCII name constructor
`0x0e32a646` creates a temporary name representation. Factory `0x0e1f66de`
uses the +4 words of prefix, local-name and namespace arguments as an intern
key, then stores the resulting intern pointer through its destination.

The namespace input at `0x0e12cdfc` is `http://www.w3.org/1999/xhtml`.
The `script` ASCII input at `0x0e12d040` is saved in the initializer's stack
array, reloaded at `0x0e12d984`, and constructed at `0x0e12d988`. Factory call
`0x0e12d994` writes slot `T+0x148=0x0e5fb3c8`. This is precisely the registry
reference passed by owner constructor `0x0e21b750` through literal
`read32(0x0e21bb48)`. The slot's offset is not a resource ID.

The attribute sequence uses
`B=read32(0x0e12e974)=0x0e5fb428`. Complete initialization traces each input
temporary into the following qualified-name factory calls:

| Name | ASCII input | Destination | Factory call |
| --- | --- | --- | --- |
| `charset` | `0x0e12dea0` | `B+0x94 = 0x0e5fb4bc` | `0x0e12ec56` |
| `language` | `0x0e12e1f0` | `B+0x164 = 0x0e5fb58c` | `0x0e12f21c` |
| `src` | `0x0e12e8a4` | `B+0x304 = 0x0e5fb72c` | `0x0e12fd92` |
| `type` | `0x0e12e080` | `B+0x338 = 0x0e5fb760` | `0x0e12ff02` |

For `type`, literal word `read32(0x0e12e904)=0x0e12e080` provides the ASCII
pointer indirectly. The other three inputs use direct address formation.
The selected destinations and consumer literals match; they are not inferred
from neighboring strings. The registry destinations are uninitialized globals:
reading those virtual addresses as physical ELF bytes would be incorrect.

## Owner interface selects four different attributes

Owner O's interface is `I=O+0x44`, with table
`read32(0x0e21bb50)+0x40=0x0e5aa358`. Each adapter below subtracts `0x44` from
its incoming interface argument, then enters a getter. The getter calls
`0x0e1ea9d0(O,attribute_ref)` and copies the returned value at +4 through
`0x0e335922`.

| I slot | Stored Thumb pointer | Adapter → getter | Attribute reference |
| --- | --- | --- | --- |
| `+0x0c` | `0x0e21be67` | `0x0e21be66 → 0x0e21be50` | `src`, via `0x0e21bf10` |
| `+0x10` | `0x0e21be81` | `0x0e21be80 → 0x0e21be6a` | `charset`, via `0x0e21bf08` |
| `+0x14` | `0x0e21be9b` | `0x0e21be9a → 0x0e21be84` | `type`, via `0x0e21bf14` |
| `+0x18` | `0x0e21beb5` | `0x0e21beb4 → 0x0e21be9e` | `language`, via `0x0e21bf18` |

The existing type/language gate `0x0e1f936e` uses +0x14/+0x18. The helper
`0x0e1f9456` instead uses +0x10 at `0x0e1f9460`. Its result can fall back to
a frame-associated value through `0x0e145680` and `0x0e166d20`. The previous
probe label `probe_script_request_name` is corrected to
`probe_script_request_charset`. The request starter preserves its incoming
name independently at stack+8 and passes it as r1 to `0x0e15edcc`, with this
charset temporary as r2 and helper X as r3. Neither the +0x10 getter nor its
fallback establishes the request URL.

## Reproduce and remaining boundary

Use the [precompiled-class recipe](shpapp_widget_listener.md#reproduce-and-remaining-boundary)
with `ProbeShpAppScriptRegistry.java` / `.class`, an absent absolute JSON path,
and `-noanalysis -readOnly`. Final report/console are
`out/rea_shpapp/script_registry_verified.*`; independent listing and checks are
`out/rea_shpapp/script_registry.objdump.txt` and
`out/rea_shpapp/script_registry.verification.json`. Full output stays local.

The [request follow-up](shpapp_script_request.md) connects the src getter and
attribute update to the resource loader. Next: trace resource construction and
scheduling. This probe does not establish a parser invoking the script
constructor for any specific package, installation, actual script/callback
execution or resource transport. Host event values, native-menu ownership,
physical orientation, RBM mode 2, global resource IDs and Rsrc2 remain unknown.
Cellular/baseband paths remain excluded.
