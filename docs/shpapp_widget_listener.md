# Widget listener wrapper and script-call boundary

The listener object created by the WidgetObject adapter has a concrete virtual
table: slot `+8` enters `0x0e280f08`. That function selects a callable
`handleEvent` property when available, otherwise tests the saved listener itself
for callability. It converts the native event and passes it through a script-call
bridge. This closes the static registration-to-call path; it does not demonstrate
that a packaged widget ran or received a hardware event.

## Identity and verification

The input is the same embedded ShpApp ELF documented in
[widget events](shpapp_widget_events.md): SHA-256
`44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
Parent offset is `VMA - 0x0e000000 + 0x192e` in initialized sections.
`ProbeShpAppWidgetListener.java` selects ten functions and checks the constructed
table address and `handleEvent` literal. All ten decompilations completed, with
812 instruction addresses matching independently selected ARM objdump ranges.
The physical ELF hash matches; Ghidra discarded read-only project changes.

These are ordinary Ghidra 12.1/objdump 2.45.50 observations, not REA Evidence.
The full native REA analysis previously timed out. Analyst names and boundaries,
inferred signatures, and the saved ARM loader language do not recover original
source types or establish the physical CPU model. No target code was executed.

## From adapter to constructed object

The [add-listener adapter](shpapp_widget_bindings.md) passes argument 1 to
`0x0e27de86`, with the factory's fifth argument set to `1`. This is separate
from the user's argument-2 flag stored in the event record.

The factory first calls `0x0e27de4e` to look for a cached wrapper. Both lookup
and allocation use the predicate `0x0e338e78` on the callback value. If lookup
misses and the predicate passes, it allocates 20 bytes and calls `0x0e281442`.
If the predicate fails, it returns a null listener. This predicate alone is not
a callability check; the invocation function tests callability later.

The constructor calls `0x0e331e0c`, then writes:

| Object offset | Observed initialization |
| --- | --- |
| `+0` | virtual table `0x0e5a1a24`, read through literal `0x0e2816e8` |
| `+4` | base constructor writes `1`, reference-count-like word |
| byte `+8` | base constructor writes `0`; lifecycle meaning unknown |
| byte `+9` | factory flag, `1` in the examined Widget adapter |
| `+0xc` | saved callback value through `0x0e342434` |
| `+0x10` | saved execution-context candidate through `0x0e342388` |

Nonzero saved callbacks are inserted through `0x0e36556c` into one of two
context-associated caches. Lookup chooses offsets `+0x150/+0x168` from a
context helper's result according to the factory flag. Cache ownership,
invalidation, and the types returned by other wrapper factories remain unknown.
In particular, a cache hit should not be described as a fresh construction.

The seven raw table words are:

| Slot | Raw Thumb pointer | Observed role |
| --- | --- | --- |
| `+0` | `0x0e2813c1` | destruction-path candidate; outside this probe |
| `+4` | `0x0e281413` | deleting-destruction candidate; outside this probe |
| `+8` | `0x0e280f09` | invocation function, entry `0x0e280f08` |
| `+0xc` | `0x0e2812e9` | outside this probe |
| `+0x10` | `0x0e33afe9` | outside this probe |
| `+0x14` | `0x0e281423` | returns object word `+0xc` |
| `+0x18` | `0x0e281427` | returns object word `+0x10` |

The event dispatcher previously resolved only the expression
`read32(read32(listener)+8)(listener,event,1)`. For this constructed wrapper,
the table and accessors now resolve that boundary without guessing its class name.

## Invocation branches

`[0x0e280f08,0x0e2812d8)` includes several early-return guards. It checks
global state, host/context methods, the saved callback/context, and a
context-associated object. One conditional host gate permits only the canonical
`unload` name when nonzero. The meanings and runtime values of these guards
remain unknown; registration does not guarantee callback execution.

After the guards, the routine obtains an execution-state candidate through
context slot `+0xb8`. It constructs the name `handleEvent` from ASCII at
`0x0e2812dc`, passes it with the saved callback to `0x0e3390f8`, then tests the
result through virtual slot `+0x10` with a local call-data output. A separate
bounded objdump trace of `0x0e3390f8` shows lookup through object slot `+0x64`
or a direct helper, and traversal through object metadata `+0x10` on a miss.
Full property/getter and prototype semantics were not recovered.

If the looked-up value supplies a nonzero call-kind result, it becomes the
callee and the saved listener is passed as its receiver. Otherwise the routine
tests the saved listener through its own slot `+0x10`; a zero result skips the
call. On this fallback branch, the dispatcher's third argument `1` selects a
receiver through context slot `+0x54`; the other branch derives a receiver from
event word `+0x1c`. The exact JavaScript `this` identity remains unresolved.

The native event is converted by `[0x0e280d92,0x0e280ef0)`. That function checks
an existing wrapper first, then selects conversion helpers through event virtual
predicates. It does not simply pass the native pointer as a JavaScript value.
The invocation routine appends the converted value to a local argument container
through `0x0e32239c`, saves and sets a context-associated current event, and calls
`0x0e0dad48`. Afterwards it restores the current event and runs result/exception
handling. The complete event wrapper ABI and exception effects remain unknown.

## Script-call bridge

At both call sites, register/stack flow establishes this six-argument shape:
`bridge(exec, callee, call_kind, &call_data, receiver, &arguments)`.
These labels describe observed roles, not recovered declarations.

`[0x0e0dad48,0x0e0daddc)` branches on raw `call_kind == 1`:

- The `1` branch calls `read32(call_data)(exec,callee,receiver,&arguments)`.
- The other branch calls `0x0e0e2102(callee,exec,receiver,&arguments)`.

The latter helper reads callee words `+0x18/+0x1c`, converts the receiver, and
calls `0x0e0fdf7c`. Its body is `[0x0e0e2102,0x0e0e215c)` plus the shared
epilogue `[0x0e0e20fa,0x0e0e20fe)`. The probe includes that explicit island;
it does not claim the intervening preceding function as part of the helper.
Untyped decompilation infers extra arguments at the final engine call, so the
register trace takes precedence. The engine's bytecode format and execution
semantics were not examined. The native-pointer branch and engine-helper branch
support a host/script distinction, without proving which a particular widget
callback takes at runtime.

## Reproduce and remaining boundary

The local Java source loader returned an OSGi bundle-load error, including on a
run outside the sandbox. An explicit `javac` check also found and allowed fixing
an incorrect initial `getBytes` overload. Verification used Ghidra's supported
precompiled-class route, without changing Ghidra configuration or installation:

```sh
python3 - <<'PY'
from pathlib import Path
import subprocess
classes = Path('out/ghidra_listener_scripts')
classes.mkdir(parents=True, exist_ok=True)
jars = sorted(Path('/opt/ghidra_12.1_PUBLIC/Ghidra').rglob('*.jar'))
subprocess.run(['javac', '-proc:none', '-cp', ':'.join(map(str, jars)),
                '-d', str(classes),
                'tools/ghidra_scripts/ProbeShpAppWidgetListener.java'], check=True)
PY
XDG_CONFIG_HOME=/tmp/bcm2153-ghidra-config \
XDG_CACHE_HOME=/tmp/bcm2153-ghidra-cache \
/opt/ghidra_12.1_PUBLIC/support/analyzeHeadless \
  "$PWD/out/ghidra_shpapp/projects" BCM2153_ShpApp \
  -process ShpApp_embedded.elf -noanalysis -readOnly \
  -scriptPath "$PWD/out/ghidra_listener_scripts" \
  -postScript ProbeShpAppWidgetListener.class \
  "$PWD/out/rea_shpapp/widget_listener.ghidra.json"
```

Choose an absent JSON destination on repeat runs. Full reports, compilation
outputs and failed-attempt logs remain ignored in `out/`; validated reports are
`widget_listener.ghidra.json`, `widget_listener_class_verified.console.log`,
`widget_listener.objdump.txt`, `.provenance.json`, and `.verification.json`.

The subsequent [event-source probe](shpapp_event_sources.md) identifies bounded
resize/focus/blur and beforeunload producers, with document-receiver identity and
upstream triggers still unresolved. Exact ASCII searches found neither `widgetmodechange` nor
`widgetendkey` in this ELF; that does not rule out host-supplied or dynamically
constructed names. Packaged callback execution, receiver/provider construction,
default-widget installation, RBM mode 2, global resource IDs and Rsrc2 remain
explicitly unresolved. Cellular/baseband paths remain outside scope.
