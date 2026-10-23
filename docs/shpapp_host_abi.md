# ShpApp host interface: first bounded pass

This pass follows the embedded ELF entry into its dispatcher and one table
registration path. Cellular services are outside its scope.

## Sources and method

- Parent: `ShpApp.app`, SHA-256
  `6f5a455adb73a22eef95f1c7f01ee4de6d4a2c812c394f43c791beb774dcbab1`.
- Derived ELF: exact parent bytes from offset `0x192e` to EOF, SHA-256
  `44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511`.
- Local Ghidra report: `out/rea_shpapp/host_abi.ghidra.json`.
- Local literal/identity report: `out/rea_shpapp/provenance.json`.
- Reproducible probe: `tools/ghidra_scripts/ProbeShpAppHostAbi.java`.

The six function ranges were selected from ARM objdump output, then explicitly
decoded as Thumb and decompiled in the existing Ghidra project with
`-noanalysis -readOnly`. All six decompilations completed. Edits to analysis
metadata were discarded on close. This is an ordinary Ghidra/Python result,
not REA Evidence. REA's two full-ELF attempts timed out before returning a
function dossier; their diagnostic JSON remains under `out/rea_shpapp/`.

The saved project's language is `ARM:LE:32:v8:default`. This loader choice does
not establish an ARMv8 CPU. Conclusions below use the bounded Thumb instructions
corroborated by objdump; unexamined code and callees remain unknown.

## Entry and returned dispatcher

| Address | Observed behavior |
| --- | --- |
| `0x0e00ad0c` | Saves incoming `r0` and `r1` at `0x0e5e8c0c` and `0x0e5e8c10` |
| `0x0e00ad16` | Calls internal code at `0x0e311eec`; its complete effects are not established |
| `0x0e00ad28` | Calls through the saved context's `+0x0c` interface and table slot `+0x24`, passing `0xb8`, a format string, and the original `r0` |
| `0x0e00ad2a` | Calls the getter at `0x0e00ad08`, which loads `0x0e00ac93` into `r0` |
| `0x0e00ad2e` | Pops saved registers and returns without overwriting `r0` |

Thus the instruction sequence returns `0x0e00ac93`, a Thumb pointer to the
wrapper at `0x0e00ac92`. This register-level observation is stronger than the
untyped decompiler's inferred `void` entry signature.

The format string at `0x0e3bbc00` starts with `Webkit's DllBaseInit called`
and names `pDllBaseEcomFactory`. That name supports a factory/interface-context
interpretation, but does not establish the object's full type or the loader's
identity.

## Dispatcher and lifecycle candidate

The wrapper at `0x0e00ac92` logs entry, calls `0x0e00ab4c`, logs exit, and
returns `1`. The call preserves the incoming first three registers and passes
the address of saved incoming `r3` in `r3`; a varargs-style adapter is a
candidate interpretation, not a recovered source signature.

The routine at `0x0e00ab4c` selects on its first argument:

| Value | Direct calls, in order | Result |
| --- | --- | --- |
| `0` | `0x0e0084e0`, `0x0e02f234`, `0x0e00ab8e` | Last call's register result is retained |
| `1` | `0x0e0084f6`, `0x0e02fb8c`, `0x0e00ab30` | Last call's register result is retained |
| Other | None in this function | Returns `0` |

Initialization/teardown are plausible roles for the two branches. The outer
wrapper returns `1` regardless of the inner result on these returning paths;
its return value therefore does not directly expose the inner status.

## Registration table

The `0` branch reaches `0x0e00ab8e`. It writes 20 contiguous function-pointer
slots at `B = 0x0e5e8bbc`, spanning `B+0x00` through `B+0x4c`, and writes
`B` at `B-0x0c = 0x0e5e8bb0`.

Selected slot values are:

| Table offset | Stored pointer | Bounded interpretation |
| --- | --- | --- |
| `+0x00` | `0x0e00ab83` | Thumb entry at `0x0e00ab82`; objdump shows an increment of a referenced object's word at `+8` |
| `+0x04` | `0x0e00ab77` | Thumb entry at `0x0e00ab76`; objdump shows a decrement of the same field |
| `+0x08` | `0x0e00ab4d` | Thumb pointer to the lifecycle candidate above |

The increment/decrement pattern suggests reference management. It does not yet
establish ownership rules, destruction behavior, or a standard interface ABI.

After populating the table, the routine calls the context's `+0x0c` interface,
table slot `+0x0c`, with these register arguments:

| Register | Value |
| --- | --- |
| `r0` | `0` |
| `r1` | `0x01000076` |
| `r2` | `0x0e5e8bb0` |
| `r3` | `0x00111104` |

This is consistent with registration of a module interface. Meanings of the two
numeric constants and the receiving function remain unresolved. The nearby
format string at `0x0e3bbbbc` names `__WebkitConstruct`.

## Incoming service-table sketch

Let `C` be the saved entry `r0`, `D` the saved entry `r1`, and
`T(C,s) = read32(read32(C+s))`. An indirect target is read from `T(C,s)+k`.
This describes observed pointer dereferences; it does not prove C++ classes.

| Context offset `s` | Table offset `k` | Observed use |
| --- | --- | --- |
| `0x0c` | `0x24` | Format-string calls with selector-like `0xb8`; logging is strongly suggested |
| `0x0c` | `0x0c` | Receives the constructed table and the numeric values above |
| `0x14` | `0xbc` | Adjacent routine `0x0e00ad30` passes `D` |
| `0x6c` | `0x20` | Same adjacent routine passes `D` |
| `0x14` | `0xc0` | Same adjacent routine performs another indirect call |

The adjacent routine returns `1`, but this pass has not established its caller
or a shutdown/unload role. In particular, `0x80+0x3c` is table offset `0xbc`;
recording only the final instruction's `0x3c` would lose part of the offset.

## Remaining questions

1. Which loader constructs `C`, and which functions fill these incoming tables?
2. What are the registration constants and all 20 outgoing methods?
3. Who invokes the returned dispatcher, with which event values and arguments?
4. What calls `0x0e00ad30`, and what do its three non-logging callbacks do?
5. Which module owns the native menu and main input loop? These WebKit paths
   establish a browser/runtime component, not ownership of the entire UI.
