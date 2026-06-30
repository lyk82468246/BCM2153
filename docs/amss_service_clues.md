# AMSS service and debug clues

This page tracks short, public-safe string evidence for possible AMSS service,
AT/USB, CAPI2, filesystem, calibration, trace, and debug interfaces. It does not
claim that any interface is externally reachable yet; each item still needs code
cross-reference work in Ghidra.

Generated locally with:

```sh
python3 tools/amss_service_survey.py \
  /home/joe/thing/amss.bin \
  --out out/amss_service_survey
```

The report assumes the current AMSS base hypothesis `0x80300000`, so VMA equals
file offset plus `0x80300000`.

## Survey summary

`tools/amss_service_survey.py` scanned 71,819 printable strings and found 485
categorized hits.

| Category | Hits | Meaning |
| --- | ---: | --- |
| `memory_debug` | 5 | ARM memory read/write format/help strings |
| `usb_at_test` | 37 | USB AT test command handler strings |
| `usb_acm` | 46 | USB CDC/ACM adapter strings |
| `capi2_at_ipc` | 8 | CAPI2 AT/IPC queues and entry points |
| `capi2_ffs` | 5 | CAPI2 filesystem-control request/response strings |
| `download_diag` | 25 | download-mode and DIAG-like request strings |
| `trace_logging` | 213 | trace/logging subsystem strings, mostly not direct service entry points |
| `calibration_nv` | 148 | calibration, sysparm, NVRAM, and RF/PMU ACK strings |

## Highest-value clues

### ARM memory debug strings

| Offset | VMA | Text |
| ---: | ---: | --- |
| `0x18840` | `0x80318840` | `ARM memory *(int32 *)0x%0lx = 0x%0lx` |
| `0x18868` | `0x80318868` | `ARM memory *(char *)0x%0lx = 0x%0x` |
| `0x18890` | `0x80318890` | `ARM memory *(int16 *)0x%0lx = 0x%0x` |
| `0x188b8` | `0x803188b8` | `First parameter should be 1, 2 or 3, then address` |
| `0x18928` | `0x80318928` | `First parameter should be 1, 2 or 3, then address, value` |

Interpretation: these strongly suggest an internal command handler for typed ARM
memory access. The missing piece is the command name and ingress path. Trace the
string references in Ghidra before assuming it is exposed over AT, USB, UART, or
calibration mode.

### USB AT test and USB ACM

The USB test cluster includes `ATCmd_MUSBTST_Handler` / `ATCmd_MUSBTEST_Handler`
strings near offsets `0x2310` through `0x2af8`. Selected visible cases include
USB VID/PID get/set handling, a calibration-mode test case, and switching ATC to
UART A.

The USB ACM layer has `JusbAdapter_acm_*` strings around offsets `0x155e4` and
later, including read/write, DTR/DCD, open-device, and calibration-waiting
messages. This is likely one path that carries AT or diagnostic data over USB.

### CAPI2 AT and filesystem control

CAPI2 AT/IPC strings include:

| Offset | VMA | Text |
| ---: | ---: | --- |
| `0x597c` | `0x8030597c` | `CAPI2AT_Q` |
| `0x5a54` | `0x80305a54` | `CP2ATC_Q` |
| `0xb4a4` | `0x8030b4a4` | `CAPI2_SYS_ClientInit atChannel=%d` |
| `0xbde0` | `0x8030bde0` | `CAPI2_atc_entry: MSG_ATC_DATA` |

Filesystem-control strings include:

| Offset | VMA | Text |
| ---: | ---: | --- |
| `0x11ca4` | `0x80311ca4` | `CAPI2_FFS_Control enter cmd=%d, address=0x%x, offset=%d` |
| `0x11ce0` | `0x80311ce0` | `CAPI2_FFS_Control ack FAIL %d` |
| `0x11d00` | `0x80311d00` | `CAPI2_FFS_Control exit` |
| `0x555f4` | `0x803555f4` | `CAPI2_FFS_Control_RSP_Rsp_t` |
| `0x55658` | `0x80355658` | `CAPI2_FFS_Control_Req_t` |

Interpretation: CAPI2 appears to bridge AT/client-side messages and CP services.
`CAPI2_FFS_Control` may be relevant to filesystem or flash-file operations, but
its command IDs and caller path still need code tracing.

### Download, DIAG, trace, and calibration

`download_diag` contains strings such as `Please download script file`,
`mode :0=normal,1=cal,2=download`, and several `CAPI2_DIAG_*` request/response
type names. `trace_logging` is much larger and mostly represents general logging
infrastructure such as `src\sdltrace.c`, so it should not be confused with a
confirmed diagnostic ingress path.

Calibration/NV strings are dense around the same early AMSS region as the memory
and USB clues. Visible ACK strings include battery voltage calibration, Bluetooth
address, checksum write, TX dynamic calibration, calibration date, and flash-like
ACK messages. Treat these as high-risk device-specific paths until their storage
and access control are understood.

## AT Command Dispatch Table

`tools/amss_at_table_probe.py` scans for 24-byte records whose command-name
field points at visible AT command strings. It writes only metadata to ignored
`out/` storage:

```sh
python3 tools/amss_at_table_probe.py \
  /home/joe/thing/amss.bin \
  --out out/amss_at_table_probe
```

The current run found 232 candidate AT command records. The command-name table
uses the same AMSS base hypothesis, so `*MUSBTST` is stored at file offset
`0x534f39`, VMA `0x80834f39`; its dispatch record is at file offset
`0x43e9b4`. The handler pointer is odd, which marks a Thumb entry; the cleared
entry address is `0x803023ac`.

High-value test/debug records from the current probe:

| Command | Record offset | Flags | Handler | Mode | Bucket |
| --- | ---: | ---: | ---: | --- | --- |
| `*MTEST` | `0x43e42c` | `0x30101` | `0x803d897c` | Thumb | main AT handler region |
| `*APMTEST` | `0x43e444` | `0x230900` | `0x803d897c` | Thumb | main AT handler region |
| `*MUSBTST` | `0x43e9b4` | `0x30100` | `0x803023ac` | Thumb | USB AT test handler region |
| `*MTESTUSB` | `0x43e9cc` | `0x30401` | `0x803021c4` | Thumb | USB AT test handler region |
| `*MAUDLOG` | `0x43e9fc` | `0x230600` | `0x803020a0` | Thumb | USB AT test handler region |
| `*MDSPTST` | `0x43e9e4` | `0x30501` | `0x803d53e8` | Thumb | main AT handler region |
| `*MADCTST` | `0x43ea14` | `0x30600` | `0x803d47fc` | Thumb | main AT handler region |
| `+TEMPTEST` | `0x43ea74` | `0x230303` | `0x803d9b5c` | Thumb | main AT handler region |

This upgrades the USB AT clue from "nearby strings exist" to “visible AT
commands dispatch into concrete Thumb handlers.” The next Ghidra work should set
Thumb context at `0x803021c4`, `0x803023ac`, and `0x803020a0`, then identify
case dispatch and parameter parsing.

## Reference Probes

Two complementary probes now test whether the highest-value strings have direct
references:

```sh
python3 tools/amss_string_xref_probe.py \
  /home/joe/thing/amss.bin \
  --out out/amss_string_xref_probe

/opt/ghidra_12.1_PUBLIC/support/analyzeHeadless \
  out/ghidra/projects BCM2153 \
  -process amss.bin \
  -noanalysis \
  -scriptPath tools/ghidra_scripts \
  -postScript FindAmssServiceStringRefs.java \
    /home/joe/BCM2153/out/amss_service_refs/ghidra_string_refs.md
```

The raw xref probe searches little-endian 32-bit values for several candidate
bases (`0x0`, `0x80000000`, `0x80300000`, `0x80400000`). It found no convincing
direct references to the memory-debug or USB AT strings; the few raw-offset hits
for `0x11d00` are likely too weak on their own.

The Ghidra reference probe is more useful. In the current `amss.bin` project it
reports:

| Label | Target | Refs | First ref |
| --- | ---: | ---: | --- |
| `CAPI2AT_Q` | `0x8030597c` | 1 | `0x803058fc` in `FUN_80305888` |
| `CP2ATC_Q` | `0x80305a54` | 1 | `0x803059fa` in `FUN_803059a4` |
| `CAPI2_atc_entry` | `0x8030bde0` | 1 | `0x8030bd98` |
| `CAPI2_FFS_Control_enter` | `0x80311ca4` | 1 | `0x80311c48` in `FUN_80311c34` |
| `CAPI2_FFS_Control_fail` | `0x80311ce0` | 1 | `0x80311c8c` in `FUN_80311c34` |
| `CAPI2_FFS_Control_exit` | `0x80311d00` | 1 | `0x80311c96` in `FUN_80311c34` |

It still reports zero refs for the selected ARM memory-debug strings and the USB
AT test strings. Treat this as a real negative result for the current Ghidra
analysis state, not proof the strings are unreachable. The likely next causes to
check are Thumb regions not yet disassembled, logging/string-table indirection,
or handler tables that store offsets/IDs rather than absolute string pointers.

## Working model

The most promising interaction chain to trace is:

```text
USB ACM / UART AT transport -> AT command handler -> CAPI2 AT/IPC -> CP service
```

The memory access strings may sit inside a calibration/test command family rather
than a normal user-facing AT command. The next reverse-engineering step is to use
Ghidra references from the strings at `0x80318840`-`0x80318928` and from
`ATCmd_MUSBTST_Handler` strings to identify the dispatch table, command name,
and parameter parser.
