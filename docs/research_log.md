# Research log

## 2026-10-23 non-cellular REA continuation

Deferred cellular protocols, SIM/call/SMS, RF and baseband DSP work. Verified
all 15 documented firmware sample sizes and SHA-256 digests against the private
sample set, and reused the existing ShpApp Ghidra project.

REA CLI successfully detected `/opt/ghidra_12.1_PUBLIC` through its invocation
environment. ShpApp whole-ELF analysis timed out under two different profiles;
a new read-only `ProbeShpAppHostAbi.java` instead completed six bounded Thumb
decompilations, corroborated with objdump. Findings include a returned Thumb
dispatcher, `0/1` lifecycle candidates, a 20-slot outgoing method table, and
incoming host-interface offsets. See `docs/shpapp_host_abi.md`; these ordinary
tool observations are not labelled as REA Evidence.

For bcmboot, an approved REA run outside the sandbox resolved the Unix-socket
restriction. An explicit function seed at `0x28000030` produced Evidence
`ev_d0a27ed64562ec96678d620540261f8b393d8792dd70ef06ee2190ed3b031c5c`
and a local snapshot. The main path copies NAND page-plus-extra-area data,
checks the first RAM header, advances by page size, uses RAM `+0x24` as an end
criterion, and branches to `0x08400000`. No explicit software decoder was
identified within that bounded loop; the standalone boot2/package relationship
remains open. See `docs/bcmboot_analysis.md`.

Public research added a dated reference to `raulmrio28-git/ImrcUnpacker` at
commit `de8a85c342b431b7d18778c8c31e28fb8d21169e`. Its Quram IMRC header model
matches the local Rsrc header through the block count and distance bits.
`tools/imrc_public_compare.py` confirms a `0x20` block-table start, `0x21b50`
data start, 17,253 plausible records and a 1,883-byte tail containing the
known TkTool marker; the final declared record is malformed against the file
length. This is a format hypothesis with strong external corroboration, not a
completed resource decompression.

## 2026-06-27 initial state

The working sample directory is `/home/joe/thing` in WSL. It contains a Samsung
GT-B5310/B5310U-style firmware package with boot, modem, app, resource, DSP,
filesystem, parameter, and NVRAM-like components.

Observed private sample components:

- `bcmboot.img`
- `boot2.img`
- `amss.bin`
- `apps_compressed.bin`
- `drom_dsp.img`
- `patch_dsp.img`
- `FactoryFs_B5310_China.ffs`
- `PFS_B5310_Open_China_Common.pfs`
- `Rsrc_B5310_China.rc1`
- `Rsrc2_B5310U(Low).rc2`
- `Rsrc2_B5310U(Mid).rc2`
- `ShpApp.app`
- `sysparm_dep.img`
- `sysparm_ind.img`
- `NVRAM6.bin`

Important early observations:

- `amss.bin` begins with an ARM little-endian exception vector table.
- `amss.bin` contains BCM2153, Hedge, Nucleus PLUS, CAPI2, RF calibration, and
  Samsung model/version strings.
- `bcmboot.img` contains NAND boot strings and transitions to `boot2.img` or
  download mode on failure.
- `boot2.img` and the beginning of `apps_compressed.bin` look high-entropy and
  need format/compression/encryption checks before static loading.

Near-term milestones:

1. Generate a reproducible firmware survey report.
2. Infer image load addresses and boot-chain handoff points.
3. Create Ghidra import notes for `bcmboot.img` and `amss.bin`.
4. Identify UART/download-mode memory read/write or RAM execution primitives.
5. Build a RAM-only hello-world payload path before considering flash changes.

## 2026-06-27 repository setup

Created public-safe project scaffolding in `/home/joe/BCM2153`. The repository
contains scripts and manually filtered notes only; raw firmware and generated
local reports remain ignored.

Added the first durable fact store, boot-chain hypothesis page, and initial
survey summary.

## 2026-06-27 Ghidra bootstrap

Added a reproducible Ghidra headless import path for `amss.bin` and
`bcmboot.img`.

Validated imports:

- `amss.bin`: raw ARM little-endian, base `0x80300000`, file offset `0x0`.
- `bcmboot.img`: raw ARM little-endian, base `0x28000000`, file offset `0x40`.

Installed WSL helper packages `bubblewrap` and `binutils-arm-none-eabi` so the
Codex sandbox and quick ARM objdump checks work directly inside WSL.

## 2026-06-28 TkTool trailer survey

Added `tools/tktool_tail_survey.py` to locate short Samsung/TkTool trailer
markers without copying firmware bytes.

High-confidence observation: `bcmboot.img`, `boot2.img`, `amss.bin`, and
`apps_compressed.bin` all have a final `cd ab cd ab` marker exactly 1024 bytes
before EOF. This makes the final KiB a likely packaging/tooling metadata block.

`boot2.img` also has a visible `MID_*` module-name table before its final
trailer, starting around `0x0004c000`.

## 2026-06-28 architecture pass

Added a first architecture map covering the boot/packaging layer, Nucleus modem
stack, Samsung SHP/native application layer, IMRC resources, FAT16 FactoryFs,
and parameter/calibration images.

Important new observations:

- `FactoryFs_B5310_China.ffs` is FAT16 and contains `Exe`, `Media`, `Security`,
  `Settings`, and `SystemFS` root directories.
- `Exe/Java` contains preinstalled J2ME `.jad` / `.jar` applications; `Exe/Mocha`
  is also present.
- `ShpApp.app` contains an embedded ARM ELF at file offset `0x192e` and many
  Samsung SHP/Web/widget-related source-path strings.
- `Rsrc_B5310_China.rc1` starts with `IMRC` and contains XML, PNG, zlib, bitmap,
  and other UI/media resources.

## 2026-06-28 ShpApp ELF pass

Added `tools/shpapp_elf_survey.py` and `docs/shpapp_analysis.md`.

Confirmed that `ShpApp.app` is a `FimBIN` container with an embedded ARM ELF at
offset `0x192e`. The ELF entry is `0x0e00ad0c`, the LOAD segment starts at VMA
`0x0e000034`, and sections use ARM toolchain-style names `ER_RO`, `ER_RW`, and
`ZI`.

## 2026-06-28 resource layer pass

Added `tools/resource_magic_survey.py` and `docs/resource_layer.md`.

`Rsrc_B5310_China.rc1` is confirmed as a dense IMRC resource bank with PNG,
JPEG/JFIF, XML/BWFXML, ZIP, SWF, and zlib-like resources. `ShpApp.app` also
contains a small embedded resource set in addition to the native ELF. FactoryFs
shows many ZIP/JAR/widget-like resources, consistent with FAT16-hosted Java and
widget packages.

## 2026-06-28 IMRC probe pass

Added `tools/imrc_probe.py` to test resource-bank structure without extracting
assets.

New model: `Rsrc_B5310_China.rc1` starts with an `IMRC` header whose declared
`0x1000` header/table area is not a direct absolute offset/length table. Strict
resource span parsing shows that magic scans overcount real resource starts:
115/137 PNG hits currently parse as complete PNG files, while SWF hits are also
mixed between parseable and incidental matches.

`Rsrc2_B5310U(Low).rc2` and `Rsrc2_B5310U(Mid).rc2` are not IMRC files. They are
near-identical `CHN`-marked profile banks with a profile word difference at
`0x08` and a short differing tail region.

## 2026-06-28 ShpApp Ghidra import pass

Added `tools/shpapp_ghidra_import.sh` for a reproducible local-only import of
the embedded ELF inside `ShpApp.app`. The script extracts from file offset
`0x192e` into ignored `out/` storage and imports with Ghidra's ELF loader.

A full automatic-analysis attempt was interrupted after several minutes due to
slow mixed code/resource analysis and a decompiler warning. The workflow now
defaults to `-noanalysis`; manual or targeted analysis should start from the
Thumb entry region around `0x0e00ad0c`.

## 2026-06-28 ShpApp entry probe pass

Added `tools/shpapp_entry_probe.py` for metadata-only entry-region analysis.
The probe maps the ShpApp entry `0x0e00ad0c` to container offset `0xc63a`,
confirms the entry should be treated as Thumb, and records that the first block
stores the incoming context in a ZI global around `0x0e5e8c0c` before calling
through host-provided function pointers.

## 2026-06-28 FactoryFs survey pass

Added `tools/factoryfs_survey.py` and `docs/factoryfs_analysis.md` for a
metadata-only FAT16 filesystem map. The FactoryFs image has 608 visible entries,
with `SystemFS` as the dominant tree, 10 preinstalled `.jad`/`.jar` J2ME pairs,
3 widget `.wgt` packages, certificate-heavy `Security`, and hardware-support
files under `SystemFS/Driver`.

## 2026-06-28 AMSS service clue pass

Added `tools/amss_service_survey.py` and `docs/amss_service_clues.md` for a
metadata-only survey of AMSS AT/USB/CAPI2/debug strings. Highest-value clues are
ARM memory access format/help strings near `0x18840`-`0x18928`, USB AT test
handler strings near `0x2310`-`0x2af8`, USB ACM transport strings,
`CAPI2AT_Q`/`CP2ATC_Q`, and `CAPI2_FFS_Control` request/response names.

## 2026-06-30 AMSS xref probe pass

Added `tools/amss_string_xref_probe.py` and
`tools/ghidra_scripts/FindAmssServiceStringRefs.java`. Raw multi-base 32-bit
xref probing found no convincing direct references for the selected memory-debug
or USB AT strings. Ghidra's reference manager did find CAPI2 references:
`CAPI2AT_Q` from `FUN_80305888`, `CP2ATC_Q` from `FUN_803059a4`, and all three
`CAPI2_FFS_Control` strings from `FUN_80311c34`. The memory-debug and USB AT
strings still need Thumb/dispatch-table/string-table tracing.
## 2026-06-30 AMSS AT dispatch table probe

Added `tools/amss_at_table_probe.py` to scan 24-byte AT command dispatch
records. The corrected scan found 232 candidate records. Important results:
`*MUSBTST` dispatches through record `0x43e9b4` to Thumb handler
`0x803023ac`, `*MTESTUSB` through record `0x43e9cc` to `0x803021c4`, and
`*MAUDLOG` through record `0x43e9fc` to `0x803020a0`. This confirms the USB AT
test strings are reachable from visible AT command names, while the ARM memory
debug strings still need a separate command or case-level trace.

## 2026-10-24 bounded IMRC decode and tail correction

Scope: `Rsrc_B5310_China.rc1` only. Cellular/AMSS/RF/SIM/baseband analysis was
excluded. Used the `reverse-engineer-anything` workflow for evidence boundaries;
all new format conclusions below come from ordinary local Python/C tools.
REA firmware inspection first hit an approval-review timeout; the later session
query succeeded and confirmed no open target and no configured firmware
provider. No REA signature result is claimed, no configuration was changed,
and no flashing utility was executed.

Sample identity: 48,287,158 bytes; SHA-256
`425f464bbdaae55fb685bd3e2636b76473cd787dde8a6dadd66f03e8c521e1e3`.
Tools: CPython 3.14.4; GCC/cc 15.2.0; public ImrcUnpacker commit
`de8a85c342b431b7d18778c8c31e28fb8d21169e`.

The plan's starting `0x20` block table assumption was incorrect. Comparing
`QuramDataDecompInit` with the actual bytes establishes `0x1c`. Under the old
model, 17,253 records end at `0x2e0c65b`; the supposed final `(0x1ea,
0x76efaff5)` pair straddles the actual table/data boundary. Under the corrected
model, all 17,254 records fit; the first 17,253 end at `0x2e0c6d8` and the last
ends at `0x2e0c9b6`, exactly at the final KiB's `cd ab cd ab` marker. Both
interpretations remain in the metadata report so the former observation is
reproducible rather than silently discarded.

Added `tools/imrc_bounded_decode.py` and corrected
`tools/imrc_public_compare.py`. The decoder selects blocks directly, verifies
all table ranges first, bounds all stream accesses/distances/output sizes, and
writes structured errors. Supported version is deliberately limited to
`0x02000400`; other header variants remain untested. An early exploratory
implementation decoded a prefix through block 17252 in memory; that temporary
buffer was discarded. The final tool decodes only selected blocks, with an
8 MiB selection limit and no allocation of the declared 70 MB bank.

Reproduction commands (from repository root):

```sh
python3 tools/imrc_public_compare.py \
  /home/joe/thing/Rsrc_B5310_China.rc1 \
  --out out/imrc_bounded_decode/table_models.json

python3 tools/imrc_bounded_decode.py \
  /home/joe/thing/Rsrc_B5310_China.rc1 \
  --blocks 0,1,2,100,1000,10000,17252,17253,4198:4203,5097:5099,13001:13005,12951 \
  --scan-resources --boundary tktool \
  --extract-dir out/imrc_bounded_decode/blocks \
  --out out/imrc_bounded_decode/report.json

# Same selection with EOF still available as IMRC input.
python3 tools/imrc_bounded_decode.py \
  /home/joe/thing/Rsrc_B5310_China.rc1 \
  --blocks 0,1,2,100,1000,10000,17252,17253,4198:4203,5097:5099,13001:13005,12951 \
  --scan-resources --boundary eof \
  --out out/imrc_bounded_decode/eof_report.json

IMRC_SAMPLE=/home/joe/thing/Rsrc_B5310_China.rc1 \
  python3 -m unittest discover -s tests -v
# Synthetic regressions can also run without IMRC_SAMPLE.
```

Results: 20 selected blocks / 80,828 output bytes succeeded; both boundary
models have identical per-block output hashes. The final block produces 3,004
bytes and consumes all 490 data bytes, ending before TkTool metadata. Ten PNGs
passed length/CRC checks through IEND and were extracted only under ignored
`out/`. The first spans adjacent blocks, logical offset `0x1068d78`, length
996, SHA-256
`178085e5cc8cc651a51102bd52df565f3f9eba86779b2fae27f729feac03de45`.
Additional decoded features include XML/BWFXML `0x13e9ec6/0x13e9eee`, FWS
`0x3297de8`, and JFIF `0x32c9802`. These additional types have no validated
standalone extent yet. CWS's header size is an uncompressed length, so the
legacy magic probe's CWS span counts are not safe compressed boundaries.

Public comparison: five cached sources plus two missing headers were placed
only in `/tmp/imrc-public/`. All original Git blob hashes match the pinned
commit's tree. Fetching missing files worked through single-file requests;
batch fetches timed out in automatic approval review, so verified cached
snapshots supplied the remainder. Temporary LP64/type/macro/copy-helper
adaptations are detailed in [public_references.md](public_references.md).
The final comparison uses the unchanged core algorithm and a small original
harness retained locally in
`out/imrc_bounded_decode/public_compare_harness.c`:

```sh
cc -O1 -g -fsanitize=address \
  /tmp/imrc-public/compare.c /tmp/imrc-public/common/imrc_common.c \
  -o /tmp/imrc-public/compare
ASAN_OPTIONS=detect_leaks=0 timeout 15 /tmp/imrc-public/compare \
  /home/joe/thing/Rsrc_B5310_China.rc1 \
  0 1 2 100 1000 4200 4201 4202 10000 17252 17253
```

All eleven selected reference outputs match the local output byte-for-byte,
length and SHA-256. Initial temporary build attempts exposed upstream LP64 and
macro incompatibilities; those attempts are not counted as validated runs.
The public unchecked decoder was not run on deliberately malicious streams.
The local suite passed 22 tests (21 synthetic/CLI tests plus one optional
private sample test), including non-IMRC/truncated files, oversized fields,
record/table bounds, zero/out-of-window distances, command/data exhaustion,
output length mismatch, literal/XOR/LZ/mixed paths, selection budgets, PNG CRCs
and cross-block extraction, both tail boundaries, and input preservation.

Local evidence: `out/imrc_bounded_decode/{report,eof_report,table_models,
cross_check,public_source_identity,public_build_provenance}.json`, `tests.log`,
and selected block/PNG artifacts. Only original tools, tests and sanitized
notes enter the tracked change. No complete decompressed bank was saved.

Status: bounded compression and PNG-boundary verification complete. The tail
boundary is explained for this sample, but internal tail fields/checksum,
resource-ID/index mapping, complete resource export and Rsrc2 profile mapping
remain explicit unknowns. Partial block/resource success is not a complete
resource-library unpack.

## 2026-10-24 logical directory and RBM local-ID follow-up

Continued the resource-only scope after the user requested publishing and
further work. Ordinary local parsing establishes a directory tree in the
logical IMRC bank: a 64-byte root header, directory headers of three u32
parent/directory-count/file-count fields, 48-byte directory entries and 52-byte
file entries. Both entry types use 44-byte zero-padded names; file entries end
with offset/length. Parent links, exact metadata adjacency, payload bounds and
four-byte alignment corroborate the layout across 101 directories / 736 files.
The index ends at `0xad3c`; the first payload begins there, and file extents
end at the header's declared bank length. Only 11 initial blocks are needed
for index enumeration. `[0,0xad3c)` SHA-256:
`c30c58587eaf4c0dd6179dd1bc86632708ef247f6f10328ac9fb72d29f8d7c77`.

Added `tools/imrc_resource_index.py` with a bounded block LRU, strict names,
parent/cycle/extent checks, explicit selected-file structural validators and
optional RBM table/ID selection. Its CLI and layout are documented in
[imrc_resource_index.md](imrc_resource_index.md). New original tests supplement
the existing decoder suite: 35 total pass with the private sample enabled.
No numeric application ID is inferred from directory paths.

Indexed extraction now independently matches the earlier PNG carve:
`System/Media/Img/Java/checkbox_off.png`, entry `0xb50`, bank offset
`0x1068d78`, length 996, SHA-256
`178085e5cc8cc651a51102bd52df565f3f9eba86779b2fae27f729feac03de45`.
A complete named FWS file, bookmark XML and RIFF/WAV also pass structural
checks at their exact indexed ends. The earlier XML/BWFXML signature at
`0x13e9ec6` is a length-bounded 1,580-byte iXML chunk inside `alarm.wav`, with
root `BWFXML`; it is not a separate top-level file. The earlier JFIF feature
falls inside `Bluetooth.swf`; JPEG extent remains unknown.

The optional RBM survey checks all 139 files: header words `(0,0x100,count)`,
16-byte `(kind,local-ID,relative-offset,length)` records, first body at table
end, consecutive nonoverlapping bodies and exact indexed file end. All 11,539
local IDs are sequential within their files and agree with the first u32 in
each body. This recovers a path-plus-local-ID lookup, not global-ID composition
or pixel encoding. `KJava.rbm` IDs 0 and 8 were selected and exported as
6,704/9,584 encoded body bytes. Their SHA-256 values are respectively
`6898c833dc6363a20694d0a44ab235045d08ef4778d0b6bc8448c4b072ea368f`
and `39780ef4845b3064f8d0116e9450b8c6cf8375c0c07ce174b75d5fa6e4514a8f`.

Reproduction commands:

```sh
python3 tools/imrc_resource_index.py /home/joe/thing/Rsrc_B5310_China.rc1 \
  --survey-rbm \
  --verify System/Media/Img/Java/checkbox_off.png \
  --verify System/Rsrc/Flash/Bluetooth/Bluetooth.swf \
  --verify System/Settings/PreConnection/KoreaGumi/User/Br/bookmark.xml \
  --verify System/MediaSet/Sound/EffectTone/alarm.wav \
  --extract-dir out/imrc_resource_index/files \
  --out out/imrc_resource_index/index.json
python3 tools/imrc_resource_index.py /home/joe/thing/Rsrc_B5310_China.rc1 \
  --rbm-id System/Rsrc/Bmp/Black/KJava.rbm 0 \
  --rbm-id System/Rsrc/Bmp/Black/KJava.rbm 8 \
  --extract-dir out/imrc_resource_index/files \
  --out out/imrc_resource_index/rbm_selected.json
IMRC_SAMPLE=/home/joe/thing/Rsrc_B5310_China.rc1 \
  python3 -m unittest discover -s tests -v
```

The combined four-file/RBM survey addresses 1,445,576 bytes and decodes
15,917,056 block bytes through a bounded cache; it does not save a full bank.
Only requested verified files and requested RBM body bytes are exported under
ignored `out/`. Full reports: `out/imrc_resource_index/index.json`,
`rbm_selected.json`, `rbm_probe.json`, `shpapp_path_seeds.json` and `tests.log`.
Python/GCC/sample identities are unchanged from the preceding entry.

A bounded ShpApp ASCII/UTF-16LE search checked eight selected patterns. The
only `checkbox_off.png` substring belongs to the complete C string
`sfb_checkbox_off.png` at container `0x20076`. Exact indexed full paths and the
other selected basenames were absent in this search, and raw little-endian
pointer searches for the candidate string addresses produced no hits. No
resource consumer/caller or absence of one is established; no native target
was opened and no runtime behavior was observed. Next focus: the resource
loader/host API that selects an RBM file and local ID, then global-ID encoding
and one actual consumer. RBM pixel format remains a separate unknown.

Publishing encountered an infrastructure restriction: normal staging failed
because `.git/index.lock` is on a read-only mount; elevated staging attempts
hit automatic-approval timeouts. A separate checkout under writable `/tmp` is
used to prepare the reviewed source/docs/tests for publication. No Git history
is rewritten, and raw/generated assets remain excluded.

## 2026-10-24 Browser RBM selection and drawing path

Continued Q1/Q5 using only the existing ShpApp and resource-bank samples.
A bounded 37-string candidate report (`shpapp_resource_strings.json`) led to
`SFBrowserRsrc.rbm` at parent offset `0xa7d6`, mapped ELF VMA `0x0e008ea8`.
The resource inventory contains one exact basename match, a 30-record RBM.
Raw pointer search was negative, but objdump exposed six Thumb ADR references
with resource-selection arguments 20/21/22/23/24/28. Returns are saved and
four are passed to drawing calls. This demonstrates why a raw-pointer-only
negative search did not settle consumer attribution.

The new original `ProbeShpAppBrowserResources.java` uses the existing project
with `-noanalysis -readOnly`, exact ELF SHA-256 guard, and two analyst-selected
Thumb code islands. Ghidra 12.1 decoded 279 instructions and completed the
function decompilation, then discarded analysis changes. ARM objdump version
`2.45.50.20251209` independently corroborates the call sites. No native code
was executed; this report is ordinary Ghidra output, not REA Evidence. Known
full-ELF REA startup timeouts were not retried unchanged.

Initial Ghidra launch failed trying to write `java_home.save` in read-only home
configuration. Retrying with task-local `XDG_CONFIG_HOME` and `XDG_CACHE_HOME`
under `/tmp` succeeded without changing persistent configuration.

Reproduction commands and the concise argument/extent table are in
[shpapp_resource_consumer.md](shpapp_resource_consumer.md). Parent and derived
ELF digests remain those in [shpapp_host_abi.md](shpapp_host_abi.md); the IMRC
sample digest remains `425f464bbdaae55fb685bd3e2636b76473cd787dde8a6dadd66f03e8c521e1e3`.
Generated reports stay at `out/rea_shpapp/browser_resources.ghidra.json`,
its console/script logs and `out/imrc_resource_index/browser_selected.json`.
The six selected bodies passed indexed extent/body-ID checks; their SHA-256
values are in that local report. ID 20 is 1,508 bytes and hashes to
`74e1ce26539c09eb859c61cfcf9738f37d3010df359d6513fac4e99e54d7fe9a`.

Observed callback paths: context `+0x23c`, vtable `+0x18` for resource selection;
context `+0xe4`, vtable `+0x18c` for drawing. Returned-object `+8/+0xc` fields
participate in layout arithmetic; they are not asserted to be encoded-body
offsets. Matching filename/IDs supports the RBM link, while actual host path
resolution, theme selection, allocation contract and global IDs remain unknown.
Native menu ownership, Rsrc2 and TkTool internal fields remain unresolved.

## 2026-10-24 RBM body headers and mode-0/1 expansion

An independent body-header question was delegated as prescribed by the REA
skill's broader-investigation workflow; native analysis and publication stayed
with the primary agent. All 11,539 headers were inspected through bounded IMRC
reads. The 9,292 ordinary bodies have a 40-byte header whose payload count equals
the enclosing record length minus 40. The other 2,247 are exact 40-byte sentinel
placeholders. Width/height and encoding-selector observations are documented in
[rbm_body_encoding.md](rbm_body_encoding.md).

New original `tools/rbm_body_probe.py` expands raw 16-bit mode 0 and the mode-1
reserved-pattern repeat stream. All 33 raw and 296 mode-1 bodies match exact
dimension-derived sample counts and input extents, permitting only required
four-byte stream alignment in mode 1. Batch checks read 847,572 logical bytes
and decoded 913,408 block bytes. Generated reports are local:
`out/imrc_resource_index/rbm_pixel_probe/headers.json` and
`validated_modes_0_1.json`. No public implementation or vendor bytes were added.

The exact indexed MsgTypeIcon ID 0 body produces 225 samples/450 bytes with
SHA-256 `89cba3b5c3c3b21aa986829e29f5dc62bc54c416d1dac848050fe08b3763510d`.
Its explicit RGB565 candidate preview displays BCC letters; native color layout,
orientation and transparency remain unverified. Reproduction and optional
private-sample tests are in the linked note. Malformed synthetic tests cover
run/extent limits and placeholder sentinels. Modes 2/5, global IDs and the host
bitmap constructor remain unresolved.

## 2026-10-24 Reproducible bank-wide RBM header/sample checks

Added `tools/rbm_bank_survey.py` so the header and known-mode coverage can be
regenerated directly from the private IMRC sample. Default operation inspects
only indexed 40-byte headers; `--decode-modes 0,1` explicitly expands known
streams and stores metadata/hashes, with no byte or image export. Header parsing
accepts an explicit indexed body size without allocating that body's payload.
The existing logical-read, work and cache bounds remain in effect, supplemented
by a 16,384-record aggregate report limit. Unknown modes remain opaque.

The combined command completed with 139 files, 11,539 headers, 2,247
placeholders and 329 expanded bodies, agreeing with the earlier independent
surveys. Addressed reads: 1,630,276 bytes; block decode work: 25,579,520 bytes.
Report: `out/imrc_resource_index/rbm_pixel_probe/reproduced_bank.json`.
All 46 tests pass with `IMRC_SAMPLE` enabled, including opaque-mode preservation,
sentinel dimensions, retained failure path/ID and bank-wide real-sample counts.
Commands are in [rbm_body_encoding.md](rbm_body_encoding.md).

Publication of the preceding `e2de2b1` commit encountered a separate environment
block: normal SSH rejected system SSH configuration ownership; a sandboxed
read with clean SSH configuration failed DNS resolution. Two elevated push
attempts were rejected because automatic approval review did not finish before
its deadline. These are approval timeouts, not evidence that the commits are
unsafe. Remote publication has not been confirmed; prepared commits remain in
the writable temporary checkout recorded under ignored `out/`.

## 2026-10-25 Mode-2 ambiguity and bounded image cross-check

The preceding round's mode-2/16-bit corpus experiments fit a candidate command
extent in all 4,434 bodies and a simple length/distance model in 4,241; all
193 exceptions are ContactRsrcBmp records with additional command flags.
Those experiments did not establish a decoder. First-literal and hidden-seed
interpretations both satisfy count/distance checks but can produce different
pixels. All ordinary candidates begin with a literal, so a hidden seed cannot
be inferred merely from making their tail shorter.

Added original `tools/rbm_mode2_probe.py` and seven regression tests, including
a real indexed Br_Cd_Etc ID 0 case with two fitting, different candidate hashes,
a flagged Contact case, and a command extent crossing the 16-bit size boundary.
The tool never selects a model or exports pixels. All 53 tests pass with the
private sample enabled; log: `out/imrc_resource_index/tests_mode2_diagnostics.log`.
Reproduction, exact sample/candidate hashes and limits are documented in
[rbm_mode2_limits.md](rbm_mode2_limits.md). Stable mode-0/1 decoding is unchanged.

An independent comparison read all 183 indexed PNGs (886,468 bytes), checked
PNG chunk extents/CRCs, and used Pillow 12.1.1 to compare candidate RGB565/BGR565
variants with truncation/rounding, row reversal and transparent-key handling.
No match was found against the 4,241 hidden-seed hashes. Adding 49 BMPs whose
bfSize matched their indexed length also produced no match; the no-seed model
was checked on 109 ordinary bodies with matching raster dimensions. This is a
bounded negative search, not proof that no related image exists. Four other
BMPs were excluded for inconsistent bfSize/biSizeImage fields; their indexed
lengths are not thereby disproven. The first PNG comparison addressed 975,164
bytes/decoded 958,464 block bytes; the BMP and selected no-seed pass addressed
316,936 bytes/decoded 344,064 block bytes. No whole-bank output was retained.

Local experiments/reports: `rbm_pixel_probe/compare_pngs.py`,
`compare_no_seed.py`, `png_seed_comparison.json`, `raster_comparison.json`,
`bmp_extents.json`, `Br_Cd_Etc_0_ambiguity.json`, and
`ContactRsrcBmp117_unsupported.json`, all under `out/imrc_resource_index/`.
The exact IMRC digest remains unchanged. Tool versions: Python 3.14.4,
Pillow 12.1.1, Capstone 5.0.7. A bounded Thumb mask-pattern scan of ShpApp
yielded 24 windows without establishing an RBM decoder; the ordinary-tool
report `mode1_native_mask_candidates.json` is local, not REA Evidence.

Publication remains pending the earlier request for guidance after two automatic
approval timeouts. No further remote push was attempted in this round.
Next independent native question: the early ShpApp screenshot/bitmap wrapper
may establish host-created bitmap object layout. Mode-2 framing/pixel identity,
the indirect host decoder, Rsrc2 and application-wide IDs remain unknown.

## 2026-10-25 ShpApp screenshot descriptor and JPEG path

A focused follow-up expanded native evidence without repeating full ELF analysis.
The new read-only `ProbeShpAppScreenshot.java` selected Thumb islands
`0x0e00069a..0x0e000824` and `0x0e000924..0x0e000986`; Ghidra 12.1 completed
231 instructions and the decompilation. ARM objdump 2.45.50 independently
corroborates the range. Task-local XDG configuration/cache kept the run outside
read-only home configuration; project changes were discarded. The report remains
ordinary Ghidra evidence, not REA Evidence.

The routine calls context `+0xe4`, table `+0x170` to capture a bitmap-like object,
then reads returned fields `+8`, `+0xc`, `+0x24`, byte `+0x10`, `+0x14`, and
`+0x18`. It copies them into a nested host descriptor at offsets `+0x1c`, `+0x20`,
`+0x34`, byte `+0xd`, `+0x00`, and `+0x30`. The same `+8/+0xc` fields were used
in browser layout arithmetic; this independently supports a dimension-like role,
without identifying encoded RBM fields or the provider object type.

A second host call at context `+0x20c`, table `+0x14`, is supplied `(8, state,
&buffer, &length, 5)` and feeds a formatted `/User/Br_ScreenShot/` `%s%05d.jpg`
path. File create/write/close and cleanup branches are bounded and documented in
[shpapp_screenshot.md](shpapp_screenshot.md). The selected source string is
`Src\\SHP\\SFBalDebugShp.c`; quality-like value is 5. This ties the object fields
to a JPEG screenshot adapter, not to RBM mode-2 decoding.

Parent/ELF hashes remain unchanged. Local report:
`out/rea_shpapp/screenshot.ghidra.json`, with logs and
`out/rea_shpapp/screenshot_prefix.objdump.txt`. The mode-2 candidate remains
unresolved; the next native question is the implementation behind context
`+0x23c/+0x18` or `+0xe4/+0x18c` resource/bitmap callbacks.
