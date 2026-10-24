# Resource layer notes

This page summarizes UI/media/resource container findings. Complete generated
reports and extracted assets stay local-only under `out/`.

## Rsrc_B5310_China.rc1: bounded decoding verified

The tested sample is `0x2e0cdb6` bytes, SHA-256
`425f464bbdaae55fb685bd3e2636b76473cd787dde8a6dadd66f03e8c521e1e3`.
The header declares version `0x02000400`, block size `0x1000`, extended/standard
byte-distance widths `12/6`, decompressed size `0x04365bbc` (70,671,292 bytes),
and `0x4366` (17,254) blocks. The local decoder supports this version only.

**Correction, 2026-10-24:** the versioned header is **28 bytes (`0x1c`)**, not
`0x20`. The public `QuramDataDecompInit` computes `2 * sizeof(DWORD) +
sizeof(tk15_IMRCHeader)` = `8 + 20`. The prior metadata script's extra four
bytes mixed each data length with the following command length and created an
apparent malformed last record. This was an analyst/parser error rather than
evidence of a damaged final IMRC record.

### Table and tail boundaries

All ranges below are half-open file offsets; indices are zero-based.

| Structure | File interval | Interpretation |
| --- | --- | --- |
| Header | `[0, 0x1c)` | Magic, version, five header fields |
| Block table | `[0x1c, 0x21b4c)` | 17,254 command/data length pairs |
| Packed blocks | `[0x21b4c, 0x2e0c9b6)` | Every record fits EOF and the TkTool boundary |
| Record 17252 | table `0x21b3c`; packed `[0x2e0c3a4, 0x2e0c6d8)` | Command/data `0x13f/0x1f5`; output 4,096 bytes |
| Record 17253 | table `0x21b44`; packed `[0x2e0c6d8, 0x2e0c9b6)` | Command/data `0xf4/0x1ea`; output 3,004 bytes |
| TkTool tail | `[0x2e0c9b6, 0x2e0cdb6)` | Exactly 1,024 bytes, begins `cd ab cd ab` |

The corrected first 17,253 records end at `0x2e0c6d8`. The old `0x20` model
still reproduces its former first-17,253 end `0x2e0c65b` and its putative last
pair `(0x1ea, 0x76efaff5)` at `0x21b48`. That second word actually comes from
packed data at `0x21b4c`, beyond the real table. The corrected first pairs are
`(373,827)`, `(242,655)`, `(315,694)`; their packed offsets are `0x21b4c`,
`0x21ffc`, `0x2237d`, and the third ends at `0x2276e`.

Both boundary models were exercised: treating EOF as available IMRC input and
excluding the tail at the TkTool marker. All table records fit both; the same
20 selected blocks decode identically under both. The last block consumes its
490 data bytes exactly and ends at the marker. Together with the declared
output length, this supports treating the final KiB as packaging metadata for
this sample. Merely making that KiB available to the decoder does not cause
it to be consumed. The tail's internal field meanings/checksum remain unknown;
this finding does not establish a universal TkTool specification.

### Reproduce bounded output

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
```

Ranges use an exclusive end. The default selects only blocks `0,1,2` and writes
JSON metadata. Each selected block starts with an empty output buffer and a
distance of four; observed blocks decode independently. The implementation
rejects a distance outside the already produced block bytes, rejects zero and
one-byte word distances, and requires each block's exact declared output length
and data-stream consumption. Command bits are MSB first; the fixed 256-word XOR
dictionary follows the [public Quram model](public_references.md).

The tool memory-maps input read-only, caps selected output at 8 MiB, block size
at 64 KiB, and header-declared total output/input at 512 MiB each. It never
allocates the declared whole-bank output. A malformed table is rejected before
decoding; stream errors stop at the failing block and retain prior block
metadata and diagnostic offsets in JSON. Raw bytes are written only when
`--extract-dir` is supplied, to a separate directory. Validated PNG extraction
can join adjacent selected blocks; it never joins gaps. Resources extending
outside a selected window remain unvalidated. Magic reports are capped at
32 per type per block and 256 per type per contiguous scan window; validated
PNG reports/extractions are capped at 256 per window.

20 selected blocks (80,828 output bytes) passed local decoding. Eleven were
also compared against the temporary public C implementation; every length and
SHA-256 matched. Representative results:

| Block | Output bytes | Output SHA-256 |
| ---: | ---: | --- |
| 0 | 4096 | `1b5b531f0eac403b2bf07664bad0493316723880d1d1865a2f1bf19d5884126f` |
| 10000 | 4096 | `3043b88a81746f398ac31897eaff5e9a69050305cc2e097e39de141e25cc8656` |
| 17252 | 4096 | `e2c151e4d52ca7025843acc0c68af898533d2c3924016b29d9b89c7256692638` |
| 17253 | 3004 | `4278d17e4e6a5ce52f9d2f7cb7dab009bb4fcbfe4408b352b865a2c9b011dca9` |

This verifies selected compression blocks and bounded resource spans. It does
not establish a complete resource-bank unpack or ID-to-resource map.

### Actual resource boundaries and content features

These offsets are in the **decompressed logical bank**, not the `.rc1` file:

| Feature | Logical offset | Evidence |
| --- | --- | --- |
| PNG | `0x1068d78` | 996-byte span, IHDR through IEND; every chunk CRC checked |
| XML | `0x13e9ec6` | Parsed 1,580-byte WAV iXML chunk; root `BWFXML` |
| BWFXML | `0x13e9eee` | Root element inside the WAV iXML chunk |
| FWS | `0x3297de8` | Indexed Bluetooth SWF; header/tag extents validated through End |
| JFIF | `0x32c9802` | Feature inside indexed Bluetooth SWF; JPEG subextent unknown |

Ten complete PNGs were bounded and extracted in the selected `4198:4203`
window. The first crosses blocks 4200/4201, ends at `0x106915c`, and hashes to
`178085e5cc8cc651a51102bd52df565f3f9eba86779b2fae27f729feac03de45`.
Extraction follows PNG chunk lengths and validated CRCs through a zero-length
IEND; it is not a carve from one magic to the next. This verifies the encoded
PNG span, not all raster semantics. Subsequent directory parsing also bounds
the named SWF/XML files and the nested WAV iXML chunk; see the index pass below.
No independent resource extent is claimed from magic alone. In particular a CWS header's declared size is the **uncompressed**
SWF size, not its compressed file span; earlier probe counts using it as a
compressed boundary must not be treated as validated extraction results.

Earlier packed-byte surveys (`resource_magic_survey.py`, `imrc_probe.py`)
remain useful for seeds only: they found 137 PNG, 122 JFIF, 16 XML, 27 BWFXML,
17 FWS, and 29 CWS features in the compressed file. Packed-byte signature
counts and candidate chunk chains do not count independent decoded resources.

## Logical directory and RBM index follow-up

The [resource index pass](imrc_resource_index.md) recovers 101 directories and
736 file entries from only 11 initial blocks. Metadata ends at `0xad3c`;
file offsets/lengths cover the bank with at most three bytes of alignment
between payloads. Named PNG, SWF, XML and WAV files were located by these
entries and structurally validated at their exact indexed lengths.

All 139 RBM files also expose bounded local indices: 11,539 records with IDs
restarting at zero per file, contiguous body extents and matching body IDs.
The new tool can select and hash a body by path and local ID. Pixel decoding,
global application ID composition and the consuming loader remain unknown.

## ShpApp.app resources

`ShpApp.app` is primarily a FimBIN/native ELF payload, but it also embeds a small
set of resource-like data:

| Magic | Count |
| --- | ---: |
| `PNG` | 4 |
| `GIF87a` | 3 |
| `GIF89a` | 3 |
| `JFIF` | 7 |
| `XML` | 8 |
| `ZIP_local` | 1 |

This supports the model that ShpApp carries both native code and bundled runtime
assets.

## FactoryFs resources

`FactoryFs_B5310_China.ffs` is FAT16 and contains many normal user/application
files. Magic counts include:

| Magic | Count |
| --- | ---: |
| `PNG` | 266 |
| `GIF89a` | 26 |
| `JFIF` | 55 |
| `XML` | 14 |
| `ZIP_local` | 1786 |
| `SWF_FWS` | 4 |
| `SWF_CWS` | 3 |

The high ZIP count is consistent with preinstalled J2ME `.jar` files and widget
packages in the FAT filesystem. See `docs/factoryfs_analysis.md` for the FAT16
directory and extension map.

## Rsrc2 profile banks

`Rsrc2_B5310U(Low).rc2` and `Rsrc2_B5310U(Mid).rc2` are not `IMRC` containers.
Both are `0x85128` bytes and begin mostly with zeroes; offset `0x10` contains
`CHN\0`. The Mid variant has `u32le[0x08] == 1`, while Low has zero there. A
byte comparison shows only that profile word and a short tail area near
`0x84f70` differ in the first pass, suggesting low/mid profile selection data
plus a checksum/signature-like trailer rather than a second full resource bank.

## Working model

- `Rsrc_B5310_China.rc1`: primary packed UI/resource database for native/SHP UI.
- `ShpApp.app`: native ARM SHP runtime/application payload plus a small embedded
  asset set.
- `FactoryFs_B5310_China.ffs`: FAT16 filesystem for Java apps, widgets, media,
  certificates, settings, and system files.

## Next questions

1. Recover global resource-ID composition and RBM pixel encoding; file lookup
   and RBM local-ID extents are now verified.
2. Map `Rsrc` resource IDs to ShpApp references.
3. Determine whether `Rsrc2_B5310U(Low/Mid).rc2` are density/profile variants or
   secondary resource banks.
4. Identify which resources are loaded directly from FactoryFs versus IMRC.
