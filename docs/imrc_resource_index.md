# IMRC logical directory and RBM local indices

This pass establishes **path → logical offset/length → validated file** and,
for RBM files, **path + local ID → indexed body bytes**. The application-wide
resource-ID encoding remains unknown. A subsequent [ShpApp consumer pass](shpapp_resource_consumer.md)
connects six browser callback arguments to these local IDs. This is a directory
model derived from the shipped sample, not a vendor format specification.

Sample: `Rsrc_B5310_China.rc1`, SHA-256
`425f464bbdaae55fb685bd3e2636b76473cd787dde8a6dadd66f03e8c521e1e3`.
All offsets on this page refer to decompressed IMRC bytes unless identified
as ShpApp container offsets. The [bounded decoder](resource_layer.md) supplies
only addressed blocks; no full bank is allocated or exported.

## Directory model

The first 64 logical bytes contain two words `1,1`, a 44-byte zero-padded
ASCII root name (`System`), root directory offset `0x40` at `0x34`, bank length
`0x04365bbc` at `0x38`, and a zero word at `0x3c`. The semantics of the initial
and final words are unknown.

Each directory begins with three little-endian u32 fields:

| Relative offset | Field | Evidence |
| --- | --- | --- |
| `0` | Parent directory offset | Every child points back to its actual parent; root uses zero |
| `4` | Child directory count | Exactly matches the following 48-byte records |
| `8` | File count | Exactly matches the following 52-byte records |
| `12` | Directory entries, then file entries | Extents of all 101 directory nodes meet exactly |

A directory entry contains `name[44]` followed by a u32 child offset. A file
entry contains `name[44]`, u32 logical data offset and u32 byte length. Names
in this sample are ASCII with zero padding. No numeric application resource ID
is present in these directory records.

The parser recovered **101 directories and 736 files**. Directory metadata
occupies `[0x40, 0xad3c)` continuously; the first file starts at `0xad3c`.
Only 11 compression blocks are needed for the complete directory index.
The logical header plus directory bytes `[0,0xad3c)` have SHA-256
`c30c58587eaf4c0dd6179dd1bc86632708ef247f6f10328ac9fb72d29f8d7c77`.
All nonempty payloads are disjoint, separated by 0–3 bytes for four-byte
alignment, and end at `0x04365bbc`. There is one zero-length file.

Extension counts are names, not content validation: 183 `.png`, 162 `.wav`,
139 `.rbm`, 53 `.bmp`, 34 `.swf`, 34 `.ivt`, 29 `.ini`, 23 `.mmf`, 22 `.ttf`,
and two `.xml`, among other types. The complete listing stays local in `out/`.

## Indexed files and nested resources

| Lookup path | File-entry offset | Logical data offset | Bytes | Validation |
| --- | --- | --- | ---: | --- |
| `System/Media/Img/Java/checkbox_off.png` | `0xb50` | `0x1068d78` | 996 | PNG chunk lengths/CRCs through IEND at indexed end |
| `System/Rsrc/Flash/Bluetooth/Bluetooth.swf` | `0x9868` | `0x3297de8` | 1,033,349 | FWS header length, RECT/frame header, 518 bounded tags, End exactly at indexed end |
| `System/Settings/PreConnection/KoreaGumi/User/Br/bookmark.xml` | `0xa78c` | `0x435f68c` | 545 | Entire indexed XML parsed; root `bookmark`; external DTD not fetched |
| `System/MediaSet/Sound/EffectTone/alarm.wav` | `0x4820` | `0x13d472c` | 89,542 | RIFF size/chunk lengths exactly match indexed end |

Selected output SHA-256 values are retained in
`out/imrc_resource_index/index.json`. The PNG hash equals the earlier bounded
carve, independently joining a named directory entry to a CRC-checked file.
SWF structural validation does not execute ActionScript or recover its resource
consumer. PNG validation does not decode its raster pixels.

The earlier XML/BWFXML features at `0x13e9ec6/0x13e9eee` are inside the WAV's
**iXML chunk**, not a separate top-level XML file. Its 1,580 bytes parse as XML
with root `BWFXML`; its SHA-256 is
`0c555dbb007bfa44fadd7817bf38066cb971f7efd0a3a8d3fe38ff574bfb5e15`.
The WAV's RIFF chunks are `fmt ` (16 bytes), `data` (87,806), `LIST` (96), and
`iXML` (1,580). Thus the nested XML extent follows a real length field. The
JFIF feature at `0x32c9802` falls inside the indexed Bluetooth SWF. Its JPEG
subresource extent is still unvalidated; it must not be counted as a separate
top-level file from its signature alone.

## RBM local-ID model

All **139 RBM files** have a 12-byte header: words `(0,0x100)` and a record
count. Each following 16-byte record is four little-endian u32 values:

| Field | Observed invariant |
| --- | --- |
| Kind word | `0x100`; exact semantics unknown |
| Local ID | Distinct and sequential `0..count-1` in each file |
| Body offset | Relative to the RBM file start; first equals table end |
| Body length | Adjacent bodies meet; last body ends exactly at directory-indexed file end |

Across **11,539 records**, every extent is bounded and every body's first u32
matches its table ID. These checks read only headers, tables and four bytes per
body; they do not decode bitmap pixels. IDs restart in every RBM file, so a
local ID alone cannot identify a global resource.

For `System/Rsrc/Bmp/Black/KJava.rbm` the directory entry identifies a
38,212-byte file at `0x20746b4`, with nine records:

| Local ID | Relative body offset | Logical bank offset | Bytes | Body SHA-256 |
| ---: | --- | --- | ---: | --- |
| 0 | `0x9c` | `0x2074750` | 6,704 | `6898c833dc6363a20694d0a44ab235045d08ef4778d0b6bc8448c4b072ea368f` |
| 8 | `0x6fd4` | `0x207b688` | 9,584 | `39780ef4845b3064f8d0116e9450b8c6cf8375c0c07ce174b75d5fa6e4514a8f` |

Both bodies were selected by path/local ID and exported locally at their exact
indexed lengths. They remain encoded RBM body bytes. Dimensions, color format,
compression, global ID composition, theme selection and the loader API are not
established by this index pass. The subsequent [body encoding pass](rbm_body_encoding.md)
validates a 40-byte header and mode-0/1 sample expansion for 329 other bodies.

## Reproduction and limits

```sh
# Directory metadata, selected complete files, and all RBM subindices.
python3 tools/imrc_resource_index.py /home/joe/thing/Rsrc_B5310_China.rc1 \
  --survey-rbm \
  --verify System/Media/Img/Java/checkbox_off.png \
  --verify System/Rsrc/Flash/Bluetooth/Bluetooth.swf \
  --verify System/Settings/PreConnection/KoreaGumi/User/Br/bookmark.xml \
  --verify System/MediaSet/Sound/EffectTone/alarm.wav \
  --extract-dir out/imrc_resource_index/files \
  --out out/imrc_resource_index/index.json

# Resolve two RBM local IDs without a whole-bank export.
python3 tools/imrc_resource_index.py /home/joe/thing/Rsrc_B5310_China.rc1 \
  --rbm-id System/Rsrc/Bmp/Black/KJava.rbm 0 \
  --rbm-id System/Rsrc/Bmp/Black/KJava.rbm 8 \
  --extract-dir out/imrc_resource_index/files \
  --out out/imrc_resource_index/rbm_selected.json

IMRC_SAMPLE=/home/joe/thing/Rsrc_B5310_China.rc1 \
  python3 -m unittest discover -s tests -v
```

The index reader uses a 32-block LRU. Limits: 1 MiB metadata address range,
16,384 entries per checked count, 64 path levels, 1,024 path characters,
8 MiB cumulative logical reads, 32 MiB block decode work and 2 MiB per selected
file/body. Only verified requested files and explicitly selected RBM bodies
are exported; pixel decoding is not implied. Default behavior inventories
metadata only. The combined survey and four-file check read 1,445,576 addressed
bytes and decoded 15,917,056 block bytes, discarded from the bounded cache as
it advanced; no complete decompressed bank was retained.

35 tests pass, including directory parents/cycles, names, count/extent limits,
file boundaries, nested directories, PNG/XML/FWS/RIFF structure, nested iXML,
RBM body IDs and selection, and optional real-sample index/PNG checks. Full
reports, extracted files, and local ID tables remain ignored under `out/`.

## Consumer search boundary and next step

An exact ASCII/UTF-16LE search of eight selected path/name patterns in
`ShpApp.app` (SHA-256
`6f5a455adb73a22eef95f1c7f01ee4de6d4a2c812c394f43c791beb774dcbab1`)
produced one substring hit for `checkbox_off.png`. The complete C string is
**`sfb_checkbox_off.png`**, starting at container offset `0x20076`; it is not
the indexed Java filename. No matching full indexed path or direct little-endian
pointer to either candidate string address was found in that bounded search.
This establishes neither a consumer nor absence of one. No new disassembly or
runtime evidence is claimed.

The subsequent [browser consumer pass](shpapp_resource_consumer.md) found direct
Thumb ADR references to `SFBrowserRsrc.rbm` and callback arguments
20/21/22/23/24/28. It follows saved returns into drawing calls. This resolves a
specific consumer seed without establishing the host's path/theme resolution.

Next: follow that host callback or recover the bounded RBM pixel encoding.
An independent pixel-format decoder can follow
from one of the small, now bounded RBM bodies. Rsrc2 mapping, tail internals and
complete library export remain outside this result.
