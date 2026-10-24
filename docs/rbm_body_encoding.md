# RBM body headers and two sample encodings

The indexed RBM bodies have a 40-byte, ten-u32 little-endian header. A header
survey of all 11,539 indexed bodies found 9,292 ordinary records and 2,247
40-byte placeholders. Offsets below are relative to an individual body.

| Offset | Observed field | Evidence / limit |
| --- | --- | --- |
| `0x00` | Local ID | Agrees with enclosing RBM table |
| `0x04` | Word `1` | Ordinary records; full meaning unknown |
| `0x08` | Payload bytes | Equals indexed body length minus 40 |
| `0x0c` | Encoding selector | Observed values 0, 1, 2, 5 |
| `0x10/0x14` | Width/height | Product equals recovered sample count in modes 0/1 |
| `0x18` | Bits per sample | 16 or 32; only 16-bit modes 0/1 decoded here |
| `0x1c/0x20` | Candidate key flag/value | Flag 0/1; sample key `0xf81f` resembles RGB565 magenta, native use unverified |
| `0x24` | Word `0x1c` | Present in every body; meaning unknown |

Placeholders have eight `0xffffffff` words at `0x04..0x20`, retain their local
ID and final `0x1c`, and contain no payload. They must not trigger allocation
from their sentinel dimensions/lengths.

## Verified sample-word expansion

`tools/rbm_body_probe.py` implements an original bounded decoder for:

- **Mode 0:** raw little-endian u16 samples; payload must be exactly
  `width * height * 2` bytes, without per-row padding. All 33 observed records
  satisfy this rule.
- **Mode 1:** read a little-endian u16 `v`. When `(v & 0x3f) == 0x20`, read
  the next u16 sample and repeat it `v >> 6` times. Otherwise emit `v` once.
  A reserved-pattern sample can be escaped with a repeat of one. Stop at
  exactly `width * height` samples; only the 0 or 2 bytes needed to align the
  consumed stream to four bytes may remain. Observed alignment bytes are not
  consistently zero. All 296 observed records satisfy this rule, including
  exact sample count and stream/alignment boundary.

This 329-body validation addressed 847,572 logical bytes and decoded 913,408
IMRC block bytes using the bounded reader. It did not decompress the full bank.
The remaining ordinary records are 8,942 mode-2 bodies (4,434 at 16 bits,
4,508 at 32 bits) and 21 mode-5 bodies (one at 16 bits, 20 at 32 bits).
Their payloads remain opaque in the stable tool.
The separate [mode-2 diagnostic](rbm_mode2_limits.md) demonstrates why fitting
pixel counts do not resolve its literal-stream origin. It exports no raster.

`System/Rsrc/Bmp/Black/MsgTypeIcon.rbm`, ID 0, is a 224-byte body at logical
offset `0x23b7158`: mode 1, 15 by 15, 184 payload bytes. It yields 225 samples
(450 bytes), SHA-256
`89cba3b5c3c3b21aa986829e29f5dc62bc54c416d1dac848050fe08b3763510d`.
Body SHA-256:
`42660237dfc96f9d8b89b809696c35b9887dbc014fbb1fcdf93d62f95872a91b`.
A candidate RGB565 preview shows readable `BCC` letters against key-valued
pixels. This is supporting visual evidence for the expansion and dimensions;
native color packing, row orientation and transparency behavior still require
consumer-side corroboration. The PPM preview explicitly retains key pixels
as colors and applies no transparency.

## Reproduce a bounded body

```sh
python3 tools/imrc_resource_index.py /home/joe/thing/Rsrc_B5310_China.rc1 \
  --rbm-id System/Rsrc/Bmp/Black/MsgTypeIcon.rbm 0 \
  --extract-dir out/imrc_resource_index/files \
  --out out/imrc_resource_index/msg_type_icon.json

python3 tools/rbm_body_probe.py \
  out/imrc_resource_index/files/rbm_records/System/Rsrc/Bmp/Black/MsgTypeIcon.rbm.id_0.bin \
  --samples-out out/imrc_resource_index/MsgTypeIcon_0.u16 \
  --rgb565-preview out/imrc_resource_index/MsgTypeIcon_0.ppm \
  --out out/imrc_resource_index/MsgTypeIcon_0.json

IMRC_SAMPLE=/home/joe/thing/Rsrc_B5310_China.rc1 \
  python3 -m unittest discover -s tests -v
```

The bank-wide checks are also reproducible without exporting bodies:

```sh
# Default: indexed headers only, including opaque modes and placeholders.
python3 tools/rbm_bank_survey.py /home/joe/thing/Rsrc_B5310_China.rc1 \
  --out out/imrc_resource_index/rbm_headers.json
# Explicitly expand known encodings and report per-body sample hashes.
python3 tools/rbm_bank_survey.py /home/joe/thing/Rsrc_B5310_China.rc1 \
  --decode-modes 0,1 --out out/imrc_resource_index/rbm_modes_0_1.json
```

The combined header-and-sample command recovered the same 329 outputs and all
11,539 headers, addressing 1,630,276 logical bytes and decoding 25,579,520 block
bytes. This includes header/table traversal across all encodings, so it does
more work than the earlier selected-mode-only check. It stays within the
reader's 8 MiB addressed-read/32 MiB decode-work budgets and 32-block cache.
An aggregate 16,384-record limit bounds report memory. Errors retain completed
records and the failing path/local ID. All 46 tests pass with the private sample,
including exact bank-wide counts and known-mode expansion.

Default output is JSON metadata and hashes. Export requires explicit paths.
The tool caps a body at 2 MiB payload plus header, each dimension at 4,096 and
output at 1,048,576 samples. Invalid extents, zero/overflowing runs, exhausted
streams, unsupported decoding requests and unbounded dimensions fail before
export. Inputs and all output paths must differ. Synthetic regressions cover
these boundaries and a private-sample test independently checks the exact
MsgTypeIcon body and sample hashes.

Complete headers, per-record validation and previews remain local in
`out/imrc_resource_index/rbm_pixel_probe/`. This result does not resolve all
RBM modes, global resource IDs, theme mapping or the host bitmap constructor.
