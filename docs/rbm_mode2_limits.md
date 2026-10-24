# Mode 2: reproducible ambiguity and search limits

Mode-2 decoding remains **unresolved**. A matching pixel count and legal
backreferences are insufficient to choose its literal-stream origin. The
diagnostic `tools/rbm_mode2_probe.py` reports two competing hypotheses and
their hashes; it selects neither and exports no raster. The stable body
decoder continues to support only modes 0/1.

## Observed framing and candidate grammar

Source: `Rsrc_B5310_China.rc1`, SHA-256
`425f464bbdaae55fb685bd3e2636b76473cd787dde8a6dadd66f03e8c521e1e3`.
Of 8,942 mode-2 records, 4,434 declare 16 bits and 4,508 declare 32 bits.
The following model was investigated only for the 16-bit group.

For body payload `p` after its 40-byte header, let
`low = BE16(p[0:2])`, `high = LE16(p[2:4])`, and
`N = low + floor(high/2) * 65536`. The resulting interval `[4,N+3)` is a
bounded, even-length candidate command stream in all 4,434 records.
The duplicated bit `(high & 1) == (low >> 15)` was checked on the 4,241
ordinary candidates. This is an observed encoding model; a native reader has
not established the field's actual type or semantics.

Treating each command as big-endian u16, with high four bits as copy length
and low twelve as distance, gives exact dimension-derived counts and legal
distances for **4,241** bodies. A zero-length command consumes one little-endian
u16 from the putative raw stream at `p[N+3:]`. All these bodies begin with a
literal command. The remaining **193** records all belong to
`ContactRsrcBmp.rbm` and use command bit `0x800`; this grammar does not explain
them. Treating that bit as two inserted literals works for only 2/193 records
and was rejected as a general rule.

## Two interpretations of one real body

`System/Rsrc/Bmp/Black/Br_Cd_Etc.rbm`, ID 0, is a 156-byte body declaring
7 by 7 pixels. Body SHA-256:
`367a0b0f2acffd799e23893c9836dfbc599a42bb1ae23be2efcc1b075fb171d1`.
Its candidate command interval is payload `[4,76)`, containing 36 words.

| Hypothesis | Produced samples | Raw bytes consumed | Remaining modeled bytes | Candidate sample SHA-256 |
| --- | ---: | ---: | --- | --- |
| First raw word is the first literal | 49 | 36 | One unexplained word plus two alignment bytes | `70b219847dbf83e0f4e1dc08c70b337a75e2d9f5b02bc9be0568853d5b75f84d` |
| First raw word is hidden initial history | 49 | 38 | Two alignment bytes | `3f17ba713b1a4c3cf10027515328cfc7d8726770014729dbe3d72b61da29d7de` |

Both satisfy the tested count/distance constraints, yet produce different
pixels. The second hypothesis's cleaner tail is not independent proof of a
hidden seed. In uniform images both hypotheses can even yield the same hash;
that also cannot establish a model. Synthetic tests cover both cases.

`ContactRsrcBmp.rbm`, ID 117, exposes four commands carrying `0x800`.
The diagnostic explicitly returns an unresolved unsupported-grammar result
and does not attempt either raster model for it. The 32-bit browser bodies
are also unsupported; their extra framing must not be forced into this model.

## Independent image comparison

All 183 indexed PNGs (886,468 bytes) passed PNG span/CRC checks and were read
with Pillow 12.1.1. The comparison tested RGB565 and reversed red/blue packing,
truncation and rounding, vertical row reversal, and either retaining transparent
RGB or mapping zero alpha to key `0xf81f`. There was no exact match to any of
the 4,241 hidden-seed candidate hashes.

A further comparison added 49 BMPs whose `bfSize` equals the indexed file
length. Neither candidate matched these raster variants; the first-literal
model was evaluated for the 109 ordinary RBM records with matching raster
dimensions. This search does not exclude transformed, composited or differently
quantized copies. The four other BMPs were excluded because their `bfSize`
equals `bfOffBits`, 1,600 bytes below their indexed size. Their `biSizeImage`
also disagrees with an 8-bit 40-by-40 raster. These field inconsistencies do
not establish that their indexed extents or pixel data are damaged.

Earlier comparison against the 329 validated mode-0/1 outputs also found no
identical hidden-seed candidate. No comparison has selected a mode-2 model.
The PNG/BMP experiment read bounded addressed blocks and retained metadata,
not a full decompressed bank. Complete experimental scripts/reports remain
local in `out/imrc_resource_index/rbm_pixel_probe/`.

## Reproduce the ambiguity

```sh
python3 tools/imrc_resource_index.py /home/joe/thing/Rsrc_B5310_China.rc1 \
  --rbm-id System/Rsrc/Bmp/Black/Br_Cd_Etc.rbm 0 \
  --rbm-id System/Rsrc/Bmp/Black/ContactRsrcBmp.rbm 117 \
  --extract-dir out/imrc_resource_index/files \
  --out out/imrc_resource_index/mode2_inputs.json

python3 tools/rbm_mode2_probe.py \
  out/imrc_resource_index/files/rbm_records/System/Rsrc/Bmp/Black/Br_Cd_Etc.rbm.id_0.bin \
  --out out/imrc_resource_index/mode2_ambiguity.json

IMRC_SAMPLE=/home/joe/thing/Rsrc_B5310_China.rc1 \
  python3 -m unittest discover -s tests -v
```

A diagnostic can exit zero with JSON `status: "unresolved"`; this means the
probe ran, not that decoding succeeded. Bounds come from the stable body
header checks (2 MiB payload, 4,096 per dimension, 1,048,576 pixels). Prefix,
command/data extents, copy distances and output counts are checked before
growing candidate buffers. Errors retain the candidate command offset and
consumption. Tests include a command extent crossing the 16-bit size boundary.

Next useful evidence is the native bitmap decoder or a demonstrably identical
asset. The ShpApp consumer currently reaches indirect host callbacks; their
implementations remain unknown. A bounded Thumb mask-pattern search in ShpApp
yielded 24 candidate windows, but inspection did not establish a matching RBM
mode-1 decoder. It does not prove that a decoder is absent from ShpApp.
