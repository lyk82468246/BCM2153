# Resource layer notes

This page summarizes the first pass over UI/media/resource containers. It keeps
only counts and short offsets; generated `out/` reports stay local-only.

Generated locally with:

```sh
python3 tools/resource_magic_survey.py \
  /home/joe/thing/Rsrc_B5310_China.rc1 \
  /home/joe/thing/ShpApp.app \
  /home/joe/thing/FactoryFs_B5310_China.ffs \
  --out out/resource_magic_survey

python3 tools/imrc_probe.py \
  /home/joe/thing/Rsrc_B5310_China.rc1 \
  --out out/imrc_probe
```

## Rsrc_B5310_China.rc1

- File starts with `IMRC`.
- Size: `0x2e0cdb6` bytes.
- Header words begin with `IMRC`, `0x02000400`, `0x00001000`, `0x0000000c`,
  `0x00000006`, and `0x04365bbc`; the exact table format is still unknown.
- Magic counts from a first pass:

| Magic | Count | First observed offset |
| --- | ---: | ---: |
| `PNG` | 137 | `0x00a037d2` |
| `GIF89a` | 1 | `0x00a04e49` |
| `JFIF` | 122 | `0x01ee54db` |
| `XML` | 16 | `0x00d1d82b` |
| `BWFXML` | 27 | `0x00d1e935` |
| `ZIP_local` | 3 | `0x0002fea7` |
| `SWF_FWS` | 17 | `0x01eb4412` |
| `SWF_CWS` | 29 | `0x00dceca1` |

Visible UI/resource strings include `Idle`, `WidgetTray`, `WidgetMemo`,
`BluetoothIcon`, `GamesIcon`, `WidgetSetting`, `Menu`, and `Main`.

### IMRC probe findings

`tools/imrc_probe.py` performs a stricter metadata-only pass over `IMRC` files.
For `Rsrc_B5310_China.rc1`:

- Header fields are `version_word=0x02000400`, `table_or_header_size=0x1000`,
  `word_0x0c=0x0c`, `word_0x10=0x06`, and `word_0x14=0x04365bbc`.
  `word_0x14` is larger than the file size, so it may be an unpacked, virtual,
  or tool-side size rather than a direct file length.
- The first `0x1000` bytes after the magic do not look like a direct absolute
  offset/length table. Most words after `0x18` are small values, which is more
  consistent with a compact index, size/Huffman-style table, or another encoded
  structure.
- Naive magic scans overcount real resource boundaries. Current strict parsing
  finds 115 complete PNG spans out of 137 PNG magic hits, 7 complete `FWS` SWF
  spans out of 17, and 18 complete `CWS` SWF spans out of 29.
- JFIF, XML, and BWFXML strings are visible, but this pass does not yet bound
  them as standalone resource records. Treat them as evidence of embedded
  content, not as safe replacement boundaries.


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

1. Decode the `IMRC` header and entry table format.
2. Map `Rsrc` resource IDs to ShpApp references.
3. Determine whether `Rsrc2_B5310U(Low/Mid).rc2` are density/profile variants or
   secondary resource banks.
4. Identify which resources are loaded directly from FactoryFs versus IMRC.
