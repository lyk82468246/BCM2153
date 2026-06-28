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
packages in the FAT filesystem.

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
