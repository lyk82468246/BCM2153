# FactoryFs FAT16 notes

`FactoryFs_B5310_China.ffs` is a FAT16 filesystem image used for application,
media, certificate, settings, widget, and system-support files. Generated local
reports stay under `out/`.

Generated locally with:

```sh
python3 tools/factoryfs_survey.py \
  /home/joe/thing/FactoryFs_B5310_China.ffs \
  --out out/factoryfs_survey
```

## Filesystem metadata

| Field | Value |
| --- | ---: |
| Filesystem | `FAT16` |
| OEM name | `MSWIN4.1` |
| Volume ID | `0xd00bad61` |
| Sector size | `512` |
| Cluster size | `8192` |
| Total cluster range | `2 - 27628` |

The Sleuth Kit listing has 608 visible entries plus 4 pseudo entries such as FAT
metadata. Visible entries split into 325 directories and 283 files.

## Top-level shape

| Root | Directories | Files | Interpretation |
| --- | ---: | ---: | --- |
| `Exe` | 20 | 33 | preinstalled Java and Mocha application trees |
| `SystemFS` | 272 | 191 | main system/user/settings/media support tree |
| `Security` | 20 | 56 | certificates and security configuration |
| `Media` | 6 | 1 | default media folders and one bundled media file |
| `Settings` | 4 | 0 | settings directory skeleton |
| `DicDB` | 1 | 1 | dictionary/database placeholder |
| `Debug` | 1 | 0 | debug directory skeleton |
| `Mount` | 1 | 0 | mount-point directory skeleton |
| `@samsung.ess` | 0 | 1 | Samsung root-level metadata/resource file |

## Extension profile

Most common file suffixes:

| Suffix | Count | Likely role |
| --- | ---: | --- |
| `.png` | 34 | Java/widget/UI icons and assets |
| `.der` | 29 | certificate material |
| `.bmp` | 29 | UI/media bitmap assets |
| `.mp3` | 25 | bundled audio assets |
| `.jpg` | 25 | media and camera simulator assets |
| `.txt` | 18 | text/config placeholders |
| `.cer` | 16 | certificate material |
| `.ini` | 14 | settings and application configuration |
| `.xml` | 11 | browser/IMS/multistage/config data |
| `.jad` / `.jar` | 10 each | preinstalled J2ME applications |
| `.bin` | 9 | driver/firmware/security blobs |
| `.wgt` | 3 | widget packages |

## Subtree observations

- `Exe/Java` contains 10 `.jad` files and 10 `.jar` files: 5 app directories
  under `Exe/Java/Games` and 5 under `Exe/Java/Locked Games`.
- `Exe/Mocha` exists with `App` and `Lib` subdirectories, but this image has no
  visible files under that subtree in the first `fls` pass.
- `SystemFS/Driver` has 11 files: 6 `.bin`, 4 `.dls`, and 1 `.xml`. Observed
  names include camera firmware-like `CE143_*`, `Mobile_*_base.dls`,
  `volpreset.xml`, and Broadcom WLAN firmware-like `Wlan_bcm_*` files.
- `SystemFS/MediaSet/Widget` contains 3 `.wgt` packages.
- `Security` is certificate-heavy: 29 `.der` files and 16 `.cer` files dominate
  that subtree.
- `SystemFS/User` is the largest mutable-looking tree, with browser, IMS,
  widget, multistage, Java, Mocha, and media/config subtrees.

## Interpretation

FactoryFs is not the native executable core. It looks like the persistent file
layer consumed by the feature-phone application environment: preinstalled J2ME,
widget packages, browser/IMS/user configuration, certificates, and hardware
support blobs. Native UI code still appears to live in `ShpApp.app` and packed
resource databases such as `Rsrc_B5310_China.rc1`.

For modification work, FactoryFs is likely the safest first target for adding or
replacing high-level files, while native string/function changes still require
understanding ShpApp/IMRC/app payload loaders.
