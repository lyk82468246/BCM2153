# Firmware facts

This page is the durable fact store for the BCM2153 effort. Keep statements here
short, cited by local file name and offset when possible, and separate confirmed
facts from hypotheses.

## Sample set

Local private sample directory: `/home/joe/thing`.

Known sample files and SHA-256 hashes:

| File | Size | SHA-256 |
| --- | ---: | --- |
| `bcmboot.img` | 43,878 | `c0801d111659553f791eb78b4fe5138b01df3d786f91d5921712b2fc8b592601` |
| `boot2.img` | 317,078 | `e5c609e963c0154176a3e90d303ac94421ff0d38ab1b3b996c8f0022fadfbb53` |
| `amss.bin` | 5,824,292 | `864d33c85366b808beccdc02a673c91a950f177f3d1513521d2cfb540b228e1d` |
| `apps_compressed.bin` | 37,749,760 | `f35efe7382787bab43742a548cffc904dc60637ba30df6ede779a28bbaea2448` |
| `FactoryFs_B5310_China.ffs` | 37,836,800 | `c33b5d69e1376434cefa444e51afd7d5889cfbe6335521678e91433dd2238726` |
| `Rsrc_B5310_China.rc1` | 48,287,158 | `425f464bbdaae55fb685bd3e2636b76473cd787dde8a6dadd66f03e8c521e1e3` |
| `ShpApp.app` | 6,189,176 | `6f5a455adb73a22eef95f1c7f01ee4de6d4a2c812c394f43c791beb774dcbab1` |
| `drom_dsp.img` | 66,558 | `c86b00645587dd693eff75de628e197fbfe67f7e03abdda4c0b1df404d9a4716` |
| `patch_dsp.img` | 17,696 | `2bbf01285246a086b3ce788ea355d8fb367c287b3f001e97ee63df0582b5cfab` |
| `sysparm_ind.img` | 56,896 | `27bdeb13cef9255a2bba7c0917d8e7a3c646d19243cd89e7c5ad8c4f559a2d50` |
| `sysparm_dep.img` | 6,920 | `654c23dafb066ae58d213fabc25a7e1f3d0a83a6cd7ec2fc0e08646ee500d09a` |
| `NVRAM6.bin` | 3,208 | `3a93c8df31ae346aecb41b21ecb032c0f848113235ec7bdb00efb3c0c23e34af` |
| `PFS_B5310_Open_China_Common.pfs` | 5,272 | `3794f6aa77e6a8110feae83a2c4eaba1970e8defe2c47c2a52667791346cc117` |
| `Rsrc2_B5310U(Low).rc2` | 545,064 | `9bc6d7c65cb3253ed1e116f21e1f451f1a3a2e0805c0c16da4458af1a2a248e4` |
| `Rsrc2_B5310U(Mid).rc2` | 545,064 | `b65aae25c1db21d44de0d52e542b146d3d6fd051d2f93e280f15886c16c9b49b` |

## Confirmed identifiers

`amss.bin` contains these selected strings:

| Offset | Text |
| ---: | --- |
| `0x002e8d48` | `BCM2153\src\irqctrl.c` |
| `0x004158a4` | `$Revision: #13 $ For BCM2153` |
| `0x0041599f` | `Nucleus PLUS - THUMB ARM Version 1.7.G1.3` |
| `0x00513064` | `Hedge Platform: BCM2153_SI1_3_43_V70` |
| `0x0054a2b0` | `GT-B5310U` |

`FactoryFs_B5310_China.ffs` contains model XML strings identifying
`GT-B5310U` and base model `GT-B5310`.

`FactoryFs_B5310_China.ffs` is a FAT16 image. Its root directory includes
`Debug`, `DicDB`, `Exe`, `Media`, `Mount`, `Security`, `Settings`, and
`SystemFS`.

`ShpApp.app` contains an embedded 32-bit ARM ELF at file offset `0x0000192e`.
The ELF header reports machine `0x28` (ARM), one program header, and six section
headers.

`Rsrc_B5310_China.rc1` starts with `IMRC` and contains XML, PNG/zlib, GIF,
JPEG/BMP, and other resource-like data according to `binwalk` and string scans.

`apps_compressed.bin` and `boot2.img` both contain `TkToolVer:1.6.1` strings.

`bcmboot.img`, `boot2.img`, `amss.bin`, and `apps_compressed.bin` all contain a
last `cd ab cd ab` trailer marker exactly 1024 bytes before the end of the file.
See `docs/tktool_tail.md`.

## Image structure observations

`amss.bin` begins with an ARM little-endian vector table. The first eight words
are:

```text
e59ff024 e59ff024 e59ff024 e59ff024 e59ff024 e1a00000 e59ff020 e59ff020
```

`amss.bin` has a `0xbabeface` marker at offset `0x20`, followed by words that
include likely RAM/runtime addresses such as `0x803001fc`, `0x803000d8`,
`0x80300164`, `0x803000c0`, `0x8030007c`, `0x804e975d`, and `0x804e9641`.

`bcmboot.img` has an ARM vector candidate at offset `0x40`. It has a
`0xbabeface` marker at offset `0x60`, followed by words including
`0x00000b50`, `0x28000070`, and `0x2800066c`.

When loaded from file offset `0x40` at base `0x28000000`, `bcmboot.img` has
entry-like code at `0x28000030` that sets `sp` to `0x08700800`, uses
`0x08400000` as the next-stage RAM image base, checks for `0xbabeface` at
`0x08400020`, and jumps with `bx 0x08400000`.

The apparent reset-vector target word in `bcmboot.img` is `0x28000070`, but that
address falls inside the early string-output loop. Treat the first words as
vector-like header evidence, not as a confirmed CPU reset vector table.

`boot2.img` file offset `0x20` is not `0xbabeface` in the local sample. This is
evidence that raw `boot2.img` bytes are transformed or represented differently
before `bcmboot.img` performs the RAM header check.

`boot2.img` exposes a low-entropy metadata/module-name area starting around
offset `0x0004c000`. Selected visible module identifiers include `MID_PTT`,
`MID_SYSTEM`, `MID_SETTING`, and call/media-related modules. The final TkTool
trailer marker is at `0x0004d296`.

## Debug/service clues

`amss.bin` contains format strings for ARM memory reads:

- `ARM memory *(int32 *)0x%0lx = 0x%0lx`
- `ARM memory *(char *)0x%0lx = 0x%0x`
- `ARM memory *(int16 *)0x%0lx = 0x%0x`

These strings should be traced to identify service commands that may provide a
memory read/write or calibration/debug interface.

## Hypotheses

- `bcmboot.img` is an early NAND boot stage that loads `boot2.img`, or falls
  into download mode on failure.
- `boot2.img` is likely protected, compressed, encrypted, or packed; its first
  window entropy is high and `binwalk` does not identify a standard container.
- `apps_compressed.bin` is mostly high entropy, but contains late plaintext
  application/version strings; it may be compressed in blocks or contain a mixed
  image layout.
- `amss.bin` likely loads near `0x80300000`, based on vector-adjacent address
  constants in the header.
