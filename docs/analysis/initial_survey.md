# Initial firmware survey

Generated locally with:

```sh
python3 tools/firmware_survey.py /home/joe/thing --out out/initial_survey
```

The generated `out/` files are local-only. This page is the manually filtered,
public-safe summary.

## High-confidence findings

- The target firmware is for a Samsung GT-B5310/B5310U family device.
- The baseband/application stack identifies Broadcom BCM2153 and the Hedge
  platform.
- The main modem image is Nucleus PLUS for ARM/Thumb, not a Linux/Android image.
- `bcmboot.img` is a NAND boot stage that loads `boot2.img` or enters download
  mode on failure.
- `amss.bin` is directly loadable ARM little-endian code and should be the first
  major Ghidra target.
- `boot2.img` and the start of `apps_compressed.bin` are high entropy and need
  format/protection analysis before disassembly.

## Suggested loading priorities

1. `bcmboot.img`: small, boot-chain critical, has clear strings and vector code.
2. `amss.bin`: main Nucleus/BCM2153 image with rich symbols and source-path
   strings.
3. `boot2.img`: likely protected/packed; analyze after understanding
   `bcmboot.img` loading and verification.
4. `apps_compressed.bin`: large feature-phone application image; defer until
   boot path and unpacking are understood.

## Ghidra import hints

For `amss.bin`:

- Language: ARM little endian, ARM/Thumb.
- Start with base address `0x80300000` as a hypothesis.
- File offset `0x0` has a valid ARM vector table.
- Header/vector-adjacent words point to addresses around `0x80300000` and
  `0x804e0000`.

For `bcmboot.img`:

- Language: ARM little endian.
- File offset `0x40` appears to be an ARM vector table.
- Header-like data exists before `0x40`.
- `0x28000070` and `0x2800066c` appear immediately after a `0xbabeface` marker
  near the vector table and may be SRAM/runtime addresses.

## Noise notes

Vector-table scanning can produce false positives inside resource and Java data.
For now, treat only `amss.bin` offset `0x0` and `bcmboot.img` offset `0x40` as
high-confidence vector candidates.
