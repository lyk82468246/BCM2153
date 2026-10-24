# Public references used in the investigation

These references are external context only. They do not authenticate the
private firmware and are kept separate from shipped-artifact observations.

## IMRC decoder

- Project: [raulmrio28-git/ImrcUnpacker](https://github.com/raulmrio28-git/ImrcUnpacker)
- Retrieved: 2026-10-23
- Referenced commit: `de8a85c342b431b7d18778c8c31e28fb8d21169e`
- Description in repository metadata: “Unpack Imaster/Quram IMRC from Samsung
  feature phones”.
- Relevant source files: `src/imrc2raw.c`, `src/quram_imrc.c`,
  `src/imaster_imrc.c`, `common/imrc_int.h`.

The source defines the little-endian `IMRC` magic and these relevant routines:

- [`QuramDataDecompInit`, `src/quram_imrc.c`](https://github.com/raulmrio28-git/ImrcUnpacker/blob/de8a85c342b431b7d18778c8c31e28fb8d21169e/src/quram_imrc.c#L273):
  a five-DWORD `tk15_IMRCHeader` follows magic/version. For this version the
  8-byte command/data table starts at `8 + 20 = 0x1c`, not `0x20`.
- [`IM_DataDecompress`](https://github.com/raulmrio28-git/ImrcUnpacker/blob/de8a85c342b431b7d18778c8c31e28fb8d21169e/src/quram_imrc.c#L109):
  separate command/data streams, MSB-first commands, initial four literal bytes,
  an initial byte distance of four, 16-byte groups, word copies/XOR dictionary
  differences, byte copies, and the final non-16-byte literal remainder.
- [`common/bit_handle.h`](https://github.com/raulmrio28-git/ImrcUnpacker/blob/de8a85c342b431b7d18778c8c31e28fb8d21169e/common/bit_handle.h):
  `CHK_BITS`, `EXTRACT_BITS` and `EXTRACT_BIT` establish MSB-first extraction.
  The local decoder reads only needed bits and checks the command boundary;
  the C implementation also prefetches bits.
- [`common/imrc_int.h`](https://github.com/raulmrio28-git/ImrcUnpacker/blob/de8a85c342b431b7d18778c8c31e28fb8d21169e/common/imrc_int.h):
  `VER2DOUBLE(0x02000400)` computes `2.4` using its decimal formula. This is the
  public implementation's interpretation, not an authenticated vendor version
  specification. The dispatcher uses a version threshold, while the Quram
  initializer tests the raw `dwVersion >= 2.0` despite computing `dVersion`.
  The local decoder therefore supports only the observed raw version, rather
  than extending these heuristics to untested versions.

### Bounded public-code cross-check, 2026-10-24

The public decoder is compiled and executed only from the temporary
`/tmp/imrc-public/` build. Existing cached reference snapshots supplied five sources; the missing typedef
and bit headers were fetched at the same pinned commit. Git blob SHA-1 values
for all seven files match the cached pinned tree. Source identities are saved
locally in `out/imrc_bounded_decode/public_source_identity.json`.

The upstream source does not compile/run as intended on this Linux LP64 host
without portability changes. In the temporary build only:

1. `DWORD` and `LONG` use 32-bit `unsigned int`/`int` instead of 64-bit `long`.
   This restores the 20-byte header and 8-byte records.
2. `ALLOC_CHECK` uses `(type)` instead of invalid `(type ##)` token pasting.
3. The common copy helpers return their declared pointer/length types; their
   byte-copy operation is unchanged and these return values do not drive the
   decompression algorithm.

The first three blocks also matched via `QuramDataDecompress` from logical
input offset zero. For arbitrary blocks the comparison harness calls the
unchanged internal `IM_DataDecompress` after `QuramDataDecompInit`, supplying
the parsed packed offset and the exact block output size. This avoids treating
that API's logical-position argument as a compressed file pointer. It writes
only selected outputs under `/tmp`, with a 15-second process deadline and
AddressSanitizer enabled (`detect_leaks=0`). No ASan error occurred in the final
11-block run. The original harness and command log are retained as local
research outputs; no upstream implementation is added to tracked files.

Blocks `0,1,2,100,1000,4200,4201,4202,10000,17252,17253` all match the local
implementation byte-for-byte, including lengths and SHA-256. The reference's
header interpretation also agrees. Its unchecked parser/decoder is not used
as a safety oracle for malicious inputs: failure offsets for the old `0x20`
model are established by bounded metadata parsing, while malformed command,
data and distance behavior is tested against the checked local decoder.
These are format cross-checks, not proof of local firmware authenticity or
complete resource-ID recovery.

The same GitHub search also lists
[ImrcUnpacker-Unicorn](https://github.com/raulmrio28-git/ImrcUnpacker-Unicorn),
which may provide a second implementation for later cross-checking. No code
from that repository has been executed in this pass.

## Other public search leads

DuckDuckGo results for `"BCM2153" firmware` surfaced a BCM2153/NAND3G
downloader listing and Broadcom datasheet mirrors. These are leads only; the
downloader is an executable and was not downloaded or run. Searches for
`FimBIN`, `TkTool`, and `pDllBaseEcomFactory` did not produce a directly
authenticated format specification in this pass. A GitHub search for `FimBIN`
returned no repositories, while a broad `IMRC` search found the decoder above.

## Research hygiene

Search-result pages and fetched source snapshots are stored under the ignored
`out/web_research/2026-10-23/` directory. Network results may change, so each
technical claim above includes the repository URL, retrieval date and commit
where available. Public code is used to generate hypotheses and tests; local
firmware bytes remain the primary shipped-artifact evidence.
