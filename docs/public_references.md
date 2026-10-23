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

The source defines the little-endian `IMRC` magic, the Quram header fields
`block size`, `extended distance bits`, `standard distance bits`, decompressed
size and block count, and 8-byte command/data block records. Its `imrc2raw`
dispatcher chooses Quram when the version word meets its threshold or when the
legacy block-size condition is present. The code is used here as a format
hypothesis and comparison reference; it is not copied into this repository and
has not been assumed to match every Samsung resource-bank variant.

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
