# TkTool/Samsung tail records

Several firmware images end with a common Samsung/TkTool-style trailer. Treat
this trailer as packaging metadata unless a loader proves otherwise.

Generated locally with:

```sh
python3 tools/tktool_tail_survey.py /home/joe/thing --out out/tktool_tail_survey
```

The generated `out/` files are local-only. This page keeps the public-safe
summary.

## Observed markers

| File | Size | Last `cd ab cd ab` offset | Distance from end | Selected tail strings |
| --- | ---: | ---: | ---: | --- |
| `bcmboot.img` | 43,878 | `0x0000a766` | 1024 bytes | `B5310` |
| `boot2.img` | 317,078 | `0x0004d296` | 1024 bytes | `B5310+XX+IL1`, `TkToolVer:1.6.1` |
| `amss.bin` | 5,824,292 | `0x0058db24` | 1024 bytes | `B5310`, `B5310U` |
| `apps_compressed.bin` | 37,749,760 | `0x02400000` | 1024 bytes | `B5310U+ZC+JH2`, `TkToolVer:1.6.1` |

## Boot2-specific notes

`boot2.img` has a high-entropy body followed by a low-entropy tail region. At
offset `0x0004c014`, the tail begins exposing many `MID_*` module identifiers,
including app/service names such as `MID_PTT`, `MID_SYSTEM`, `MID_SETTING`, and
call/media-related modules.

The common `cd ab cd ab` marker is at `0x0004d296`, exactly 1024 bytes from the
end of the file. Nearby tail metadata includes model string `B5310+XX+IL1` and
`TkToolVer:1.6.1`.

This supports the working model that `boot2.img` is a packaged image with a
tooling trailer and mixed payload/metadata, not a simple raw ARM stage that can
be loaded directly from file offset zero.

## Current interpretation

- The final 1024-byte region is likely downloader/build-tool metadata.
- The marker can identify where payload ends and packaging metadata begins.
- Runtime load analysis should ignore this tail until the loader explicitly
  references it.
- For `boot2.img`, the high-entropy body before the module-name table remains
  the primary unpacking/decryption target.
