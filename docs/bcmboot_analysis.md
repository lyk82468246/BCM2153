# bcmboot analysis notes

`bcmboot.img` is imported with file offset `0x40` mapped to runtime base
`0x28000000`.

## Early flow

- `0x28000030`: entry-like setup code; computes `sp = 0x08700800`.
- `0x28000040`: calls a controller-init routine at `0x2800083c`.
- `0x28000048`: calls a controller read/status routine at `0x28000960` with
  `r0 = 0x40`.
- `0x28000054`: optional copy routine at `0x280003ac`.
- `0x28000058`: setup routine at `0x28000458`.
- `0x2800005c`: calls routine `0x280009c4`, which manipulates a buffer at
  `0x28007800` and repeatedly uses the controller routines at `0x280008b8` and
  `0x28000960`.

## Next-stage load

The load loop uses `0x08400000` as the destination base. After reading/copying,
it checks `*(uint32_t *)(0x08400000 + 0x20)` against the local `0xbabeface`
constant at `0x28000770`.

If the check passes, the loop continues until the image end is reached and then
jumps with `bx 0x08400000` at `0x280003a8`.

If the first header check fails, the code writes status values through addresses
loaded from `0x28000638` and `0x2800063c`, then spins forever at `0x28000350`.

## I/O clues

- `0x28000598`, `0x280005b8`, `0x280005c8`, `0x280005e8`, and `0x28000610`
  operate around `0x08821000` / `0x08820000` and look like byte-oriented serial
  or download-channel helpers.
- `0x2800083c`, `0x280008b8`, and `0x28000960` operate around `0x0c0c9000` and
  look like NAND/flash-controller helpers.
- `0x2800040c` checks bit `0x02000000` of the word at `0x08880008`; the result
  controls whether the copy loop reads 8-bit or 16-bit data from the NAND data
  register.

## Caution

The first words at `0x28000000` look like ARM exception vectors, but the
apparent reset target `0x28000070` lands inside a code sequence that expects
prior register setup. Treat this area as a Broadcom-style image header plus
vector-shaped stubs until hardware behavior confirms otherwise.

## REA follow-up: page loading and handoff

On 2026-10-23, REA 6.7.0 with Ghidra 12.1 returned a function dossier for
`0x28000030`:

- Evidence ID: `ev_d0a27ed64562ec96678d620540261f8b393d8792dd70ef06ee2190ed3b031c5c`.
- Complete local record: `out/rea_bcmboot/entry.seeded.evidence.json`.
- Reusable snapshot: `out/rea_bcmboot/seeded.snapshot.json`.
- Parent image SHA-256:
  `c0801d111659553f791eb78b4fe5138b01df3d786f91d5921712b2fc8b592601`.
- Derived input is the parent from offset `0x40` to EOF, SHA-256
  `e7b676a2cbe246af5aa497e683f49da9ac73b637e5742e9a04d49665a8c8a53d`.
- Raw ARM import maps derived file offset zero to `0x28000000`. A caller-supplied
  function seed identifies `0x28000030`; it is not an automatically discovered
  cold-start entry. The observed body spans `0x28000030`–`0x280003ab`.

The dossier confirms the following instruction-level flow:

| Region | Observation |
| --- | --- |
| `0x28000128`–`0x2800016c` | Bit `0x20000000` at `0x08880008` selects size pairs `0x200/0x10` or `0x800/0x40`, saved at `0x08700004` and `0x08700008` |
| `0x2800017c`–`0x28000180` | Initializes source-address counter to `0x1000` and RAM destination to `0x08400000` |
| `0x280001a0`–`0x28000318` | Issues controller commands/address cycles and copies `page_size + extra_size` bytes into RAM, using either halfword stores or byte stores from masked halfword reads |
| `0x2800031c`–`0x28000334` | Checks `0xbabeface` at RAM `+0x20` on the first page only; `r8` records that the check passed |
| `0x28000338`–`0x28000350` | On this failure path, writes word `1` to `0x08880018`, byte `8` to `0x088e0000`, then loops |
| `0x28000354`–`0x28000398` | Advances RAM and source counters by page size, reads the word at RAM `+0x24`, and compares the advanced destination against RAM base plus that word |
| `0x2800039c`–`0x280003a8` | Outputs a status value and branches to `0x08400000` |

The size pairs and controller address cycles support NAND page/spare semantics.
Because the copy includes the extra area but the next destination advances only
by page size, a subsequent iteration overwrites the preceding extra area.
The last iteration can leave extra bytes after its page. The word at RAM `+0x24`
acts as an image-length/end criterion; this pass does not establish a separate
maximum-size or authenticity check.

No explicit software decompression/decryption operation appears inside this
bounded copy/check loop. That narrows the investigation: first reconcile the
download-package file layout with the NAND/controller representation, rather
than assuming this loop contains a decoder. It does not prove that `boot2.img`
is unencrypted, or rule out transformations in initialization, hardware, another
loader path, or the host flashing tool. The counter `0x1000` is not established
as an offset into the standalone `boot2.img` file.

The raw provider selected generic `ARM:LE:32:v7:default`; this is not silicon
identification. Static evidence does not execute reset vectors, emulate MMIO,
or prove that a device follows this path. The first sandboxed REA attempt failed
at Unix-socket binding; the successful run used the approved external-sandbox
execution path. CLI cleanup completed and the snapshot was saved.
