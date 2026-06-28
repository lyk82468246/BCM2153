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
