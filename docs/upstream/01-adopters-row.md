# adopters.md — c64-mlkem row update (draft, PATCH)

Replace the `c64-mlkem` row's cells as follows. Cells not listed are
unchanged from the v0.4.0 text landed in #126. Everything below is status;
no SPEC text changes.

## §6 Build target variants — append

> **SPEC v0.11.1 §6.3 implemented on the invalidation branch, and pinned**
> (c64-mlkem `79b80e1`): the flattened `CA65FLAGS|CONTRACT_DEFINES|CONTRACT_ZP_DEFINES`
> string is compared at **parse time** and a mismatch deletes the object
> trees, PRG, map and labels outright — deletion rather than a stamp
> prerequisite because the host toolchain is GNU Make 3.81, whose 1-second
> mtime granularity lets a stamp rewritten in the same second as the objects
> compare as not-newer (measured: stamp and object at the same mtime, content
> changed, zero ca65 invocations). Parse-time rather than recipe-time because
> a recipe that deletes the PRG runs after make has stat'd it, so the link is
> skipped and the build emits no file at all (also measured). Pinned by
> `make check-staleness`, both legs: a changed `CONTRACT_ZP_DEFINES` knob
> flips the linked PRG's hash, and repeating the knob rebuilds nothing and
> reproduces the hash — comparing PRGs, never `.o`/`.a` bytes, per the §6.3
> checkability note. Only the invalidation branch applies: `LIB_SRCS` is one
> unconditional assignment, so there is no member-set axis to reject. This
> replaces the 0.11.1 changelog's "`c64-mlkem` is unassessed against this
> paragraph."

## §8 Shared primitives — replace

> ✅ **c64-mlkem v0.5.0 (Phase 2, ML-KEM-768).** `mlkem-keccak.a` is n/a —
> Keccak has no multiply; both masks `0`, from its own manifest object (§6.4,
> see §6 below). `mlkem.a` is a **§8.1 `sqtab` consumer**: `.ifndef`-guarded `LIB_SHARED_SQTAB_BASE` header in one shared
> include (`src/sqtab_base.inc`, standalone default `$9000` — chosen
> page-aligned, clear of `$7800` / `$8000` / `$9C00` and of c64-https' baked
> `$B800` / `$BC00`, in RAM under every `$01` state, and outside the
> `$C000-$CFFF` range the fleet test harness claims), both §8.1 asserts,
> canonical `mul_tables_init` in owner builds, `.import` under
> `SHARED_SQTAB_INIT` (never a stub), `sqtab_lo/hi` and the base never
> exported, §6.7 image guard in the archive-free driver TU. Masks in the
> §8.0 conditional form: standalone `$0001 / $0001`, deferring `$0000 / $0001`.
> **§8.3 is deliberately not taken**: the NTT's 12×12→24 multiply uses a
> private `mlkem_`-prefixed body reading `sqtab` directly (no canonical
> name, no `poly_prod_*` / `smc_*` exports, bit `$0004` clear in both masks);
> reasoning in c64-mlkem `docs/contract-p2-alignment.md` §3. **§8.2 not
> taken**: no REU in P2. Measured masks from `od65` on the shipped manifest
> member: `mlkem.a` `$0001 / $0001`; with `-D SHARED_SQTAB_INIT`
> `$0000 / $0001`; `mlkem-keccak.a` `$0000 / $0000`. §6.7 guard proven to
> fire (`make check-sqtab-guard`: `-D LIB_SHARED_SQTAB_BASE=0x0900` fails the
> link on the guard's message; default links). The multiply that consumes the
> table costs ~330 cycles per NTT butterfly product and ~440 per general
> product; keygen+decaps measure 61.9M cycles, 65% of them Keccak.

## §8.0 Precalc tables enumerated — replace

> ✅ **v0.5.0.** `src/precalc_table.inc` copied byte-for-byte from this
> repo's root (cmp-verified), `.include`d from `src/lib_manifest.s` only.
> Three rows in `mlkem.a`, each landed in the same commit as its bytes and
> its `docs/precalc-tables.md` row; `od65 --dump-exports` on the shipped
> `mlkem_lib_manifest.o`:
> `LIB_MLKEM_PRECALC_sqtab_{SIZE,REGION,SHARED} = 1024, 1 (RAM), 1`;
> `LIB_MLKEM_PRECALC_mlkem_zetas_* = 256, 3 (RODATA), 0` (the 128 NTT
> twiddles, exactly at the floor, hot-loop-read);
> `LIB_MLKEM_PRECALC_mlkem_rtab_* = 1024, 1 (RAM), 0` (the mod-q reduction
> tables R1/R2, page-aligned BSS built at init — enumerated on the `sqtab`
> precedent, which is likewise built at init). Zero rows in `mlkem-keccak.a`.
> Resolved without rows: basemul zetas (derived at run time, 0 B), CBD_η=2
> lookup (32 B nibble tables), compress tables (108 B). No bare
> `LIB_PRECALC_*` export in either archive (`make check-prefix`).
> Only the `LIB_MLKEM_PRECALC_*` family is emitted: the manifest TU defines
> `LIB_NO_BARE_EXPORTS` before the include, keeping the library's export
> surface byte-identical with and without the consumer define (the §1
> zero-consumer stance applied to §8.4's bare triple). `make check-prefix`
> fails the build on any bare or foreign-prefixed export in a shipped archive.

## §6.4 manifest per member set — append

> `mlkem-keccak.a` (FIPS 202 only) ships its own manifest object, assembled
> with `-D MLKEM_KECCAK_ONLY=1` into a separate object directory by the
> `lib-keccak` target only: masks `0/0`, no §8.4 rows,
> `LIB_MLKEM_RESIDENT_BYTES = 1536` (1,477 B measured) against `mlkem.a`'s
> `6912` (6,719 B measured, 87.5% of the 7,680 B consumer window). The
> selector is **not** a §6.2 consumer knob: passing `MLKEM_KECCAK_ONLY` in
> `CONTRACT_DEFINES` is rejected at parse time (§6.3 rejection branch — no
> target can honor it build-wide without the full archive's manifest
> describing a member set it does not ship). `make check-archives` pins both
> manifests' values with `od65` on the extracted member; `make
> check-staleness` (now three knobs: ZP slot, `LIB_SHARED_SQTAB_BASE`,
> Keccak-only) pins that alternating `lib` / `lib-keccak` on a warm tree
> rebuilds nothing and overwrites neither. **Needs the user's sign-off as a
> row entry** (docs/contract-p2-alignment.md §7 item 4).

## §6.6 footprint — replace

> v0.5.0: `mlkem.a` 6,719 B code+rodata measured from a probe link of the
> shipped archive (5,694 + 1,025), declared 6912; `mlkem-keccak.a` 1,477 B
> (unchanged since v0.3.0), declared 1536; `COLD_BYTES` 0 in both; BSS 6,641
> B / 594 B. Delta v0.4.0 → v0.5.0: +5,242 B resident for the full archive,
> 0 for the Keccak-only one.

## §1/§8.4 prefixed exports — append

> `make check-prefix` (in `make test`) extracts every member of every shipped
> archive and rejects any export not under `mlkem_` / `LIB_MLKEM_` /
> `keccak_` or one of the exact §8 canonical names — the library-side guard
> against the #82/#83 consumer-link discovery class, needed because ML-KEM's
> reference naming (`poly_*`, `mul_*`, `ct_*`) collides with three registered
> prefixes.
