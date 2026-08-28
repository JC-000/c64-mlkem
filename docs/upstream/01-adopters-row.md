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

> ⚠️ **in flight (Phase 2)**. P1 (v0.4.0) is n/a — Keccak has no multiply;
> both masks `0`. P2 (ML-KEM-768 NTT) makes the library a **§8.1 `sqtab`
> consumer**: `.ifndef`-guarded `LIB_SHARED_SQTAB_BASE` header in one shared
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
> taken**: no REU in P2. Row to be refreshed to ✅ at the P2 tag.

## §8.0 Precalc tables enumerated — replace

> ✅ shipped for P1 (no table clears the floor; zero `LIB_PRECALC_*`
> exports). **P2 (pending):** `src/precalc_table.inc` copied byte-for-byte
> from this repo's root (cmp-verified), `.include`d from `src/lib_manifest.s`
> only. Planned rows, each landing in the same commit as its bytes and its
> `docs/precalc-tables.md` row: `"sqtab"` 1024 / RAM / SHARED_YES (§8.1
> mandatory, name normative) and `"mlkem_zetas"` 256 / RODATA / SHARED_NO
> (the 128 NTT twiddles, exactly at the floor, hot-loop-read). Conditional
> rows if the implementation tabulates them: a basemul-zeta table, a
> page-aligned reduction aid, a CBD_η=2 lookup — all algorithm-specific.
> Only the `LIB_MLKEM_PRECALC_*` family is emitted: the manifest TU defines
> `LIB_NO_BARE_EXPORTS` before the include, keeping the library's export
> surface byte-identical with and without the consumer define (the §1
> zero-consumer stance applied to §8.4's bare triple). `make check-prefix`
> fails the build on any bare or foreign-prefixed export in a shipped archive.

## §1/§8.4 prefixed exports — append

> `make check-prefix` (in `make test`) extracts every member of every shipped
> archive and rejects any export not under `mlkem_` / `LIB_MLKEM_` /
> `keccak_` or one of the exact §8 canonical names — the library-side guard
> against the #82/#83 consumer-link discovery class, needed because ML-KEM's
> reference naming (`poly_*`, `mul_*`, `ct_*`) collides with three registered
> prefixes.
