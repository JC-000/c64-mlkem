# =============================================================================
# c64-mlkem — Makefile
#
# Contract: c64-lib-contract SPEC 1.2.3 (../c64-lib-contract).
#
# §6.2 defines-forwarding. Both variables default empty and are ADDITIVE to
# CA65FLAGS — a hard-assigned CA65FLAGS that a consumer must clobber to inject
# one -D is non-conformant, because clobbering silently drops -t c64 and the
# include path.
#
#   CONTRACT_DEFINES      reaches EVERY archive-member recipe.
#                         e.g. make lib CONTRACT_DEFINES="-D LIB_NO_BARE_EXPORTS=1"
#
#   CONTRACT_ZP_DEFINES   reaches ONLY the ZP-defining TU (zp_config.o).
#                         §6.2 scoping rule: a slot define MUST reach every TU
#                         that DEFINES the slot and MUST NOT reach any TU that
#                         .importzp's it (that is a hard "Symbol already
#                         defined" error). c64-mlkem uses the consumer-assembled
#                         ZP model, so exactly one TU in this build defines
#                         slots and this variable is scoped to it.
#                         e.g. make CONTRACT_ZP_DEFINES="-D mlkem_zp_src=0x40"
#
# Values must be `$`-free — `0x40` or decimal, never `$40` (§2).
# =============================================================================

CA65  = ca65
LD65  = ld65
AR65  = ar65

# A failed recipe must not leave its target behind. ca65 writes the .o before
# it opens the .d, so a .d it cannot write (EACCES, ENOSPC) would otherwise
# leave a fresh .o with no .d: the retry exits 0 and later header edits never
# rebuild that object.
.DELETE_ON_ERROR:

CA65FLAGS          ?=
CONTRACT_DEFINES   ?=
CONTRACT_ZP_DEFINES ?=

# --- configuration invalidation (repo-local build hygiene) ------------------
#
# The defines above reach the ca65 command lines, but they are not prerequisites
# of anything, so over a WARM tree make sees no reason to rebuild and ships the
# previously-configured artifact with exit 0 and no diagnostic. Measured here
# before the fix: `make CONTRACT_ZP_DEFINES="-D mlkem_zp_src=0x40"` after a
# default build answered "Nothing to be done" and left the slot at $30. That is
# the chacha#86 shape. These knobs are invalidated, not rejected, because they
# are configuration the targets CAN honor.
#
# Fix: a stamp holds the configuration signature, compared at parse time. When
# it DIFFERS the stale objects are deleted outright, so:
#   - a changed knob invalidates every object (the artifact flips), and
#   - an unchanged knob touches nothing (no spurious rebuild).
#
# Deleting rather than making the objects depend on a stamp file is deliberate,
# and the obvious "simplification" back to a timestamp prerequisite silently
# reintroduces the bug on this platform. macOS ships **GNU Make 3.81**, whose
# mtime comparison has 1-second granularity: a stamp rewritten in the same
# second as the objects it should invalidate compares as not-newer, so nothing
# rebuilds. Measured here — stamp and object both at mtime 1787521864, content
# changed, zero ca65 invocations.
# Both properties matter. A guard which has quietly degraded to an
# unconditional rebuild still passes a check that only exercises the
# change-rebuilds leg, which is why `make check-staleness` asserts both.
# `deps1` names the build scheme, not a knob: object trees built before the
# ca65 .d files existed have objects and no .d, so a header edit there would
# still rebuild nothing. The changed signature wipes such a tree once.
CONFIG_SIG := deps1|$(CA65FLAGS)|$(CONTRACT_DEFINES)|$(CONTRACT_ZP_DEFINES)
CONFIG_STAMP = build/.config-sig

# Rejected, not invalidated. MLKEM_KECCAK_ONLY is not a consumer knob: it
# names the member set of mlkem-keccak.a and is set by the lib-keccak target
# itself, on its own manifest object (build/kobj). Reaching every archive
# member through CONTRACT_DEFINES is something no target here can honor — the
# full archive's manifest would then describe a member set it does not ship
# (§6.4) — so it is refused at parse time rather than silently producing a
# lying mlkem.a.
ifneq (,$(findstring MLKEM_KECCAK_ONLY,$(CONTRACT_DEFINES) $(CA65FLAGS)))
$(error MLKEM_KECCAK_ONLY is selected by `make lib-keccak`, not by CONTRACT_DEFINES: no target can honor it as a build-wide define (contract §6.4))
endif

# Run at PARSE time, deliberately — not from a recipe. By the time a recipe
# runs, make has already stat'd its targets and decided what is up to date;
# deleting the PRG from a recipe then leaves make convinced it still exists and
# the link is skipped, producing no output file at all (measured).
_ := $(shell \
  if [ -f build/.config-sig ] && [ "$$(cat build/.config-sig)" != '$(CONFIG_SIG)' ]; then \
    rm -rf build/obj build/tobj build/kobj build/lib build/mlkem.prg build/labels.txt build/mlkem.map build/mlkem-lib.prg build/mlkem-lib.map build/mlkem-keccak-lib.prg build/mlkem-keccak-lib.map; \
  fi; \
  mkdir -p build 2>/dev/null; printf '%s' '$(CONFIG_SIG)' > build/.config-sig)

SRC_DIR   = src
CFG_DIR   = cfg
TOOLS_DIR = tools
BUILD_DIR = build
LIB_DIR   = $(BUILD_DIR)/lib

CFG      = $(CFG_DIR)/mlkem.cfg
PRG      = $(BUILD_DIR)/mlkem.prg
LABELS   = $(BUILD_DIR)/labels.txt
MAPFILE  = $(BUILD_DIR)/mlkem.map

BASE_CA65FLAGS = -t c64 -I $(SRC_DIR) -g
ALL_CA65FLAGS  = $(BASE_CA65FLAGS) $(CA65FLAGS) $(CONTRACT_DEFINES)

# Python for the test tooling. The fleet's shared venv carries
# c64_test_harness (the system python3 does not), but fall back to plain
# python3 so a clone on any other machine still runs `make test-ref` — that
# target is pure stdlib and needs no harness.
FLEET_VENV := /Users/someone/Documents/c64-ChaCha20-Poly1305/.venv/bin/python3
PYTHON ?= $(shell [ -x $(FLEET_VENV) ] && echo $(FLEET_VENV) || command -v python3)

# --- object sets ------------------------------------------------------------
#
# TWO separately-configured object trees, which contract §6.4 requires: a
# manifest TU must be assembled under the same configuration as the archive it
# ships in. The standalone PRG is built with -D MLKEM_TEST_HOOKS=1 so the
# differential harness can reach the individual step functions; the archive is
# built WITHOUT it, so its export surface stays minimal and stable (§6.5 makes
# exported symbols contract surface). Sharing one .o tree between the two would
# silently ship test scaffolding in the archive.
# (comments on their own lines: make keeps the whitespace before a trailing
#  '#', so `FOO = bar   # note` sets FOO to "bar   " and every path built
#  from it breaks in a way the error message does not point at.)
# OBJ_DIR  = archive configuration
# TOBJ_DIR = standalone/test configuration
# KOBJ_DIR = the mlkem-keccak.a MANIFEST only (-D MLKEM_KECCAK_ONLY=1): §6.4
#            wants one manifest per member set, and a separate object path is
#            what keeps `make lib` and `make lib-keccak` from overwriting each
#            other's manifest on a warm tree (check-staleness pins that).
OBJ_DIR = $(BUILD_DIR)/obj
TOBJ_DIR = $(BUILD_DIR)/tobj
KOBJ_DIR = $(BUILD_DIR)/kobj

TEST_DEFINES = -D MLKEM_TEST_HOOKS=1

# Library sources — the members of build/lib/mlkem.a.
#   NOT included, deliberately:
#     main.s       driver — §6.1 forbids a driver object in an archive
#     bench.s      measurement harness, not library surface
#     zp_config.s  §6.2 consumer-assembled ZP model: no archive TU defines a
#                  slot; the consumer assembles src/zp_config.s themselves
#     sqtab.s      §8.1 mul_tables_init (owner build) / import (deferring)
#     ntt.s        P2 WP1: mod-3329 arithmetic, NTT/INTT/basemul, R tables
LIB_SRCS = lib_version lib_manifest state keccak sponge sqtab ntt $(WP2_SRCS) $(WP3_SRCS)

# P2 / WP2: samplers (SampleNTT, CBD) and codecs (ByteEncode/Decode12,
# Compress/Decompress). Listed once, here, so the archive and the test PRG
# cannot disagree about them.
WP2_SRCS = sample codec

# P2 / WP3: K-PKE and ML-KEM-768 KeyGen / Encaps / Decaps glue.
WP3_SRCS = kem

# The `lib-keccak` member set: the FIPS 202 surface (permutation + sponge)
# only. Diverged from LIB_SRCS at P2 WP1. Its manifest is a SEPARATE object
# (KOBJ_DIR, -D MLKEM_KECCAK_ONLY=1) so it carries neither the §8.0 sqtab
# masks nor the §8.4 rows — that member set never reads the table
# (docs/contract-p2-alignment.md §2.5; §6.4 forbids one manifest describing
# two member sets).
KECCAK_SRCS = lib_version state keccak sponge

# Driver-side sources: standalone PRG only.
DRIVER_SRCS = main bench zp_config

# Archive members carry the `<shortname>_` prefix (§6.5). That clause defers
# the rename to each library's next MAJOR because a member cannot hold two
# names at once — but c64-mlkem has no released consumers, so it can be born
# prefixed and skip the migration window entirely. It also keeps this library
# off the flat-namespace pile-up the clause is worried about: `lib_version.o`
# and `lib_manifest.o` still have four claimants, not five.
LIB_OBJS    = $(addprefix $(OBJ_DIR)/mlkem_, $(addsuffix .o,$(LIB_SRCS)))
KECCAK_OBJS = $(addprefix $(OBJ_DIR)/mlkem_, $(addsuffix .o,$(KECCAK_SRCS))) \
              $(KOBJ_DIR)/mlkem_lib_manifest.o

# Probe link of the SHIPPED archive (no test hooks): the driver objects plus
# mlkem.a, every public entry forced in with -u so ld65 pulls every member.
# Measures the footprint of the bytes a consumer actually links (§5) and
# proves the archive links on its own.
LIB_PROBE     = $(BUILD_DIR)/mlkem-lib.prg
LIB_PROBE_MAP = $(BUILD_DIR)/mlkem-lib.map
LIB_PROBE_PULL = -u mlkem_keygen -u mlkem_encaps -u mlkem_decaps -u LIB_MLKEM_RESIDENT_BYTES -u LIB_MLKEM_VERSION_MAJOR
DRIVER_OBJS = $(addprefix $(TOBJ_DIR)/, $(addsuffix .o,$(DRIVER_SRCS)))

# Probe link of the SHIPPED mlkem-keccak.a, for its own §5 figures (contract
# 1.2.3: the basis is the placed span in a real link, per archive — a subset
# sum of the mlkem.a probe's member sizes is the object-size basis 1.2.3
# forbids, and would miss any fill that member set places differently). The
# driver objects cannot link against it (main.o imports the KEM entry points),
# so the probe is the consumer-assembled zp_config.o plus the archive, with
# every member's public surface forced in; check_manifest.py fails if any
# member is left out. ld65 warns that LOADADDR/BASICSTUB do not exist —
# expected, no driver is linked.
LIB_PROBE_KECCAK      = $(BUILD_DIR)/mlkem-keccak-lib.prg
LIB_PROBE_KECCAK_MAP  = $(BUILD_DIR)/mlkem-keccak-lib.map
LIB_PROBE_KECCAK_PULL = -u mlkem_absorb -u mlkem_squeeze -u keccak_f1600 -u keccak_state -u LIB_MLKEM_RESIDENT_BYTES -u LIB_MLKEM_VERSION_MAJOR

# main.o MUST come first so `start` lands at $080D, matching SYS 2061.
LINK_OBJS = $(addprefix $(TOBJ_DIR)/, $(addsuffix .o,$(DRIVER_SRCS) $(LIB_SRCS)))

ARCHIVE        = $(LIB_DIR)/mlkem.a
ARCHIVE_KECCAK = $(LIB_DIR)/mlkem-keccak.a

.PHONY: all clean test test-ref test-vice test-sha3 test-sha3-full test-ntt test-ntt-full \
        test-sampler test-sampler-full test-mlkem test-mlkem-full test-mutants \
        bench bench-sampler bench-kem tables lib lib-keccak \
        check-manifest check-archives check-staleness check-prefix check-sqtab-guard \
        check-harness-routing check-precalc check-manifest-selftest check-precalc-selftest \
        check-deps check-deps-rebuild \
        vectors help rig rig-full rig-turbo

all: $(PRG)

# --- standalone PRG ---------------------------------------------------------

$(PRG): $(LINK_OBJS) $(CFG) | $(BUILD_DIR)
	$(LD65) -C $(CFG) -o $(PRG) -m $(MAPFILE) -Ln $(LABELS).raw $(LINK_OBJS)
	# The harness's Labels parser wants `al C:xxxxxx .name`; ld65 -Ln emits
	# `al xxxxxx .name`. Same rewrite as the sibling repos.
	sed 's/^al \([0-9a-fA-F]\{6\}\) /al C:\1 /' $(LABELS).raw > $(LABELS)
	@rm -f $(LABELS).raw
	@echo "built $(PRG)  (map: $(MAPFILE), labels: $(LABELS))"

# zp_config.o is the ONLY TU that defines ZP slots, so it is the only recipe
# that receives CONTRACT_ZP_DEFINES (§6.2 scoping rule: a slot define must
# reach every TU that DEFINES the slot and no TU that .importzp's it).
$(TOBJ_DIR)/zp_config.o: $(SRC_DIR)/zp_config.s | $(TOBJ_DIR)
	$(CA65) $(ALL_CA65FLAGS) $(TEST_DEFINES) $(CONTRACT_ZP_DEFINES) -o $@ $< --create-full-dep $(@:.o=.d)

$(TOBJ_DIR)/%.o: $(SRC_DIR)/%.s | $(TOBJ_DIR)
	$(CA65) $(ALL_CA65FLAGS) $(TEST_DEFINES) -o $@ $< --create-full-dep $(@:.o=.d)

$(OBJ_DIR)/mlkem_%.o: $(SRC_DIR)/%.s | $(OBJ_DIR)
	$(CA65) $(ALL_CA65FLAGS) -o $@ $< --create-full-dep $(@:.o=.d)

# The mlkem-keccak.a manifest: same source, same CONTRACT_DEFINES, plus the
# member-set selector. Nothing else is ever built into KOBJ_DIR.
$(KOBJ_DIR)/mlkem_lib_manifest.o: $(SRC_DIR)/lib_manifest.s | $(KOBJ_DIR)
	$(CA65) $(ALL_CA65FLAGS) -D MLKEM_KECCAK_ONLY=1 -o $@ $< --create-full-dep $(@:.o=.d)

# Header dependencies come from ca65 itself: every recipe above writes
# --create-full-dep next to its object, listing every file that TU included
# (nested includes too: constants.s pulls in sqtab_base.inc everywhere; the
# §8.4 precalc_table.inc reaches the manifest TUs only). The .d files are
# written as a side effect of assembling and nothing here can make one, so
# they never trigger a make restart or a rebuild of their own. ca65 also
# emits an empty rule per header, so deleting a header does not break a warm
# tree. Before the first build there is no .d, and no object either.
# Each .d lives in its object's tree, so the configuration guard's rm -rf of
# obj/tobj/kobj removes it together with the object: a .d assembled under
# another configuration can never be included.
-include $(wildcard $(OBJ_DIR)/*.d $(TOBJ_DIR)/*.d $(KOBJ_DIR)/*.d)

$(OBJ_DIR) $(TOBJ_DIR) $(KOBJ_DIR):
	@mkdir -p $@

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(LIB_DIR):
	@mkdir -p $(LIB_DIR) $(LIB_DIR)/cfg

# --- §6.1 archives ----------------------------------------------------------

SHIPPED = $(LIB_DIR)/mlkem.inc $(LIB_DIR)/zp_config.s $(LIB_DIR)/sqtab_base.inc $(LIB_DIR)/cfg/mlkem-example.cfg

# mlkem.a IS the ML-KEM archive: K-PKE/ML-KEM cannot be separated from the
# sponge it hashes with, so HANDOFF-P2's "mlkem-kem.a alongside" would be a
# byte-identical second name for it. Recorded in README as a divergence; no
# `lib-kem` target.
lib: $(ARCHIVE) $(SHIPPED)
	@echo "§6.1 archive: $(ARCHIVE)"

lib-keccak: $(ARCHIVE_KECCAK) $(SHIPPED)
	@echo "§6.1 archive: $(ARCHIVE_KECCAK)"

$(LIB_PROBE): $(ARCHIVE) $(DRIVER_OBJS) $(CFG)
	$(LD65) -C $(CFG) $(LIB_PROBE_PULL) -o $@ -m $(LIB_PROBE_MAP) $(DRIVER_OBJS) $(ARCHIVE)

$(LIB_PROBE_KECCAK): $(ARCHIVE_KECCAK) $(TOBJ_DIR)/zp_config.o $(CFG)
	$(LD65) -C $(CFG) $(LIB_PROBE_KECCAK_PULL) -o $@ -m $(LIB_PROBE_KECCAK_MAP) $(TOBJ_DIR)/zp_config.o $(ARCHIVE_KECCAK)

$(ARCHIVE): $(LIB_OBJS) | $(LIB_DIR)
	@rm -f $@
	$(AR65) r $@ $(LIB_OBJS)

$(ARCHIVE_KECCAK): $(KECCAK_OBJS) | $(LIB_DIR)
	@rm -f $@
	$(AR65) r $@ $(KECCAK_OBJS)

# Shipped alongside every archive: the public header, the consumer-assembled
# ZP source (§6.2), the §8.1 placement header (a consumer needs
# LIB_SHARED_SQTAB_BASE for its own image guard, and the header is the ONLY
# place the default lives), and the starter cfg fragment (§4).
$(LIB_DIR)/mlkem.inc: $(SRC_DIR)/mlkem.inc | $(LIB_DIR)
	@cp $< $@
$(LIB_DIR)/zp_config.s: $(SRC_DIR)/zp_config.s | $(LIB_DIR)
	@cp $< $@
$(LIB_DIR)/sqtab_base.inc: $(SRC_DIR)/sqtab_base.inc | $(LIB_DIR)
	@cp $< $@
$(LIB_DIR)/cfg/mlkem-example.cfg: $(CFG_DIR)/mlkem-example.cfg | $(LIB_DIR)
	@cp $< $@

# --- checks (§6.1: the lib/lib-* namespace is reserved for archives) --------

# (a) no driver/harness object ever lands in an archive (§6.1);
# (b) each archive's manifest describes ITS member set (§6.4): mlkem.a carries
#     the §8.0 sqtab bits and the three §8.4 rows, mlkem-keccak.a carries
#     neither. Read from the extracted member with od65 — od65 on an archive
#     prints nothing and exits 0.
check-archives: lib lib-keccak
	@fail=0; \
	for a in $(ARCHIVE) $(ARCHIVE_KECCAK); do \
	  for bad in main.o bench.o zp_config.o mlkem_main.o mlkem_bench.o mlkem_zp_config.o; do \
	    if $(AR65) t $$a 2>/dev/null | grep -qx "$$bad"; then \
	      echo "FAIL: $$bad is a member of $$a (contract §6.1)"; fail=1; fi; \
	  done; \
	done; \
	[ $$fail -eq 0 ] && echo "check-archives: OK (no driver objects in any archive)"
	@$(TOOLS_DIR)/check_archive_manifest.sh $(ARCHIVE) 1 1 7424 3
	@$(TOOLS_DIR)/check_archive_manifest.sh $(ARCHIVE_KECCAK) 0 0 2048 0

# Repo-local configuration invalidation, both legs. Leg 1 alone is not a
# test: a guard that has degraded to an unconditional rebuild passes it. Leg 2
# is what catches that.
check-staleness:
	@$(TOOLS_DIR)/check_staleness.sh

# Every exported symbol in every shipped archive is under mlkem_ / LIB_MLKEM_ /
# keccak_ or is one of the exact §8 canonical names the contract makes
# normative. Extracts members first — od65 cannot read archives (§8.4).
#
# Rebuilds the archives through a sub-make rather than listing them as
# prerequisites: check-staleness wipes build/ mid-run, and in one invocation
# `make check-staleness check-prefix` (the order `test` uses) would otherwise
# find make already satisfied that the archives exist.
check-prefix:
	@$(MAKE) --no-print-directory lib lib-keccak >/dev/null
	@$(TOOLS_DIR)/check_prefix.sh

# Contract §5 (1.2.3): each footprint equate a shipped archive's manifest
# declares must be >= the PLACED SPAN of the segments it covers in a probe
# link of THAT archive (internal alignment fill charged; gaps between and
# padding before the segments not charged). Both member sets, each against its
# own manifest member. Fails on an unsafe value; refresh safe-direction (>=
# measured, rounded UP to the next 256-byte boundary).
check-manifest: $(PRG) $(LIB_PROBE) $(LIB_PROBE_KECCAK)
	@$(PYTHON) $(TOOLS_DIR)/check_manifest.py --test-map $(MAPFILE) \
	    --probe mlkem.a $(ARCHIVE) $(LIB_PROBE_MAP) \
	    --probe mlkem-keccak.a $(ARCHIVE_KECCAK) $(LIB_PROBE_KECCAK_MAP)

# §8.4: src/precalc_table.inc is a byte-for-byte copy of the contract's root
# precalc_table.inc at a PINNED contract tag, read from the contract repo's
# git objects — not the moving origin/HEAD (an upstream comment edit must not
# turn this repo red) and not its working tree (any branch). A missing
# contract checkout or ref FAILS rather than skipping. CONTRACT_DIR defaults
# to the sibling of the MAIN checkout (via the git common dir), so it resolves
# from a git worktree too.
CONTRACT_DIR ?= $(abspath $(shell git rev-parse --path-format=absolute --git-common-dir 2>/dev/null)/../../c64-lib-contract)
# Move this pin deliberately, when adopting a new contract tag.
CONTRACT_PRECALC_REF ?= v1.2.2
check-precalc:
	@$(TOOLS_DIR)/check_precalc.sh "$(CONTRACT_DIR)" "$(CONTRACT_PRECALC_REF)"

# Self-tests of the two checkers above, on hermetic fixtures (seconds, no
# VICE, no build tree). A checker nobody tests can be switched off by a
# one-line edit: each case names the mutant class it kills. The manifest
# self-test also guards the WIRING — that `test:` still depends on
# check-manifest, check-precalc and both self-tests, and that check-manifest
# still probes both archives.
check-manifest-selftest:
	@$(PYTHON) $(TOOLS_DIR)/test_check_manifest.py
check-precalc-selftest:
	@$(TOOLS_DIR)/test_check_precalc.sh

# Repo-local: the sqtab image guard must be PROVEN to fire. Builds once with
# the sqtab window deliberately inside the image and requires the link to
# fail, then restores the default configuration.
check-sqtab-guard:
	@$(TOOLS_DIR)/check_sqtab_guard.sh

# Every device read/write in tools/ must go through the c64-test-harness
# funnel (write_bytes/read_bytes/jsr), the single point that owns chunking and
# hardware /Temp cleanup. Fails the build if a tool adds a direct
# transport/socket/REST call that would bypass it and could wedge the C64U.
# Pure grep, no build inputs, so it runs standalone and inside `test`.
check-harness-routing:
	@$(TOOLS_DIR)/check_harness_routing.sh

# Header dependencies: an edited header must invalidate every object whose TU
# includes it, in every object tree (tobj / obj / kobj), and an unchanged tree
# must rebuild nothing. Without that, a value edit on a warm tree answers
# "Nothing to be done" and ships stale objects (measured: SHAKE128_RATE
# 168 -> 136 in src/constants.s, warm PRG != clean PRG at byte 1685).
# Both run in a scratch COPY of the working tree, never in build/, and take
# the include graph from ca65 --create-full-dep on the exact command lines
# make runs — not from this file's text.
#   check-deps          asks make (-n) which objects a newer header would
#                       re-assemble; names `object -> missing header`. Seconds.
#   check-deps-rebuild  per header: warm build, value edit, incremental make,
#                       == clean build of the edited tree (images byte-exact,
#                       objects/members by od65 dump); a second make runs no
#                       ca65/ld65/ar65. ~10 s, no VICE.
check-deps:
	@$(PYTHON) $(TOOLS_DIR)/check_deps.py -q
check-deps-rebuild:
	@$(PYTHON) $(TOOLS_DIR)/check_deps_rebuild.py

# --- tests ------------------------------------------------------------------

# Oracle self-tests, pure Python, no VICE: tools/keccak_ref.py against the
# XKCP published intermediate values and the NIST CAVP vectors, then
# tools/mlkem_ref.py against the NIST ACVP ML-KEM-768 vectors and
# cryptography.hazmat. Both must be green before any 6502 comparison means
# anything.
test-ref: vectors
	@$(PYTHON) $(TOOLS_DIR)/test_keccak_ref.py
	@$(PYTHON) $(TOOLS_DIR)/test_mlkem_ref.py

# Differential test of the 6502 permutation against the validated model,
# single-stepping every round. Needs VICE + c64-test-harness.
test-vice: $(PRG)
	@C64_SKIP_BUILD=1 $(PYTHON) $(TOOLS_DIR)/test_keccak.py

# FIPS 202 KATs for the sponge layer: NIST CAVP vectors plus the streaming
# properties no published vector covers. --full runs all 820 ShortMsg vectors.
test-sha3: $(PRG)
	@C64_SKIP_BUILD=1 $(PYTHON) $(TOOLS_DIR)/test_sha3.py

test-sha3-full: $(PRG)
	@C64_SKIP_BUILD=1 $(PYTHON) $(TOOLS_DIR)/test_sha3.py --full

# P2 / WP1: mod-3329 arithmetic and NTT against tools/mlkem_ref.py, per layer
# (red-first: tools/test_ntt.py documents the assumed ABI at its top). Not yet
# part of `test`; the supervisor adds it at the WP1 merge.
test-ntt: $(PRG)
	@C64_SKIP_BUILD=1 $(PYTHON) $(TOOLS_DIR)/test_ntt.py

test-ntt-full: $(PRG)
	@C64_SKIP_BUILD=1 $(PYTHON) $(TOOLS_DIR)/test_ntt.py --full

# Mutation gate: every tools/mutants/*.patch must turn its named test red.
# Works in build/mutants/<name>/ copies; a survivor exits nonzero.
test-mutants:
	@$(PYTHON) $(TOOLS_DIR)/mutate.py --manifest $(TOOLS_DIR)/mutants/manifest.json
# WP2 samplers and codecs: SampleNTT over the live SHAKE128 stream, CBD,
# ByteEncode/Decode12, Compress/Decompress against tools/mlkem_ref.py.
# RED until WP2 lands. --full sweeps every compress input and every
# encode/decode position.
test-sampler: $(PRG)
	@C64_SKIP_BUILD=1 $(PYTHON) $(TOOLS_DIR)/test_sampler.py

test-sampler-full: $(PRG)
	@C64_SKIP_BUILD=1 $(PYTHON) $(TOOLS_DIR)/test_sampler.py --full

# WP3 K-PKE + ML-KEM-768 KeyGen/Encaps/Decaps against ACVP, hazmat and
# tools/mlkem_ref.py, plus the constant-time decaps check (red-first:
# tools/test_mlkem.py documents the assumed ABI and parameter block at its
# top). RED until WP3 lands. Not in `test` yet; the supervisor adds it at the
# WP3 merge. --full runs every ACVP vector (~150 calls of 10-40M cycles).
MLKEM_ARGS ?=

test-mlkem: $(PRG)
	@C64_SKIP_BUILD=1 $(PYTHON) $(TOOLS_DIR)/test_mlkem.py $(MLKEM_ARGS)

test-mlkem-full: $(PRG)
	@C64_SKIP_BUILD=1 $(PYTHON) $(TOOLS_DIR)/test_mlkem.py --full

# Full suite: oracle self-test, the VICE differential trace, the KATs,
# contract checks.
# The VICE suites run first on the PRG `make` just built; the two checks
# that wipe and rebuild build/ (check-staleness, check-sqtab-guard) run after
# them, and check-prefix last (it rebuilds the archives through a sub-make).
test: test-ref test-vice test-sha3 test-ntt test-sampler test-mlkem check-manifest check-archives check-staleness check-sqtab-guard check-prefix check-harness-routing check-precalc check-manifest-selftest check-precalc-selftest check-deps check-deps-rebuild
	@echo "test: OK"

# Cycle-exact measurement. Calibrates the CIA1 TA+TB instrument against a
# routine of known cost and refuses to report a Keccak number if that fails.
bench: $(PRG)
	@C64_SKIP_BUILD=1 $(PYTHON) $(TOOLS_DIR)/bench_keccak.py

# WP2 samplers/codecs: cycles per routine with the same calibrated instrument,
# plus a constant-time check (four inputs each must measure identically).
bench-sampler: $(PRG)
	@C64_SKIP_BUILD=1 $(PYTHON) $(TOOLS_DIR)/bench_sampler.py

# WP4: KeyGen / Encaps / Decaps and the NTT primitives, same instrument, same
# calibration refusal, with the Keccak share separated out (permutation count
# from the model x the permutation cost measured in the same link).
bench-kem: $(PRG)
	@C64_SKIP_BUILD=1 $(PYTHON) $(TOOLS_DIR)/bench_kem.py

# --- hardware rigs (U64E; NOT part of `test` -- CI has no hardware) --------
# tools/rig_*.py drive the real machine through the harness DeviceLock and
# the write_bytes/read_bytes funnel (tools/rig_common.py). `rig` is the default
# depth at stock 1 MHz: KATs, then the cycle counts, which must equal VICE's
# exactly, plus the decaps constant-time pin. `rig-full` runs rig_kat --full
# at 1 MHz (~50 min: all SHA-3 ShortMsg, all ACVP keyGen/encaps/decaps/
# key-check vectors, the one-bit ciphertexts; NOT test_sha3's streaming
# properties or test_mlkem's hazmat/hooks/timing suites), then the counts.
# `rig-turbo` runs the same
# --full set with U64 turbo on and reports what the CIA counts mean there;
# the entry speed state is snapshotted and restored. The rigs were proven
# against the gate's wp3-cmp-mismatch-timing (rig_bench fails T1) and
# wp3-cmp-acc-reset (rig_kat onebit fails) mutants on the U64E at 1 MHz.
U64_HOST ?= 10.43.23.81
RIG_MHZ ?= 48

rig: $(PRG)
	@C64_SKIP_BUILD=1 U64_HOST=$(U64_HOST) $(PYTHON) $(TOOLS_DIR)/rig_kat.py
	@C64_SKIP_BUILD=1 U64_HOST=$(U64_HOST) $(PYTHON) $(TOOLS_DIR)/rig_bench.py

rig-full: $(PRG)
	@C64_SKIP_BUILD=1 U64_HOST=$(U64_HOST) $(PYTHON) $(TOOLS_DIR)/rig_kat.py --full
	@C64_SKIP_BUILD=1 U64_HOST=$(U64_HOST) $(PYTHON) $(TOOLS_DIR)/rig_bench.py

rig-turbo: $(PRG)
	@C64_SKIP_BUILD=1 U64_HOST=$(U64_HOST) $(PYTHON) $(TOOLS_DIR)/rig_kat.py --full --mhz $(RIG_MHZ)
	@C64_SKIP_BUILD=1 U64_HOST=$(U64_HOST) $(PYTHON) $(TOOLS_DIR)/rig_bench.py --mhz $(RIG_MHZ)

# Regenerate the rho/pi/RC tables and the ML-KEM zeta/gamma/reduction
# constants from the validated models.
tables:
	$(PYTHON) $(TOOLS_DIR)/gen_tables.py > $(SRC_DIR)/keccak_tables.inc
	$(PYTHON) $(TOOLS_DIR)/gen_tables.py --mlkem > $(SRC_DIR)/mlkem_tables.inc

vectors:
	@$(TOOLS_DIR)/fetch_vectors.sh

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "make              standalone test PRG -> $(PRG)"
	@echo "make lib          $(ARCHIVE)"
	@echo "make lib-keccak   $(ARCHIVE_KECCAK)"
	@echo "make test         full suite (oracles, every VICE suite, contract checks)"
	@echo "make test-ref     oracle self-tests, Keccak + ML-KEM (Python only, no VICE)"
	@echo "make test-vice    per-step differential trace under VICE"
	@echo "make test-sha3    FIPS 202 KATs (add -full for all 820 vectors)"
	@echo "make test-ntt     WP1 NTT/field tests in VICE (add -full for the sweep)"
	@echo "make test-mutants mutation gate over tools/mutants/manifest.json"
	@echo "make test-sampler WP2 samplers/codecs vs mlkem_ref.py (add -full to sweep)"
	@echo "make test-mlkem   WP3 K-PKE/ML-KEM KATs + hazmat + CT decaps in VICE (add -full)"
	@echo "make bench        cycle-exact Keccak-f[1600] measurement"
	@echo "make bench-sampler  WP2 sampler/codec cycles + constant-time check"
	@echo "make bench-kem    KeyGen/Encaps/Decaps + NTT cycles, Keccak share separated"
	@echo "make rig         U64E hardware: KATs + cycle counts vs VICE at 1 MHz (U64_HOST=...)"
	@echo "make rig-full    U64E hardware: rig_kat --full at 1 MHz, then the cycle counts"
	@echo "make rig-turbo   U64E hardware: every vector at RIG_MHZ turbo (default 48)"
	@echo "make tables       regenerate src/keccak_tables.inc + src/mlkem_tables.inc"
	@echo "make check-manifest  §5 footprint equates >= placed span, both archives"
	@echo "make check-precalc   src/precalc_table.inc == the contract's at CONTRACT_PRECALC_REF (§8.4)"
	@echo "make check-manifest-selftest  check_manifest.py + test: wiring vs doctored fixtures"
	@echo "make check-precalc-selftest   check_precalc.sh vs a throwaway contract repo"
	@echo "make check-archives  no driver objects (§6.1); per-archive manifest values (§6.4)"
	@echo "make check-staleness config invalidation, both legs, on the ZP, sqtab-base and Keccak-only knobs"
	@echo "make check-sqtab-guard  the sqtab image guard fires on a deliberate overrun"
	@echo "make check-prefix every archive export under a permitted prefix"
	@echo "make check-deps   every include is a prerequisite of its object, as make resolves it"
	@echo "make check-deps-rebuild  per header: value edit + incremental make == clean build; no-op make rebuilds nothing"
	@echo "make vectors      fetch NIST CAVP LongMsg vectors (ACVP ML-KEM sets are tracked)"
	@echo "make clean"
