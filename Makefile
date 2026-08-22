# =============================================================================
# c64-mlkem — Makefile
#
# Contract: c64-lib-contract SPEC v0.10.6 (../c64-lib-contract, tag v0.10.6).
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

CA65FLAGS          ?=
CONTRACT_DEFINES   ?=
CONTRACT_ZP_DEFINES ?=

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
OBJ_DIR = $(BUILD_DIR)/obj
TOBJ_DIR = $(BUILD_DIR)/tobj

TEST_DEFINES = -D MLKEM_TEST_HOOKS=1

# Library sources — the members of build/lib/mlkem.a.
#   NOT included, deliberately:
#     main.s       driver — §6.1 forbids a driver object in an archive
#     bench.s      measurement harness, not library surface
#     zp_config.s  §6.2 consumer-assembled ZP model: no archive TU defines a
#                  slot; the consumer assembles src/zp_config.s themselves
LIB_SRCS = lib_version lib_manifest state keccak

# The narrowed `lib-keccak` member set. Identical to LIB_SRCS today; they
# diverge in Phase 2 when the sponge layer lands as its own TU.
KECCAK_SRCS = $(LIB_SRCS)

# Driver-side sources: standalone PRG only.
DRIVER_SRCS = main bench zp_config

LIB_OBJS    = $(addprefix $(OBJ_DIR)/,  $(addsuffix .o,$(LIB_SRCS)))
KECCAK_OBJS = $(addprefix $(OBJ_DIR)/,  $(addsuffix .o,$(KECCAK_SRCS)))

# main.o MUST come first so `start` lands at $080D, matching SYS 2061.
LINK_OBJS = $(addprefix $(TOBJ_DIR)/, $(addsuffix .o,$(DRIVER_SRCS) $(LIB_SRCS)))

ARCHIVE        = $(LIB_DIR)/mlkem.a
ARCHIVE_KECCAK = $(LIB_DIR)/mlkem-keccak.a

.PHONY: all clean test test-ref test-vice bench tables lib lib-keccak \
        check-manifest check-archives vectors help

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
	$(CA65) $(ALL_CA65FLAGS) $(TEST_DEFINES) $(CONTRACT_ZP_DEFINES) -o $@ $<

$(TOBJ_DIR)/%.o: $(SRC_DIR)/%.s | $(TOBJ_DIR)
	$(CA65) $(ALL_CA65FLAGS) $(TEST_DEFINES) -o $@ $<

$(OBJ_DIR)/keccak.o $(TOBJ_DIR)/keccak.o: $(SRC_DIR)/keccak_tables.inc

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.s | $(OBJ_DIR)
	$(CA65) $(ALL_CA65FLAGS) -o $@ $<

$(OBJ_DIR) $(TOBJ_DIR):
	@mkdir -p $@

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(LIB_DIR):
	@mkdir -p $(LIB_DIR) $(LIB_DIR)/cfg

# --- §6.1 archives ----------------------------------------------------------

lib: $(ARCHIVE) $(LIB_DIR)/mlkem.inc $(LIB_DIR)/zp_config.s $(LIB_DIR)/cfg/mlkem-example.cfg
	@echo "§6.1 archive: $(ARCHIVE)"

lib-keccak: $(ARCHIVE_KECCAK) $(LIB_DIR)/mlkem.inc $(LIB_DIR)/zp_config.s $(LIB_DIR)/cfg/mlkem-example.cfg
	@echo "§6.1 archive: $(ARCHIVE_KECCAK)"

$(ARCHIVE): $(LIB_OBJS) | $(LIB_DIR)
	@rm -f $@
	$(AR65) r $@ $(LIB_OBJS)

$(ARCHIVE_KECCAK): $(KECCAK_OBJS) | $(LIB_DIR)
	@rm -f $@
	$(AR65) r $@ $(KECCAK_OBJS)

# Shipped alongside every archive: the public header, the consumer-assembled
# ZP source (§6.2), and the starter cfg fragment (§4).
$(LIB_DIR)/mlkem.inc: $(SRC_DIR)/mlkem.inc | $(LIB_DIR)
	@cp $< $@
$(LIB_DIR)/zp_config.s: $(SRC_DIR)/zp_config.s | $(LIB_DIR)
	@cp $< $@
$(LIB_DIR)/cfg/mlkem-example.cfg: $(CFG_DIR)/mlkem-example.cfg | $(LIB_DIR)
	@cp $< $@

# --- checks (§6.1: the lib/lib-* namespace is reserved for archives) --------

# Fails if a driver/harness object ever lands in an archive.
check-archives: lib lib-keccak
	@fail=0; \
	for a in $(ARCHIVE) $(ARCHIVE_KECCAK); do \
	  for bad in main.o bench.o zp_config.o; do \
	    if $(AR65) t $$a 2>/dev/null | grep -qx "$$bad"; then \
	      echo "FAIL: $$bad is a member of $$a (contract §6.1)"; fail=1; fi; \
	  done; \
	done; \
	[ $$fail -eq 0 ] && echo "check-archives: OK (no driver objects in any archive)"

# Reports measured segment sizes so the §5 footprint equates can be refreshed
# safe-direction (>= measured, rounded UP to the next 256-byte boundary).
check-manifest: $(PRG)
	@$(PYTHON) $(TOOLS_DIR)/check_manifest.py $(MAPFILE) $(SRC_DIR)/lib_manifest.s

# --- tests ------------------------------------------------------------------

# Oracle self-test: validates tools/keccak_ref.py against the XKCP published
# intermediate values and the NIST CAVP vectors. Pure Python, no VICE.
test-ref: vectors
	@$(PYTHON) $(TOOLS_DIR)/test_keccak_ref.py

# Differential test of the 6502 permutation against the validated model,
# single-stepping every round. Needs VICE + c64-test-harness.
test-vice: $(PRG)
	@C64_SKIP_BUILD=1 $(PYTHON) $(TOOLS_DIR)/test_keccak.py

# Full suite: oracle self-test, the VICE differential trace, contract checks.
test: test-ref test-vice check-archives
	@echo "test: OK"

# Cycle-exact measurement. Calibrates the CIA1 TA+TB instrument against a
# routine of known cost and refuses to report a Keccak number if that fails.
bench: $(PRG)
	@C64_SKIP_BUILD=1 $(PYTHON) $(TOOLS_DIR)/bench_keccak.py

# Regenerate the rho/pi/RC tables from the validated model.
tables:
	$(PYTHON) $(TOOLS_DIR)/gen_tables.py > $(SRC_DIR)/keccak_tables.inc

vectors:
	@$(TOOLS_DIR)/fetch_vectors.sh

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "make              standalone test PRG -> $(PRG)"
	@echo "make lib          $(ARCHIVE)"
	@echo "make lib-keccak   $(ARCHIVE_KECCAK)"
	@echo "make test         full suite (test-ref + contract checks)"
	@echo "make test-ref     oracle self-test (Python only, no VICE)"
	@echo "make test-vice    per-step differential trace under VICE"
	@echo "make bench        cycle-exact Keccak-f[1600] measurement"
	@echo "make tables       regenerate src/keccak_tables.inc"
	@echo "make check-manifest  measured sizes vs §5 footprint equates"
	@echo "make check-archives  no driver objects in archives (§6.1)"
	@echo "make vectors      fetch NIST CAVP LongMsg vectors"
	@echo "make clean"
