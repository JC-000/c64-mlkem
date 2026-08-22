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

# Shared venv interpreter — the system python3 lacks c64_test_harness.
PYTHON ?= /Users/someone/Documents/c64-ChaCha20-Poly1305/.venv/bin/python3

# --- object sets ------------------------------------------------------------
#
# LIB_OBJS: what ships in build/lib/mlkem.a.
#   NOT included, deliberately:
#     main.o       driver — §6.1 forbids a driver object in an archive
#     bench.o      measurement harness, not library surface
#     zp_config.o  §6.2 consumer-assembled ZP model: no archive TU defines a
#                  slot; the consumer assembles src/zp_config.s themselves
LIB_OBJS = $(BUILD_DIR)/lib_version.o \
           $(BUILD_DIR)/lib_manifest.o \
           $(BUILD_DIR)/state.o

# KECCAK_OBJS: the narrowed `lib-keccak` member set. Identical to LIB_OBJS in
# Phase 0 (there is no sponge code yet to leave out); they diverge in Phase 2
# when the sponge layer lands as its own TU.
KECCAK_OBJS = $(LIB_OBJS)

# Driver-side objects: linked into the standalone PRG only.
DRIVER_OBJS = $(BUILD_DIR)/main.o \
              $(BUILD_DIR)/bench.o \
              $(BUILD_DIR)/zp_config.o

# main.o MUST come first so `start` lands at $080D, matching SYS 2061.
LINK_OBJS = $(BUILD_DIR)/main.o \
            $(BUILD_DIR)/bench.o \
            $(BUILD_DIR)/zp_config.o \
            $(LIB_OBJS)

ARCHIVE        = $(LIB_DIR)/mlkem.a
ARCHIVE_KECCAK = $(LIB_DIR)/mlkem-keccak.a

.PHONY: all clean test test-ref bench lib lib-keccak \
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
# that receives CONTRACT_ZP_DEFINES (§6.2 scoping rule).
$(BUILD_DIR)/zp_config.o: $(SRC_DIR)/zp_config.s | $(BUILD_DIR)
	$(CA65) $(ALL_CA65FLAGS) $(CONTRACT_ZP_DEFINES) -o $@ $<

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.s | $(BUILD_DIR)
	$(CA65) $(ALL_CA65FLAGS) -o $@ $<

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

# Full suite. Phase 0 has no 6502 crypto yet, so this is test-ref plus the
# contract checks; the VICE KAT driver lands in Phase 1.
test: test-ref check-archives
	@echo "test: OK"

bench: $(PRG)
	@echo "bench: Phase 4 target — calibrates bench_spin_1000 (1287 cycles)"
	@echo "       then measures Keccak-f[1600]. Not wired up until Phase 1 lands."

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
	@echo "make check-manifest  measured sizes vs §5 footprint equates"
	@echo "make check-archives  no driver objects in archives (§6.1)"
	@echo "make vectors      fetch NIST CAVP LongMsg vectors"
	@echo "make clean"
