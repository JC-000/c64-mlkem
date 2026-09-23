#!/usr/bin/env python3
"""rig_common.py — the hardware half of the rig_*.py suites (U64E).

Imported by tools/rig_kat.py and tools/rig_bench.py; not a runnable rig
itself. Everything device-facing lives here so the two rigs cannot drift apart
on the part that is easy to get silently wrong.

WHY A MAILBOX AND NOT jsr()
---------------------------
The VICE suites call routines with the harness `jsr()`, which sets PC through
the binary monitor. The Ultimate has no CPU control (no PC, no registers, no
breakpoints), and the harness' cross-backend `run_subroutine` types `SYS` at a
BASIC prompt — but build/mlkem.prg never returns to BASIC: `start` runs the
§8.0/§8.1 table init, prints its banner and parks at `idle: jmp idle`.

So the rig installs a small dispatcher in RAM and redirects `idle` to it:

    DISP:  lda GO        ; host sets GO=1 after writing the thunk
           beq DISP
           jsr THUNK     ; the thunk is `jsr <target> ; rts`, or a bench window
           sta RES_A     ; A on return (mlkem_encaps' status)
           inc SEQ       ; SEQ first, THEN release GO: the host can
           lda #0        ; never see GO == 0 with SEQ not yet advanced
           sta GO
           jmp DISP

DISP is placed at the same LOW byte as `idle`, so the redirect is a ONE-byte
write of the jmp operand's high byte: whatever instant the DMA write lands, the
6510 either still runs `jmp idle` or already runs `jmp DISP` — never a jump
through a half-written address.

Completion is SEQ == seq0 + 1 AND GO == 0, read in ONE read_bytes. A liveness
call (an empty thunk) runs before anything else, so a dispatcher that never
took over is a FATAL at install time, not a timeout in the middle of a vector.

All device traffic goes through the harness funnel: write_bytes / read_bytes /
wait_for_text / run_prg_via_sys, plus the speed/state helpers that take the
client (config PUTs, no memory I/O). `make check-harness-routing` scans this
file with the rest of tools/.

MEASUREMENT HYGIENE
-------------------
Host reads of C64 RAM on the Ultimate are DMA, and they DO steal 6510
cycles: measured on the U64E (fw 3.15), Keccak x8 polled every 5 ms inside
its window read +1.6k-2.2k cycles, not reproducibly. So `call()` /
`run_thunk()` take `quiet_s`: no poll is issued until that long after GO is
set. rig_bench reports the effect on every run (informational, not gated).

Other builds: MLKEM_BUILD_DIR=<dir with mlkem.prg + labels.txt> runs the
rigs against that build (a mutant tree's build/, say) and skips `make`.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from c64_test_harness import (
    Labels, create_manager, read_bytes, write_bytes, wait_for_text,
    run_prg_via_sys,
)
from c64_test_harness.backends.ultimate64_helpers import (
    check_measurement_environment, get_turbo_mhz, restore_state,
    set_turbo_mhz, snapshot_state,
)

PROJECT_ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
# MLKEM_BUILD_DIR points the rigs at another build (a mutant tree's build/,
# say) without copying the tools; default is this tree's build/.
BUILD_DIR = os.environ.get("MLKEM_BUILD_DIR") or os.path.join(PROJECT_ROOT, "build")
PRG_PATH = os.path.join(BUILD_DIR, "mlkem.prg")
LABELS_PATH = os.path.join(BUILD_DIR, "labels.txt")
VECTOR_DIR = os.path.join(PROJECT_ROOT, "tools", "vectors")
PYTHON_VENV = "/Users/someone/Documents/c64-ChaCha20-Poly1305/.venv/bin/python3"

# The rig page: dispatcher, thunk and mailbox. Above the image (__MAIN_LAST__
# is checked against it), below the vector scratch at $5000.
RIG_PAGE = 0x4F00
THUNK = RIG_PAGE + 0x80         # up to 0x60 bytes of thunk
THUNK_MAX = 0x60
GO = RIG_PAGE + 0xF0
SEQ = RIG_PAGE + 0xF1
RES_A = RIG_PAGE + 0xF2

BANNER = "C64-MLKEM"


def jsr_bytes(addr):
    return bytes([0x20, addr & 0xFF, (addr >> 8) & 0xFF])


def dispatcher_code(disp):
    """The loop in the module docstring, assembled at `disp`."""
    code = bytes([0xAD, GO & 0xFF, GO >> 8,          # lda GO
                  0xF0, 0xFB])                       # beq disp (-5)
    code += jsr_bytes(THUNK)                         # jsr THUNK
    code += bytes([0x8D, RES_A & 0xFF, RES_A >> 8,   # sta RES_A
                   0xEE, SEQ & 0xFF, SEQ >> 8,       # inc SEQ
                   0xA9, 0x00,                       # lda #0
                   0x8D, GO & 0xFF, GO >> 8,         # sta GO
                   0x4C, disp & 0xFF, disp >> 8])    # jmp disp
    return code


class RigError(RuntimeError):
    pass


def build_if_needed():
    if os.environ.get("C64_SKIP_BUILD") or os.environ.get("MLKEM_BUILD_DIR"):
        return
    import subprocess
    r = subprocess.run(["make"], capture_output=True, cwd=PROJECT_ROOT)
    if r.returncode != 0:
        print(r.stderr.decode()[-2000:])
        raise RigError("build failed")


# Instruction lengths by 6502 addressing mode (documented opcodes), enough
# to walk mul_tables_init linearly.
def _oplen(op):
    a, b, c = op >> 5, (op >> 2) & 7, op & 3
    if c == 1:
        return 3 if b in (3, 6, 7) else 2
    if c == 2:
        return {0: 2, 1: 2, 3: 3, 5: 2, 7: 3}.get(b, 1)
    if c == 0:
        if op == 0x20:
            return 3
        if b == 0:
            return 2 if a >= 5 else 1
        return {1: 2, 3: 3, 4: 2, 5: 2, 7: 3}.get(b, 1)
    raise RigError(f"undocumented opcode ${op:02X} in mul_tables_init")


def read_prg():
    with open(PRG_PATH, "rb") as fh:
        prg = fh.read()
    return prg[0] | (prg[1] << 8), prg[2:]


def sqtab_extent(labels):
    """[base, base + size) of sqtab in THIS build.

    LIB_SHARED_SQTAB_BASE is deliberately never exported (contract §8.1),
    and a consumer may move it with CONTRACT_DEFINES, so it is read from
    the code that uses it: mul_tables_init's first two `sta abs,x` store
    to sqtab_lo and sqtab_hi (src/sqtab.s), sqtab_hi = sqtab_lo + $200.
    The size is the build's own §8.4 row (LIB_MLKEM_PRECALC_sqtab_SIZE)."""
    load, body = read_prg()
    pc = labels["mul_tables_init"]
    stores = []
    for _ in range(40):
        op = body[pc - load]
        n = _oplen(op)
        if op == 0x9D:
            stores.append(body[pc - load + 1] | (body[pc - load + 2] << 8))
            if len(stores) == 2:
                break
        if op == 0x60:
            break
        pc += n
    if len(stores) != 2 or stores[1] != stores[0] + 0x200:
        raise RigError(f"could not locate sqtab from mul_tables_init: stores {stores}")
    size = labels.address("LIB_MLKEM_PRECALC_sqtab_SIZE")
    if size is None:
        raise RigError("LIB_MLKEM_PRECALC_sqtab_SIZE missing from labels")
    return stores[0], stores[0] + size


def load_labels(scratch_lo, scratch_hi):
    """Labels, with the image-vs-scratch claim checked (CLAUDE.md: any
    harness scratch address is a claim about the image size), and neither
    the scratch nor the rig page overlapping this build's sqtab."""
    labels = Labels.from_file(LABELS_PATH)
    last = labels.address("__MAIN_LAST__")
    if last is None:
        raise RigError("__MAIN_LAST__ missing from build/labels.txt")
    lo = min(scratch_lo, RIG_PAGE)
    if last > lo:
        raise RigError(f"image ends at ${last:04X}, past the rig scratch "
                       f"${lo:04X}-${scratch_hi:04X}")
    sq_lo, sq_hi = sqtab_extent(labels)
    for name, a, b in (("scratch", scratch_lo, scratch_hi),
                       ("rig page", RIG_PAGE, RIG_PAGE + 0x100)):
        if a < sq_hi and sq_lo < b:
            raise RigError(f"{name} ${a:04X}-${b:04X} overlaps sqtab ${sq_lo:04X}-${sq_hi:04X}")
    print(f"  sqtab ${sq_lo:04X}-${sq_hi - 1:04X} (from mul_tables_init); "
          f"scratch ${scratch_lo:04X}-${scratch_hi - 1:04X}, rig page ${RIG_PAGE:04X}")
    return labels


class Rig:
    """One locked U64E session with build/mlkem.prg running under the
    dispatcher. Use as a context manager.

    mhz=1 is stock speed (and the measurement environment is checked);
    mhz=N>1 enables U64 turbo at N MHz. The device's speed/REU/cartridge
    state is snapshotted after acquire and restored on exit.
    """

    def __init__(self, labels, mhz=1, lock_timeout=1800.0):
        self.l = labels
        self.mhz = mhz
        self.lock_timeout = lock_timeout
        self.host = os.environ.get("U64_HOST")
        if not self.host:
            raise RigError("U64_HOST is not set (the bench U64E is 10.43.23.81)")
        self._mgr = self._ctx = self.target = self.t = None
        self.snap = None
        self.info = {}
        self._thunk = None
        self.restore_failed = False

    # --- session -----------------------------------------------------------

    def __enter__(self):
        self._mgr = create_manager(backend="u64", u64_hosts=self.host,
                                   lock_timeout=self.lock_timeout)
        self._mgr.__enter__()
        try:
            self._ctx = self._mgr.instance()
            self.target = self._ctx.__enter__()
            self.t = self.target.transport
            client = self.target.client
            self.info = client.get_info()
            self.snap = snapshot_state(client)
            print(f"U64: {self.info.get('product')} fw {self.info.get('firmware_version')} "
                  f"fpga {self.info.get('fpga_version')} core {self.info.get('core_version')}")
            print(f"  speed state at entry: CPU Speed={self.snap.cpu_speed!r} "
                  f"Turbo Control={self.snap.turbo_control!r} "
                  f"Badline Timing={self.snap.badline_timing!r}")
            if self.mhz == 1:
                set_turbo_mhz(client, None)          # Turbo Control = Off
                check_measurement_environment(client)
            else:
                set_turbo_mhz(client, self.mhz)
            eff = get_turbo_mhz(client)
            print(f"  speed state for this run: turbo {eff if eff else 'off'} "
                  f"(requested {self.mhz} MHz)")
            if self.mhz == 1 and eff not in (None, 1):
                raise RigError(f"turbo still reads {eff} MHz after disabling it")
            if self.mhz != 1 and eff != self.mhz:
                raise RigError(f"turbo reads {eff} MHz, requested {self.mhz}")
            self._boot()
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise
        return self

    def __exit__(self, *exc):
        try:
            if self.snap is not None and self.target is not None:
                restore_state(self.target.client, self.snap)
                s = snapshot_state(self.target.client)
                print(f"  speed state restored: CPU Speed={s.cpu_speed!r} "
                      f"Turbo Control={s.turbo_control!r}")
                if (s.cpu_speed, s.turbo_control) != (self.snap.cpu_speed, self.snap.turbo_control):
                    self.restore_failed = True
                    print("  ERROR: speed state did NOT restore to the entry snapshot "
                          f"(entry {self.snap.cpu_speed!r}/{self.snap.turbo_control!r})")
        finally:
            if self._ctx is not None:
                self._ctx.__exit__(*exc)
            if self._mgr is not None:
                self._mgr.__exit__(*exc)
        # A device left at a different speed poisons every later lane's
        # measurements: that is a failed run, not a warning. (With an
        # exception already in flight, that one propagates instead.)
        if self.restore_failed and exc[0] is None:
            raise RigError("device speed state was not restored to its entry snapshot")
        return False

    def _boot(self):
        with open(PRG_PATH, "rb") as fh:
            prg = fh.read()
        t0 = time.time()
        run_prg_via_sys(self.target, prg)
        if wait_for_text(self.t, BANNER, timeout=60.0, verbose=False) is None:
            raise RigError("banner did not appear after run_prg_via_sys")
        # The image in RAM must be THIS build: compare the Keccak round
        # constants (rodata, never written at runtime) with the PRG file.
        load, body = prg[0] | (prg[1] << 8), prg[2:]
        rc = self.l["keccak_rc"]
        want = body[rc - load:rc - load + 192]
        if len(want) != 192 or read_bytes(self.t, rc, 192) != want:
            raise RigError(f"keccak_rc at ${rc:04X} in C64 RAM differs from {PRG_PATH}")
        print(f"  PRG loaded and started: {PRG_PATH} ({len(prg)} B, {time.time() - t0:.1f}s)")
        self._install_dispatcher()

    def _install_dispatcher(self):
        idle = self.l["idle"]
        if read_bytes(self.t, idle, 3) != bytes([0x4C, idle & 0xFF, idle >> 8]):
            raise RigError(f"`idle` at ${idle:04X} is not `jmp idle`")
        disp = (RIG_PAGE & 0xFF00) | (idle & 0xFF)
        code = dispatcher_code(disp)
        if (disp & 0xFF) + len(code) > 0x80:
            raise RigError(f"dispatcher at ${disp:04X} would overrun the thunk")
        write_bytes(self.t, GO, bytes([0, 0, 0]))
        write_bytes(self.t, disp, code)
        write_bytes(self.t, THUNK, bytes([0x60]))
        self._thunk = bytes([0x60])
        if read_bytes(self.t, disp, len(code)) != code:
            raise RigError("dispatcher did not read back")
        # The one-byte redirect (see docstring).
        write_bytes(self.t, idle + 2, bytes([disp >> 8]))
        # Liveness: an empty thunk must complete, advancing SEQ by exactly one.
        seq0 = read_bytes(self.t, SEQ, 1)[0]
        self._go_and_wait(seq0, timeout=5.0, quiet_s=0.0, cadence=0.02)
        print(f"  dispatcher live at ${disp:04X} (idle ${idle:04X} redirected)")

    # --- calls -------------------------------------------------------------

    def _go_and_wait(self, seq0, timeout, quiet_s, cadence):
        write_bytes(self.t, GO, bytes([1]))
        t0 = time.monotonic()
        if quiet_s:
            time.sleep(quiet_s)
        while True:
            go, seq = read_bytes(self.t, GO, 2)
            if go == 0:
                if seq != (seq0 + 1) & 0xFF:
                    raise RigError(f"dispatcher SEQ {seq0} -> {seq}, expected one call")
                return time.monotonic() - t0
            if time.monotonic() - t0 > timeout:
                raise RigError(f"call did not complete in {timeout:.0f}s "
                               f"(GO={go}, SEQ={seq}, seq0={seq0})")
            time.sleep(cadence)

    def run_thunk(self, thunk, timeout=300.0, quiet_s=0.0, cadence=0.05):
        """Run `thunk` (must end in rts) once; return (A, wall seconds)."""
        if len(thunk) > THUNK_MAX or thunk[-1:] != b"\x60":
            raise RigError("bad thunk")
        seq0 = read_bytes(self.t, SEQ, 1)[0]
        # Nothing but this method writes the thunk area, so an unchanged
        # thunk is not re-sent (it halves the round trips of a KAT loop).
        if thunk != self._thunk:
            write_bytes(self.t, THUNK, thunk)
            if read_bytes(self.t, THUNK, len(thunk)) != thunk:
                raise RigError("thunk did not read back")
            self._thunk = thunk
        wall = self._go_and_wait(seq0, timeout, quiet_s, cadence)
        return read_bytes(self.t, RES_A, 1)[0], wall

    def call(self, label, timeout=300.0, quiet_s=0.0, cadence=0.05):
        """jsr <label> ; return A on return."""
        a, _ = self.run_thunk(jsr_bytes(self.l[label]) + b"\x60", timeout, quiet_s, cadence)
        return a

    def put(self, addr, data):
        write_bytes(self.t, addr, bytes(data))

    def get(self, addr, n):
        return read_bytes(self.t, addr, n)

    def ptr(self, label, addr):
        write_bytes(self.t, self.l[label], bytes([addr & 0xFF, addr >> 8]))
