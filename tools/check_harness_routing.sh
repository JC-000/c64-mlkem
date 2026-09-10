#!/usr/bin/env bash
# check-harness-routing: every byte this repo sends to a C64 (VICE or real
# hardware) MUST go through the c64-test-harness funnel — write_bytes /
# read_bytes / jsr / wait_for_text — never a raw transport, socket, or REST
# call from a tool. The harness is the SINGLE point that owns chunking
# (memory.py splits at 84 B, below the Ultimate's 128 B POST-leak boundary)
# and, on hardware, /Temp cleanup. A tool that calls transport.write_memory()
# directly, opens its own socket, or issues an HTTP/REST request bypasses that
# funnel and can wedge the shared C64U (fw 1.1.0) — see CLAUDE.md
# "Device I/O routing".
#
# This guard is deliberately a lexical grep, not a runtime check: it must fail
# the build the moment a bypass is ADDED, before it is ever pointed at a
# device. It is exact about what it forbids so it does not flag the legitimate
# `transport = inst.transport` handle-fetch, which passes the transport INTO
# the funnel functions rather than calling methods on it.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$ROOT/tools"

# Patterns that indicate a device request outside the harness funnel.
#   - .write_memory(/.read_memory(/.write_mem(/.read_mem(  : direct transport I/O
#   - requests. / urllib / http.client / \.connect(        : ad-hoc HTTP/socket
#   - import socket / from socket                           : raw sockets
#   - machine:writemem / /v1/                               : hand-rolled REST
BAD_RE='\.(write_memory|read_memory|write_mem|read_mem)\(|(^|[^_a-zA-Z])requests\.|urllib|http\.client|\.connect\(|(^|[^.])\bsocket\b|machine:writemem|/v1/'

# Only tool sources ship device traffic. The pure-Python oracle/model files
# (*_ref.py) and build helpers never touch a device, but scanning them too
# costs nothing and closes the "someone adds a socket to mlkem_ref" gap.
hits="$(grep -rnE "$BAD_RE" "$TOOLS"/*.py 2>/dev/null || true)"

if [ -n "$hits" ]; then
  echo "check-harness-routing: FAIL — device I/O that bypasses the harness funnel:" >&2
  echo "$hits" >&2
  echo >&2
  echo "Route every device read/write through write_bytes / read_bytes / jsr" >&2
  echo "(from c64_test_harness). They own chunking and hardware /Temp cleanup;" >&2
  echo "a direct transport/socket/REST call can wedge the shared C64U." >&2
  echo "See CLAUDE.md \"Device I/O routing\". If this is a deliberate, reviewed" >&2
  echo "exception, widen this guard's allow-list in the same commit." >&2
  exit 1
fi

echo "check-harness-routing: ok — all tool device I/O routes through the harness funnel"
