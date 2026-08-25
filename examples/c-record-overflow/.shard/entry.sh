#!/usr/bin/env bash
# Shard witness entry point. Declare this file as `witness_entry` in your workflow.
#
# THE CONTRACT
#   Shard runs:  bash -- .shard/entry.sh <payload-file>
#   Shard supplies the payload's CONTENT. It never writes this file — a witness the agent
#   authors and is graded on is not evidence, which is why this is yours to commit.
#
# THE DEMONSTRATION THIS ONE CLAIMS
#   fatal_signal. AddressSanitizer detects the overflow and, because of the ASAN_OPTIONS below,
#   aborts — so the process dies on SIGABRT rather than exiting 1.
#
# ASAN_OPTIONS=abort_on_error=1 IS LOAD-BEARING, not tuning. ASAN's default is to print its report
# and call exit(1), and an exit of 1 is indistinguishable from this program rejecting the input.
# Without this line the only observation available is "it exited non-zero", which this build does
# not adjudicate — so a real, detected memory-safety defect would produce nothing that gates.
#
# BUILDING HERE IS THE EXCEPTION, NOT THE PATTERN. This container carries gcc and g++, so a small
# self-contained witness can compile itself. Anything with a real build — a JDK, a .NET SDK, a
# package manager — belongs in an earlier workflow step, because none of those is in this image and
# a build that cannot run fails QUIETLY: every finding stays a hypothesis and nothing says why.
#
# CHECK IT YOURSELF BEFORE YOU TRUST IT:
#   bash .shard/entry.sh /dev/null                             # silent, exit 0
#   bash .shard/entry.sh .shard/entry.sh.benign/short.rec      # silent, exit 0
#   printf '400\nhi\n' > /tmp/attack.rec
#   bash .shard/entry.sh /tmp/attack.rec                       # AddressSanitizer report, dies on a signal
set -u
PAYLOAD="${1:-/dev/null}"

if [ ! -s "$PAYLOAD" ]; then
  exit 0
fi

PAYLOAD="$(cd "$(dirname "$PAYLOAD")" && pwd)/$(basename "$PAYLOAD")"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$HERE/record"

# Rebuild when the binary is missing or older than the source. A stale build makes every line number
# in a report a lie, which is worse than no report.
if [ ! -x "$BIN" ] || [ "$HERE/record.c" -nt "$BIN" ]; then
  if ! cc -O1 -g -fsanitize=address -fno-omit-frame-pointer -o "$BIN" "$HERE/record.c" >&2; then
    # EXIT 3, NOT 1. A build failure is this entry point being broken, not the program under test
    # misbehaving, and the two must not look alike to whatever reads the result.
    echo "entry.sh: build failed — is a C compiler on PATH?" >&2
    exit 3
  fi
fi

# `exec` so the binary IS this process: the signal it dies on reaches the adjudicator unchanged. A
# wrapper that ran it as a child and returned its own status would turn a signal into an ordinary exit
# and silently break `fatal_signal`.
export ASAN_OPTIONS=abort_on_error=1
exec "$BIN" "$PAYLOAD"
