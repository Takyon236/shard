#!/usr/bin/env bash
# Shard witness entry point. Declare this file as `witness_entry` in your workflow.
#
# THE CONTRACT
#   Shard runs:  bash -- .shard/entry.sh <payload-file>
#   Shard supplies the payload's CONTENT. It never writes this file — a witness the agent
#   authors and is graded on is not evidence, which is why this is yours to commit.
#
# THE DEMONSTRATION THIS ONE CLAIMS
#   output_marker, on SHARD_SETTINGS_ARBITRARY_CODE. See .shard/witness.py for what has to
#   happen before that string is printed, and for why "eval ran" would have been the wrong
#   thing to watch.
#
# CHECK IT YOURSELF BEFORE YOU TRUST IT — both directions, and the second is the one people skip:
#   bash .shard/entry.sh /dev/null                        # silent, exit 0
#   bash .shard/entry.sh .shard/entry.sh.benign/ordinary.conf   # silent, exit 0
#   printf 'x = __import__("os")\n' > /tmp/attack.conf
#   bash .shard/entry.sh /tmp/attack.conf                 # prints the marker
set -u
PAYLOAD="${1:-/dev/null}"

# The baseline branch. Shard runs this entry point on an empty payload and compares, so a script that
# prints its marker no matter what it is given demonstrates nothing and is correctly refused.
if [ ! -s "$PAYLOAD" ]; then
  exit 0
fi

# ABSOLUTE BEFORE `cd`, because the two lines below would otherwise disagree about where the payload
# is. Shard passes an absolute path; a person testing this by hand passes a relative one, and an entry
# point that only works for one of them is one nobody can check.
PAYLOAD="$(cd "$(dirname "$PAYLOAD")" && pwd)/$(basename "$PAYLOAD")"

# `cd` to the project root so the witness imports THIS checkout rather than anything installed. `exec`
# so the interpreter is this process and its exit status reaches the adjudicator unchanged.
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 3
exec python3 .shard/witness.py "$PAYLOAD" 2>&1
