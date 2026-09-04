#!/usr/bin/env bash
# Shard witness entry point. Declare this file as `witness_entry` in your workflow.
#
# THE CONTRACT
#   Shard runs:  bash -- .shard/entry.sh <payload-file>
#   Shard supplies the payload's CONTENT. It never writes this file — a witness the agent
#   authors and is graded on is not evidence, which is why this is yours to commit.
#
# THE PAYLOAD HERE IS A NOTE NAME, one line. That is a choice worth making deliberately: the agent
# controls the content of this file and nothing else, so the narrower the thing you read out of it,
# the easier your own witness is to reason about.
#
# THE DEMONSTRATION THIS ONE CLAIMS
#   output_marker, on SHARD_NOTE_PATH_ESCAPED. See .shard/witness.js.
#
# CHECK IT YOURSELF BEFORE YOU TRUST IT:
#   bash .shard/entry.sh /dev/null                            # silent, exit 0
#   bash .shard/entry.sh .shard/entry.sh.benign/ordinary.txt  # silent, exit 0
#   printf '../secret.txt\n' > /tmp/attack.txt
#   bash .shard/entry.sh /tmp/attack.txt                      # prints the marker
set -u
PAYLOAD="${1:-/dev/null}"

if [ ! -s "$PAYLOAD" ]; then
  exit 0
fi

PAYLOAD="$(cd "$(dirname "$PAYLOAD")" && pwd)/$(basename "$PAYLOAD")"
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 3

# `exec` so node is this process and its exit status reaches the adjudicator unchanged. `2>&1` so a
# stack trace lands where the observation is read rather than in a stream nobody keeps.
exec node .shard/witness.js "$PAYLOAD" 2>&1
