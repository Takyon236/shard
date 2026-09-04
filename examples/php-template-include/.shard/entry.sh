#!/usr/bin/env bash
# Shard witness entry point. Declare this file as `witness_entry` in your workflow.
#
# THE CONTRACT
#   Shard runs:  bash -- .shard/entry.sh <payload-file>
#   Shard supplies the payload's CONTENT. It never writes this file — a witness the agent
#   authors and is graded on is not evidence, which is why this is yours to commit.
#
# THE PAYLOAD HERE IS A TEMPLATE NAME, one line. The agent controls the content of this file and
# nothing else, so reading one narrow thing out of it keeps the witness small enough to reason about.
#
# THE DEMONSTRATION THIS ONE CLAIMS
#   output_marker, on SHARD_TEMPLATE_ESCAPED_ROOT. See .shard/witness.php.
#
# CHECK IT YOURSELF BEFORE YOU TRUST IT:
#   bash .shard/entry.sh /dev/null                            # silent, exit 0
#   bash .shard/entry.sh .shard/entry.sh.benign/ordinary.txt  # silent, exit 0
#   printf '../secrets\n' > /tmp/attack.txt
#   bash .shard/entry.sh /tmp/attack.txt                      # prints the marker
set -u
PAYLOAD="${1:-/dev/null}"

if [ ! -s "$PAYLOAD" ]; then
  exit 0
fi

PAYLOAD="$(cd "$(dirname "$PAYLOAD")" && pwd)/$(basename "$PAYLOAD")"
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 3

# `exec` so php is this process and its exit status reaches the adjudicator unchanged.
exec php .shard/witness.php "$PAYLOAD" 2>&1
