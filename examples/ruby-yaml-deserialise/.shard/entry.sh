#!/usr/bin/env bash
# Shard witness entry point. Declare this file as `witness_entry` in your workflow.
#
# THE CONTRACT
#   Shard runs:  bash -- .shard/entry.sh <payload-file>
#   Shard supplies the payload's CONTENT. It never writes this file — a witness the agent
#   authors and is graded on is not evidence, which is why this is yours to commit.
#
# THE DEMONSTRATION THIS ONE CLAIMS
#   output_marker, on SHARD_SESSION_OBJECT_CONSTRUCTED. See .shard/witness.rb.
#
# CHECK IT YOURSELF BEFORE YOU TRUST IT:
#   bash .shard/entry.sh /dev/null                            # silent, exit 0
#   bash .shard/entry.sh .shard/entry.sh.benign/ordinary.yml  # silent, exit 0
#   printf -- '--- !ruby/object:Gem::Requirement\n  requirements: []\n' > /tmp/attack.yml
#   bash .shard/entry.sh /tmp/attack.yml                      # prints the marker
#
# NOT every `!ruby/object:` tag constructs something. `!ruby/object:Struct` deserialises to nil, so a
# witness checked against THAT payload observes nothing and looks broken when it is not — which is
# how the first draft of this example was written. Name a class that really instantiates.
set -u
PAYLOAD="${1:-/dev/null}"

if [ ! -s "$PAYLOAD" ]; then
  exit 0
fi

PAYLOAD="$(cd "$(dirname "$PAYLOAD")" && pwd)/$(basename "$PAYLOAD")"
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 3

# `exec` so ruby is this process and its exit status reaches the adjudicator unchanged.
exec ruby .shard/witness.rb "$PAYLOAD" 2>&1
