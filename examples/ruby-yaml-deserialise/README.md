# Example — a Ruby session store that deserialises objects

**What it demonstrates:** `output_marker`, on a type check rather than an error.

**The defect:** `store.rb` restores sessions with `YAML.unsafe_load`. That is a change people make for
a reason: Psych 4 made `YAML.load` refuse anything but plain data, so a codebase with real objects in
its sessions breaks on upgrade, and `unsafe_load` is the one word that makes the error go away. It
also restores object construction from attacker-controlled text.

## Run it by hand first

Needs `ruby` on your PATH. The action's container carries it.

```bash
set -euo pipefail
cd examples/ruby-yaml-deserialise

bash .shard/entry.sh /dev/null                            # silent, exit 0   <- the baseline
bash .shard/entry.sh .shard/entry.sh.benign/ordinary.yml  # silent, exit 0
bash .shard/entry.sh .shard/entry.sh.benign/malformed.yml # silent, exit 0

attack_input="$(mktemp)"
printf -- '--- !ruby/object:Gem::Requirement\n  requirements: []\n' > "$attack_input"
bash .shard/entry.sh "$attack_input"                      # SHARD_SESSION_OBJECT_CONSTRUCTED
rm -f -- "$attack_input"
```

## Not every `!ruby/object:` tag constructs something

`--- !ruby/object:Struct` deserialises to **nil**. A witness checked only against that payload observes
nothing and looks broken when it is perfectly sound — which is how the first draft of this example was
written, and the test suite is what said so.

The lesson generalises past Ruby: **when your witness does not fire, the payload is as likely to be
wrong as the witness.** Check both before you conclude anything, and keep a payload you have seen work.

## The decision worth copying: check the type, not the error

`load_session` is *supposed* to parse. An entry point that fired whenever a document loaded would fire
on `.shard/entry.sh.benign/ordinary.yml` too, Shard would reproduce the finding against the benign controls beside it, and
refuse it — the adjudicator working. So the marker means one narrow thing: **the document caused an
object to be constructed, in a format that is documented to be plain data.**

`.shard/entry.sh.benign/malformed.yml` is the third control, and it is the one people forget. A safe loader raises
`Psych::DisallowedClass` on a dangerous document, and "the program raised" is not a demonstration —
it is the defence working.

## Then point Shard at it

```bash
set -euo pipefail
shard survey --repo . --out-dir /tmp/shard-out
shard preflight --repo . --witness-entry .shard/entry.sh
```
