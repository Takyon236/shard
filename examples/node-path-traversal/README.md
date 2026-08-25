# Example — a Node note reader that leaves its own directory

**What it demonstrates:** `output_marker`, with a sentinel rather than an error.

**The defect:** `app.js` builds a path with `path.join(ROOT, name)` and reads it. `path.join`
*normalises* `..` — it collapses the segment and hands back a path outside `ROOT` — it does not refuse
it. The code reads as though the join is the containment, and it never was.

## Run it by hand first

Needs `node` on your PATH. The action's container carries node 22; locally, any recent version.

```bash
cd examples/node-path-traversal

bash .shard/entry.sh /dev/null                          # silent, exit 0   <- the baseline
bash .shard/entry.sh .shard/entry.sh.benign/ordinary.txt  # silent, exit 0
bash .shard/entry.sh .shard/entry.sh.benign/missing.txt   # silent, exit 0

printf '../secret.txt\n' > /tmp/attack.txt
bash .shard/entry.sh /tmp/attack.txt                    # SHARD_NOTE_PATH_ESCAPED
```

## The decision worth copying: watch the sentinel, not the success

`readNote` is *supposed* to read files. An entry point that fired whenever a read returned something
would fire on `ordinary` and `nested` too — Shard would reproduce the finding against those benign
controls and refuse it, which is the adjudicator working. So the marker means one narrow thing:
**content that exists only outside the notes directory came back out of a function whose whole job is
to stay inside it.**

`secret.txt` holds nothing sensitive. It is a sentinel, and choosing one is usually easier than
arranging for a crash — which is why `output_marker` is the kind most projects end up using.

## The payload is one line, on purpose

The agent controls the contents of the payload file and nothing else. Reading one narrow thing out of
it — here, a note name — keeps your own witness small enough to reason about. A witness you cannot
convince yourself is sound is one you should not be gating a build on.

## Then point Shard at it

```bash
shard survey --repo examples/node-path-traversal --out-dir /tmp/shard-out
shard preflight --repo examples/node-path-traversal --witness-entry .shard/entry.sh
```
