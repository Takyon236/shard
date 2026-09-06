# Example — a PHP template renderer that includes outside its root

**What it demonstrates:** `output_marker`, where the marker proves *execution* rather than disclosure.

**The defect:** `render.php` builds a path from a template name and `include`s it. `include` resolves
`..`; it does not refuse it. The code reads as though concatenating under `TEMPLATE_ROOT` is the
containment, and it never was.

This is the Node example's defect in a language where the consequence is worse. There, escaping the
directory *reads* a file. Here, it **executes** one.

## Run it by hand first

Needs `php` on your PATH. The action's container carries `php-cli`; if your machine does not have it,
this example is the one that will skip.

```bash
set -euo pipefail
cd examples/php-template-include

bash .shard/entry.sh /dev/null                            # silent, exit 0   <- the baseline
bash .shard/entry.sh .shard/entry.sh.benign/ordinary.txt  # silent, exit 0
bash .shard/entry.sh .shard/entry.sh.benign/missing.txt   # silent, exit 0

attack_input="$(mktemp)"
printf '../secrets\n' > "$attack_input"
bash .shard/entry.sh "$attack_input"                      # SHARD_TEMPLATE_ESCAPED_ROOT
rm -f -- "$attack_input"
```

## The decision worth copying: a sentinel that runs

`secrets.php` holds nothing secret. It is a file that **emits the marker when executed**, and it sits
beside the template directory rather than inside it. No template name that stays under the root can
reach it, so the marker means exactly one thing: a PHP file from outside the template root ran.

That is a stronger observation than "the include succeeded", which is what `render` does on every
benign input. It is also stronger than matching on file *contents*: this defect's consequence is
execution, so the witness observes execution.

## The control people forget

`missing.txt` names a template that does not exist. `include` emits a warning for it, and a warning in
the output would look like something the finding caused — so the witness silences PHP's error
reporting before it renders. A template name that does not resolve is the renderer working.

## Then point Shard at it

```bash
set -euo pipefail
shard survey --repo . --out-dir /tmp/shard-out
shard preflight --repo . --witness-entry .shard/entry.sh
```
