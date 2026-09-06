---
name: False positive
about: Shard reported a finding that is not a real defect
title: ''
labels: false-positive
assignees: ''
---

<!--
This is one of the most useful reports you can send, and it is not a complaint.

Shard separates informational hypotheses from demonstrated findings, which carry an input that
reproduces the observation. When a demonstrated finding is wrong, the interesting question is which
half failed: the reproduction did not really reproduce, or it did and the thing it reproduced is not
a defect. Those have completely different fixes, and the evidence below is what tells them apart.
-->

## The finding

<!-- Paste the finding from the report — the rule id, the title, and the
     location it was filed against. -->

```
```

## Why it is not a defect

<!--
The most useful sentence you can write. For example:

  - "That path is unreachable — `validate()` two frames up rejects the input."
  - "That is deliberate; the caller is trusted and documented as such."
  - "The crash is in the test harness, not in the library."
-->

## Was it gate-eligible?

<!--
The report says. This is the single most important field in the whole issue.

  - "gate-eligible"  -> Shard claims it EXECUTED something that reproduced the
                        defect. If that is wrong, the adjudicator is wrong, and
                        that is a serious bug we want to fix urgently.
  - not gate-eligible -> Shard reported it as an unproven hypothesis. Still worth
                        reporting if it was noise, but it is a different and much
                        less severe problem.
-->

- [ ] Gate-eligible (Shard says it reproduced this)
- [ ] Not gate-eligible (reported as a hypothesis)

## The finding bundle

<!--
If Shard wrote a bundle, its `metadata.json` says whether the witness reproduced
the finding. A gate-eligible finding must have `reproduced: true`; a refused
candidate bundle may say false. If you can share it, attach it or paste
`metadata.json` and `output.txt`.

ONLY IF YOU MAY. Do not paste code, crash data or credentials you do not have the
right to share. A description of the shape of the input is genuinely useful on
its own, and we would rather have that than put you in a difficult position.
-->

## Environment

- Shard version / ref:
- Action mode (`survey` or `diff`), or CLI command (`preflight`):
- Model endpoint and model:
- Language and, if relevant, the build system:
