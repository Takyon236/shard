<!--
Thank you for contributing. The three headings below are what a reviewer reads
first, so filling them in makes the review faster for you as well as for us.

If this is a work in progress, open it as a draft and say what you would like
help with — an early draft with a question is welcome and is not a failed PR.
-->

## What this changes

<!-- One or two sentences. What behaviour is different after this merges? -->

## Why

<!--
Link the issue if there is one. If this fixes a defect, describe the case that
was wrong: what input, what Shard did, what it should have done.
-->

## Evidence

<!--
This is the section that matters most in this project, so it is worth a moment.

Shard's whole claim is that it reports a finding only when it can attach an input
that reproduces it, and we hold changes to the same standard. Paste the thing you
ran and what it printed.

  - a fixed bug        -> the failing case, before and after
  - a performance claim -> the two numbers and how you measured them
  - a new behaviour     -> the run that exercises it

"This should be better" is not reviewable, and we will only end up asking.
-->

```
```

## Checklist

- [ ] There is a **deterministic test** — no network, no model calls — that
      covers this change.
- [ ] **I broke my own fix and watched the test fail.** A test that stays green
      when the code is wrong is measuring something else.
- [ ] `python -m pytest -q` passes.
- [ ] `python -m ruff check shard/` is clean.
- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md) and signed the CLA (the
      bot will link it on your first pull request).

<!--
NOT a security report. If this pull request fixes a vulnerability in Shard
itself, please stop and read SECURITY.md first — a public pull request discloses
the issue to everyone the moment it is opened.
-->
