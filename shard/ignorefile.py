"""`.gitignore` semantics, in the walk, with no subprocess and no third-party dependency.

## Why this exists, and what it cost to find

a measured run.1. Run against a real working checkout, `survey` emitted **200
candidates and not one of them was in the customer's source.** All 200 came from
`.claude/worktrees/`, which that repository gitignores, and which held 139 MB of duplicated snapshots
of the same files. `preflight` on the same tree reported **28,674 files and 305 MB against a truth of
260 files and 6.5 MB**, and named seven languages — C, C++, Java, Kotlin, Swift, Ruby, Python — that
are not in the repository at all.

Two separate walks were wrong in two different ways and neither was noticed, because both produce a
plausible number:

- `survey.survey_repo` pruned `GENERATED_DIRS`, a fixed list. `node_modules` is on it; `.claude` is
  not, and no fixed list can be.
- `target.profile_repo` pruned only `_VCS_DIRS`, so it walked `node_modules` too.

The failure is worse than wasted budget. `to_payload` caps the candidate list at 200, and the walk
reaches `.claude` before `apps/` and `src/`, so **the cap was spent before the first line of customer
code**, and the paths reported did not exist in the repository under review.

## Why a parser rather than `git check-ignore`

`survey_repo`'s contract is *"Static only — no inference, no network, no subprocess."* That line is
load-bearing: the survey runs on a customer's checkout in their CI, and shelling out would make the
scan depend on a git binary being present and on what it does with a repository we do not own. So the
rules are parsed here, from the files themselves, with `re` and nothing else.

The subset implemented is the one that decides real checkouts: comments and blanks, `!` negation,
trailing `/` for directory-only, a leading or embedded `/` for anchoring, `*` / `?` / `[...]` within a
path segment, and `**` spanning segments. Per-directory `.gitignore` files nest, and a deeper file
wins, because that is how git resolves them.

**Not implemented, deliberately, and each would be a silent wrong answer if faked:** `.git/info/exclude`,
`core.excludesFile`, and the rule that a negation cannot re-include a file inside an ignored
directory — that last one we get for free, because an ignored directory is PRUNED and never descended,
which is also what makes this cheap.

## The fail-safe direction

Every failure path here returns "not ignored". A `.gitignore` that cannot be read, a pattern that does
not compile, a path that does not resolve — all of them mean the file gets SURVEYED. Scanning
something we could have skipped costs budget; skipping something we should have scanned is a missed
finding reported as a clean result, and this repository already has a section about instruments that
fail towards a comfortable number.

## AND A TRACKED FILE IS NEVER IGNORED, whatever the patterns say

**`.gitignore` has no effect on a file git already tracks**, and the first version of this module did
not know that. It is not a corner: the ordinary way a repository acquires the case is that somebody
commits a file and adds a pattern covering it LATER — `build/` after a generated bundle is checked in,
`*.min.js` after a vendored library, a `config.js` that shipped before it was templated. Git keeps
tracking all of them, `actions/checkout` writes them into the CI checkout, they are in the artefact the
customer ships, and this walk skipped them.

Measured on a two-commit fixture: git tracked two `.js` files and both walks saw ONE. That is the
under-scan direction — a missed finding reported as a clean result — and it is worse than the
over-scanning defect this module was created to fix, because over-scanning is visible in the candidate
list and this is visible nowhere.

So the tracked set is read from `.git/index` and OVERRIDES the patterns. Still no subprocess: the index
is parsed here, from bytes, with `struct`. When it cannot be read — no `.git` at all, a version 4 index,
a truncated one — the answer is pattern-only and `tracked_basis` says so, because a walk that quietly
changes which question it answered is the kind of instrument this file's header is about.
"""

from __future__ import annotations

import pathlib
import re
import struct
from typing import NamedTuple

__all__ = ["IgnoreIndex"]

#: Always pruned, whatever the repository says, and NOT a substitute for the parser above. These are
#: agent and tool scratch directories that are conventionally ignored but need not be: a checkout that
#: forgot to ignore `.claude/` still must not have an agent's duplicated worktrees surveyed as if they
#: were source. Kept deliberately short — a fixed list is what failed before, so it covers only
#: directories whose contents are BY CONSTRUCTION a copy or a cache of something else.
ALWAYS_PRUNE = frozenset({".claude", ".git", ".hg", ".svn"})


#: Index formats this parser reads. **Version 4 is refused rather than guessed at**: it prefix-compresses
#: every path against the previous entry, so a parser that does not implement that decoding produces
#: plausible-looking truncated names — the worst possible failure, because the answer would be wrong
#: rather than absent. v2 is what git writes by default and v3 adds only an extended-flag word.
_INDEX_VERSIONS = frozenset({2, 3})

#: Above this many entries the tracked set is not built. A ceiling because this is held in memory on the
#: customer's runner beside everything else the run needs, and 500,000 tracked files is already an order
#: of magnitude past the largest repository anyone has pointed this at. Refusing loudly (`tracked_basis`
#: says why) beats an OOM on a machine we do not own.
_INDEX_ENTRY_CAP = 500_000

#: Bytes before the path in a v2 entry: two 8-byte timestamps, six 4-byte fields, a 20-byte object id and
#: a 2-byte flags word.
_INDEX_FIXED = 62


class _GitIndex(NamedTuple):
    """What `.git/index` said, or why it said nothing.

    `dirs` holds every ancestor of every tracked file, so a directory an ignore rule would prune can be
    recognised as one that still contains tracked source — a pruned directory is never descended, so the
    decision about the directory is final for everything under it.

    **`basis` and `refusal` are exclusive and exactly one is set.** `refusal` exists because a bare
    "unavailable" made two of the guards below UNKILLABLE: a version 4 index and an over-cap one both
    fail the all-or-nothing parse further down anyway, so removing their checks changed no observable
    output and no test could tell the difference. Naming the reason fixes that AND is the better sentence
    for the customer — *"your index is version 4, which this walk does not read"* is actionable where
    *"no git index was readable"* is both vaguer and, in that case, false.
    """

    files: frozenset[str]
    dirs: frozenset[str]
    basis: str
    refusal: str


def _read_git_index(root: pathlib.Path) -> _GitIndex:
    """Every path git TRACKS, or nothing at all and the reason why.

    **Partial answers are refused.** A truncated or unrecognised index returns the empty set rather than
    the entries read so far: a half-populated tracked set would rescue some files and silently drop the
    rest, which is indistinguishable from working correctly. All-or-nothing means the caller's fallback
    is the well-understood pattern-only behaviour instead of an arbitrary subset of it.
    """
    def no(why: str) -> _GitIndex:
        return _GitIndex(frozenset(), frozenset(), "", why)

    try:
        blob = (root / ".git" / "index").read_bytes()
    except OSError:
        # No `.git` — a tarball export, a `docker build` context, a workdir copy that excluded it.
        return no("no .git/index is present, so nothing here knows what git tracks")
    if len(blob) < 12 or blob[:4] != b"DIRC":
        return no(".git/index is not in the format this walk reads")
    version, count = struct.unpack(">II", blob[4:12])
    if version not in _INDEX_VERSIONS:
        return no(f".git/index is version {version}, which this walk does not read — versions "
                  f"{'/'.join(str(v) for v in sorted(_INDEX_VERSIONS))} only")
    if count > _INDEX_ENTRY_CAP:
        return no(f".git/index lists {count:,} paths, above the {_INDEX_ENTRY_CAP:,} this walk will "
                  f"hold in memory")

    files: set[str] = set()
    dirs: set[str] = set()
    off, size = 12, len(blob)
    for _ in range(count):
        if off + _INDEX_FIXED > size:
            return no(".git/index ends mid-entry, so no part of it is trusted")
        flags = struct.unpack(">H", blob[off + 60:off + 62])[0]
        at = off + _INDEX_FIXED
        if version >= 3 and flags & 0x4000:      # the extended-flags word, when present
            at += 2
        length = flags & 0x0FFF
        if length < 0x0FFF:
            end = at + length
        else:
            # 0xFFF means "longer than this field can say"; the name runs to its terminator.
            end = blob.find(b"\x00", at)
        if end == -1 or end > size:
            return no(".git/index holds a path this walk could not read to its end")
        name = blob[at:end].decode("utf-8", errors="replace")
        if not name:
            return no(".git/index holds an empty path, so it is not being read correctly")
        files.add(name)
        parts = name.split("/")
        for depth in range(1, len(parts)):
            dirs.add("/".join(parts[:depth]))
        # Entries are NUL-padded to a multiple of eight bytes, with at least one NUL.
        used = end - off
        off += (used // 8 + 1) * 8
    return _GitIndex(frozenset(files), frozenset(dirs),
                     f"git index ({len(files):,} tracked path(s))", "")


class _Rule:
    """One compiled `.gitignore` line."""

    __slots__ = ("regex", "negated", "dir_only")

    def __init__(self, regex: re.Pattern[str], negated: bool, dir_only: bool) -> None:
        self.regex = regex
        self.negated = negated
        self.dir_only = dir_only


def _translate(pattern: str) -> str:
    """Glob to regex, one path segment at a time.

    Written by hand rather than with `fnmatch.translate` because `fnmatch`'s `*` matches `/`, and in a
    gitignore it must not: `src/*.js` names files directly in `src`, and letting `*` cross a separator
    would silently ignore the whole subtree.
    """
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern.startswith("**", i):
                # `**` spans separators. `a/**/b` must also match `a/b`, so the trailing slash is
                # folded into the optional group rather than required after it.
                i += 2
                if pattern.startswith("/", i):
                    out.append("(?:.*/)?")
                    i += 1
                else:
                    out.append(".*")
            else:
                out.append("[^/]*")
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            close = pattern.find("]", i + 1)
            if close == -1:
                out.append(re.escape(c))
                i += 1
            else:
                body = pattern[i + 1:close]
                body = body.replace("\\", "\\\\")
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append(f"[{body}]")
                i = close + 1
        else:
            out.append(re.escape(c))
            i += 1
    return "".join(out)


def _compile(line: str) -> _Rule | None:
    """One raw line to a rule, or None when the line selects nothing."""
    if not line or line.startswith("#"):
        return None
    # Trailing whitespace is not part of a pattern unless escaped. Leading whitespace IS.
    stripped = re.sub(r"(?<!\\)\s+$", "", line)
    if not stripped:
        return None

    negated = stripped.startswith("!")
    if negated:
        stripped = stripped[1:]
    if stripped.startswith("\\"):      # `\!literal` and `\#literal`
        stripped = stripped[1:]
    if not stripped:
        return None

    dir_only = stripped.endswith("/")
    if dir_only:
        stripped = stripped[:-1]
    if not stripped:
        return None

    # A `/` anywhere but the very end anchors the pattern to the .gitignore's own directory. Otherwise
    # it matches by basename at any depth below it.
    anchored = "/" in stripped
    if stripped.startswith("/"):
        stripped = stripped[1:]
    if not stripped:
        return None

    body = _translate(stripped)
    expr = f"^{body}$" if anchored else f"^(?:.*/)?{body}$"
    try:
        return _Rule(re.compile(expr), negated, dir_only)
    except re.error:
        # A pattern we cannot compile must not take the tree down with it, and must not silently
        # ignore anything. Dropped, which leaves the path surveyed.
        return None


class IgnoreIndex:
    """The `.gitignore` rules of one checkout, loaded per directory as the walk descends.

    Usage mirrors `os.walk`: call `load` on each directory as you enter it, then ask `ignored` about
    the names inside it. Rules from shallower directories still apply — `ignored` consults every
    ancestor — so loading is incremental and nothing is parsed twice.
    """

    def __init__(self, root) -> None:
        self._root = pathlib.Path(root)
        self._rules: dict[str, tuple[_Rule, ...]] = {}
        git = _read_git_index(self._root)
        self._tracked, self._tracked_dirs = git.files, git.dirs
        #: A sentence naming what the tracked set was read from, empty when there is none.
        self.tracked_basis = git.basis
        #: And WHY there is none, empty when there is one. Exactly one of the two is set.
        self.tracked_refusal = git.refusal
        #: How many paths a rule matched and TRACKING rescued. Reported, not merely applied: it is the
        #: difference between the two questions this class can answer, and a customer whose repository
        #: commits generated code is owed the number.
        self.rescued = 0

    def load(self, rel_dir: str = "") -> None:
        """Parse `<rel_dir>/.gitignore` if it exists. Idempotent."""
        key = rel_dir.strip("/")
        if key in self._rules:
            return
        path = (self._root / key / ".gitignore") if key else (self._root / ".gitignore")
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            self._rules[key] = ()
            return
        self._rules[key] = tuple(r for r in (_compile(ln) for ln in text.splitlines()) if r)

    def ignored(self, rel_path: str, *, is_dir: bool) -> bool:
        """Would git ignore this path? `rel_path` is POSIX-style and relative to the checkout root.

        Last match wins, and deeper `.gitignore` files are consulted after shallower ones — both are
        git's rules, and together they are what lets a subdirectory re-include something its parent
        ignored.
        """
        rel = rel_path.strip("/")
        if not rel:
            return False
        parts = rel.split("/")
        if any(p in ALWAYS_PRUNE for p in parts):
            return True

        decision = False
        # Ancestors shallow-to-deep: "" (root), then each directory containing the path.
        for depth in range(len(parts)):
            key = "/".join(parts[:depth])
            rules = self._rules.get(key)
            if not rules:
                continue
            subject = "/".join(parts[depth:])
            for rule in rules:
                # A directory-only rule cannot match a file, but it DOES match an ancestor directory
                # of one — and that case never reaches here, because an ignored directory is pruned.
                if rule.dir_only and not is_dir:
                    continue
                if rule.regex.match(subject):
                    decision = not rule.negated
        if decision and self._is_tracked(rel, is_dir=is_dir):
            # THE PATTERNS SAID SKIP AND GIT SAYS THIS IS THE REPOSITORY. Tracking wins: an ignore rule
            # has no effect on a file git already tracks, so treating the pattern as authoritative here
            # would skip code that is committed, checked out in CI and shipped to users. See the module
            # docstring for the measurement.
            self.rescued += 1
            return False
        return decision

    def _is_tracked(self, rel: str, *, is_dir: bool) -> bool:
        """Is this path in the index? For a directory, does it CONTAIN anything in the index?

        The directory arm is what keeps the walk from pruning a `build/` that holds committed source: a
        pruned directory is never descended, so a decision taken about the directory is final for
        everything beneath it, and the file arm would never get to run.
        """
        if not self.tracked_basis:
            return False
        return rel in self._tracked_dirs if is_dir else rel in self._tracked
