"""The examples, executed.

`examples/` is the part of this repository a new reader copies, and an example that does not run is
worse than no example — it teaches a mistake with the authority of a working sample. So these do not
inspect the files; they run every shipped entry point the way Shard runs it, `bash -- <entry>
<payload>`, and check both directions.

**Both directions, because either alone is satisfied by something broken.** An entry point that never
speaks passes every quiet-on-benign check. One that always speaks passes every demonstrates-the-defect
check. Only the pair says the witness distinguishes an attack from ordinary input — which is the
property the whole product rests on, and the one the READMEs ask the reader to verify by hand.

Deterministic: no API key, no model, no network. Each example is skipped, by name, when the runtime it
needs is not on PATH, so a machine without node still gets a real result for the other two.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples"

#: name -> (runtime needed on PATH, an input that MUST demonstrate, the marker it must print).
#: An EMPTY marker means the demonstration is a fatal signal rather than a string — both of the
#: expectations this build adjudicates are covered.
#:
#: **THE PAYLOAD IS PART OF THE FIXTURE, and choosing one is not obvious.** `--- !ruby/object:Struct`
#: deserialises to nil, so the Ruby witness observed nothing against the payload first written for it
#: and looked broken while being perfectly sound. When a witness does not fire, the payload is as
#: likely to be wrong as the witness — check both.
CASES = {
    "python-config-eval": ("python3", 'x = __import__("os")\n', "SHARD_SETTINGS_ARBITRARY_CODE"),
    "node-path-traversal": ("node", "../secret.txt\n", "SHARD_NOTE_PATH_ESCAPED"),
    "c-record-overflow": ("cc", "400\nhi\n", ""),
    "ruby-yaml-deserialise": ("ruby", "--- !ruby/object:Gem::Requirement\n  requirements: []\n",
                              "SHARD_SESSION_OBJECT_CONSTRUCTED"),
    "php-template-include": ("php", "../secrets\n", "SHARD_TEMPLATE_ESCAPED_ROOT"),
}


def _run(name: str, payload) -> subprocess.CompletedProcess:
    example = EXAMPLES / name
    return subprocess.run(["bash", "--", str(example / ".shard" / "entry.sh"), str(payload)],
                          capture_output=True, text=True, timeout=300, cwd=example)


def _need(name: str) -> str:
    runtime = CASES[name][0]
    if shutil.which(runtime) is None:
        pytest.skip(f"{runtime} is not on PATH")
    return runtime


@pytest.mark.parametrize("name", sorted(CASES))
def test_the_example_is_complete(name):
    """Both files, and the second is the one the READMEs call the highest-value addition."""
    example = EXAMPLES / name
    assert (example / "README.md").is_file()
    assert (example / ".shard" / "entry.sh").is_file()
    benign = example / ".shard" / "entry.sh.benign"
    assert benign.is_dir() and any(benign.iterdir())


@pytest.mark.parametrize("name", sorted(CASES))
def test_an_empty_payload_is_quiet(name):
    """The baseline branch every entry point must have. Shard runs yours on an empty payload and
    compares; one that speaks here demonstrates nothing, because the baseline speaks too."""
    _need(name)
    done = _run(name, "/dev/null")
    assert done.returncode == 0, done.stderr[-2000:]
    assert done.stdout.strip() == "", done.stdout[-2000:]


@pytest.mark.parametrize("name", sorted(CASES))
def test_every_declared_benign_input_is_quiet(name):
    """The control the customer declares. A finding a benign input also reproduces is refused, so an
    example whose own controls fire is teaching the reader to build a witness that cannot gate."""
    _need(name)
    controls = sorted((EXAMPLES / name / ".shard" / "entry.sh.benign").iterdir())
    assert controls, "nothing was checked"
    for control in controls:
        done = _run(name, control)
        assert done.returncode == 0, f"{control.name}: {done.stderr[-2000:]}"
        assert done.stdout.strip() == "", f"{control.name}: {done.stdout[-2000:]}"


@pytest.mark.parametrize("name", sorted(CASES))
def test_the_documented_attack_really_demonstrates(name, tmp_path):
    _need(name)
    _, attack, marker = CASES[name]
    payload = tmp_path / "attack"
    payload.write_text(attack, encoding="utf-8")
    done = _run(name, payload)
    if marker:
        assert marker in done.stdout, f"exit {done.returncode}: {done.stdout[-2000:]}{done.stderr[-2000:]}"
    else:
        # A NEGATIVE returncode is a signal. An ordinary non-zero exit is a different observation and
        # is not one this build adjudicates, so asserting `!= 0` here would pass on a run that could
        # never gate a build.
        assert done.returncode < 0, (
            f"expected a fatal signal, got exit {done.returncode}. If AddressSanitizer reported and "
            f"the process still exited normally, ASAN_OPTIONS=abort_on_error=1 is not in effect: "
            f"{done.stdout[-2000:]}{done.stderr[-2000:]}")
