# The free distribution's image. THIS FILE SHIPS; the one at the root of the development tree does not.
#
# The two are not interchangeable and copying the development one into the distribution was measured to
# produce a repository that CANNOT BUILD. That file has two build stages: the first copies the build
# tooling and runs it to strip the deep capability out of a tree that contains it. The distribution
# carries no build tooling and has no deep capability to strip — the stripping already happened,
# upstream, and is what produced this tree — so that stage's COPY resolves to nothing and the build
# fails before it reaches the application.
#
# So this is a ONE-STAGE image over an already-free tree, and that difference is the whole reason both
# files exist. The builder refuses to emit a distribution whose Dockerfile names a COPY source the
# distribution does not carry, which is the guard that would have caught the copy.
#
# What it keeps from the development image, and neither is optional:
#   * the deep-absence assertion, so the property is re-checked in the artefact a customer pulls
#     rather than only in the build that produced it
#   * PYTHONSAFEPATH, which is a containment control and is explained where it is set

FROM python:3.12-slim

# git is a real runtime dependency, not a convenience: resolving a pull request's scope shells out to
# it. Its absence degrades to an honest empty result rather than a crash, so this is about the image
# working, not about it failing safely.
# A JVM AND NODE, BECAUSE A LANGUAGE THAT CANNOT RUN HERE CAN NEVER BE GATED. A finding gates only when
# a reproduction is demonstrated, a demonstration executes the customer's declared entry point, and that
# entry point runs in THIS container — a container action, so a `setup-node` step in their workflow
# installs onto the runner where nothing here can see it.
#
# Measured 2026-08-17 with the shipping adjudicator inside the shipping image, against the reference
# harness canaries: `canary-py` 4/4 gate-eligible, `canary-js` **0/5** (`exec: node: not found`, exit
# 127), `canary-java` **0/5**. With these two lines: 5/5 and 5/5, so 4 of 14 became 14 of 14.
#
# The JRE earns its 201 MB by covering THREE languages — java, kotlin and scala share the VM — and two of
# those three are languages the marker table has no rules for at all. Still absent, deliberately: ruby,
# php, dotnet and any C compiler. Each is another 20–200 MB for a language further down the measured
# usage ranking and none has a canary, so adding one would ship an unproven claim. `probe_runtimes` names
# whichever is missing for the repository in hand, in `preflight`, before the customer spends anything.
# ruby +31 MB, php-cli +23 MB, gcc/g++ +244 MB, the .NET RUNTIME +69 MB — each priced independently
# before it was added, and each proved by a canary that scores inside this image rather than by argument.
# gcc is the only toolchain here and it earns its share because `targets/canary` compiles lazily, so a
# compiler is what makes the oldest ground truth in the corpus measurable. dotnet is the RUNTIME and not
# the SDK (+69 against +564): the Java precedent settles it, since `canary-java` scores 5/5 under a JRE
# with no javac, because the normal CI flow builds in an earlier step and this container runs the result.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git ca-certificates default-jre-headless ruby php-cli gcc g++ libc6-dev \
 && rm -rf /var/lib/apt/lists/*

# From Microsoft's own image, pinned to a major. Debian ships no dotnet in main, and adding a third-party
# apt source to a security product's image is a supply-chain decision with worse properties than a COPY.
COPY --from=mcr.microsoft.com/dotnet/runtime:8.0 /usr/share/dotnet /usr/share/dotnet
RUN ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet

# Node from the official image rather than Debian's, and pinned to a MAJOR. `apt-get install nodejs` on
# bookworm gives 20.x, which reaches end of life in April 2026 — a runtime that stops receiving security
# fixes has no place inside a security product. The assertion below is what makes the pin real.
COPY --from=node:22-bookworm-slim /usr/local/bin/node /usr/local/bin/node

WORKDIR /app
COPY shard/ /app/shard/

# PYTHONSAFEPATH IS A CONTAINMENT CONTROL, not a tidiness setting. A GitHub container action runs with
# `--workdir /github/workspace` — the CHECKOUT — and `python -m` puts the working directory at the FRONT
# of `sys.path`, ahead of PYTHONPATH. So a repository under review that contains a top-level `shard/`
# package (or `shard.py`) SHADOWS the product: the container imports and executes the customer's code,
# as root, with their inference key in the environment, and the shipped code never runs. Measured
# 2026-08-08 by building the image and running it: `import shard` resolved to the checkout's copy. On a
# `pull_request` workflow the checkout is the pull request's head, so the repository supplying that
# package need not be the one whose owner installed Shard.
#
# `PYTHONSAFEPATH=1` (3.11+) removes the cwd entry; the application is reached through PYTHONPATH, which
# is why both lines are here and why neither may be dropped without the other being reconsidered.
ENV PYTHONPATH=/app \
    PYTHONSAFEPATH=1 \
    PYTHONDONTWRITEBYTECODE=1

# Fail the IMAGE if the deep capability or the library client is present, and prove the containment
# control actually refuses a decoy rather than merely being declared. The decoy directory is the
# runner's own arrangement: a working directory carrying a `shard/` package that is not ours.
#
# NOTE ON VACUITY: these assertions are NEVER automatically verified to fail. `test ! -e …` is true
# today, true if the path is misspelled, and true if this RUN line is dropped. The one-time manual
# check — build this image with a deliberate `COPY shard/alexandria` injected and confirm the build
# fails at this step — cannot be re-run automatically; the comment IS the record.
RUN python -c "import importlib.util as u, sys; sys.exit(0 if u.find_spec('shard.deep') is None else 1)" \
 && python -c "import importlib.util as u, sys; sys.exit(0 if u.find_spec('shard.alexandria') is None else 1)" \
 && python -m shard --help > /dev/null \
 && mkdir -p /tmp/decoy/shard \
 && echo "raise SystemExit('the checkout shadowed the image')" > /tmp/decoy/shard/__init__.py \
 && cd /tmp/decoy && python -m shard --help > /dev/null && cd / && rm -rf /tmp/decoy

# FAIL THE IMAGE IF A RUNTIME IT CLAIMS IS MISSING, OR IS THE WRONG MAJOR. An absent runtime makes every
# finding in its language informational, and that failure is silent at build time and expensive at review
# time — the customer pays for a review before anything discovers it. The node MAJOR is checked because
# the COPY above is a floating tag within 22.x, and node moves observable text between PATCH releases
# (v22.12 printed `undefined:1` where v22.14 printed `<anonymous_script>:1`), so a marker derived under
# one and replayed under another need not match. A silent major bump would change what reproduces without
# changing a line of code.
RUN node --version && node --version | grep -q '^v22\.' \
 && java -version 2>&1 | head -1 \
 && ruby -e 'exit 0' && php -r 'exit(0);' \
 && dotnet --list-runtimes | grep -q '^Microsoft.NETCore.App 8\.' \
 && printf '#include <stdio.h>\nint main(){return 0;}\n' > /tmp/c.c && cc -o /tmp/c /tmp/c.c && /tmp/c \
 && printf '#include <string>\nint main(){return std::string("x").size()-1;}\n' > /tmp/c.cc \
 && c++ -o /tmp/cxx /tmp/c.cc && /tmp/cxx && rm -f /tmp/c.c /tmp/c /tmp/c.cc /tmp/cxx \
 && python -c "import sys; sys.path.insert(0, '/app'); from shard.target import probe_runtimes; \
r = probe_runtimes({'javascript': 1, 'typescript': 1, 'java': 1, 'kotlin': 1, 'scala': 1, 'python': 1, \
'ruby': 1, 'php': 1, 'c#': 1, 'c': 1, 'c++': 1}); \
sys.exit(0 if not r['absent'] else ('MISSING: ' + repr(r['absent'])))"

# ADDRESSSANITIZER, ASSERTED RATHER THAN ASSUMED. The README claims C and C++ are ground-truthed "under
# AddressSanitizer" and the action manifest tells a customer how to arrange one — and until 2026-08-24
# nothing in this build checked that `-fsanitize=address` could link here at all. The manifest had in
# fact been advising `-static-libasan` on the belief that this image carried no ASAN runtime, which is a
# statement about an image that predates the compiler being added.
#
# THE CHECK IS A REPORT AND NOT A COMPILE. A toolchain can accept the flag, link, and produce a binary
# that detects nothing; that passes a compile-and-run test and would leave every C finding in this image
# undemonstrable. So this builds a deliberate one-byte heap overflow, requires the program to DIE, and
# requires ASAN's own report on stderr. `!` because ASAN's default is `abort_on_error=0` — it prints and
# exits 1 — so a zero exit here means the sanitiser did not fire.
RUN printf '#include <stdlib.h>\nint main(void){char *p = malloc(1); p[1] = 1; return p[1];}\n' \
      > /tmp/asan.c \
 && cc -fsanitize=address -g -o /tmp/asan /tmp/asan.c \
 && ! /tmp/asan 2> /tmp/asan.err \
 && grep -q 'AddressSanitizer' /tmp/asan.err \
 && rm -f /tmp/asan.c /tmp/asan /tmp/asan.err

ENTRYPOINT ["python", "-m", "shard"]
CMD ["--help"]
