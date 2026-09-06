# This is the free distribution image: one stage over a tree from which paid modules have already been
# excluded. The checks below reassert that tier boundary in the customer artefact and prevent a checkout
# from shadowing the installed package.

FROM python:3.12-slim

# Git is what resolves pull-request scope; without it the scope comes back empty with a stated reason
# rather than raising. Reproductions execute inside this container, so language runtimes installed by
# earlier host steps are not visible here. The JRE covers Java, Kotlin and Scala; the .NET runtime
# intentionally omits the SDK because CI builds managed artefacts before Shard runs. C and C++ retain
# compilers because a reproduction may compile source inside the image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      git ca-certificates default-jre-headless ruby php-cli gcc g++ libc6-dev \
 && rm -rf /var/lib/apt/lists/*

# Copy the .NET runtime from Microsoft's image, pinned to a major, instead of adding a third-party apt
# source to the image.
COPY --from=mcr.microsoft.com/dotnet/runtime:8.0 /usr/share/dotnet /usr/share/dotnet
RUN ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet

# Copy Node from the official image and pin its major. The build assertion below prevents silent runtime
# drift.
COPY --from=node:22-bookworm-slim /usr/local/bin/node /usr/local/bin/node

WORKDIR /app
COPY shard/ /app/shard/

# PYTHONSAFEPATH is a containment control. A GitHub container action runs from the checkout, and
# `python -m` would otherwise put that directory ahead of PYTHONPATH. A pull request containing a
# top-level package directory or same-named Python module could then execute as root with the inference
# key instead of loading the product package.
#
# `PYTHONSAFEPATH=1` removes the working-directory entry; PYTHONPATH provides the trusted package path.
# Both settings are required together.
ENV PYTHONPATH=/app \
    PYTHONSAFEPATH=1 \
    PYTHONDONTWRITEBYTECODE=1

# Fail the image if paid modules are importable, then run from a decoy checkout to prove the containment
# control selects the trusted package.
RUN python -c "import importlib.util as u, sys; sys.exit(0 if u.find_spec('shard.deep') is None else 1)" \
 && python -c "import importlib.util as u, sys; sys.exit(0 if u.find_spec('shard.alexandria') is None else 1)" \
 && python -m shard --help > /dev/null \
 && mkdir -p /tmp/decoy/shard \
 && echo "raise SystemExit('the checkout shadowed the image')" > /tmp/decoy/shard/__init__.py \
 && cd /tmp/decoy && python -m shard --help > /dev/null && cd / && rm -rf /tmp/decoy

# Fail the build if a declared runtime is absent or on the wrong major. Runtime drift can change whether
# and how a reproduction executes, so it must be detected before a customer review begins.
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

# Prove AddressSanitizer detects faults rather than merely accepting the compiler flag. The deliberate
# one-byte overflow must fail and emit ASAN's report; a zero exit means the sanitizer did not fire.
RUN printf '#include <stdlib.h>\nint main(void){char *p = malloc(1); p[1] = 1; return p[1];}\n' \
      > /tmp/asan.c \
 && cc -fsanitize=address -g -o /tmp/asan /tmp/asan.c \
 && ! /tmp/asan 2> /tmp/asan.err \
 && grep -q 'AddressSanitizer' /tmp/asan.err \
 && rm -f /tmp/asan.c /tmp/asan /tmp/asan.err

ENTRYPOINT ["python", "-m", "shard"]
CMD ["--help"]
