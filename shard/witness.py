
from __future__ import annotations

import hashlib
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass

from shard.witnessfs import SnapshotError, SourceSnapshot, original_paths

SOURCE_ISOLATION_REFUSAL = "witness source isolation failed: "
CONTAINMENT_REFUSAL = "witness execution containment failed: "

FATAL_SIGNAL_CODES = frozenset({132, 134, 135, 136, 139})

TIMEOUT_KILL_CODES = frozenset({124, 137, 143})

_SECRET_ENV_SUFFIXES = ("_TOKEN", "_KEY", "_SECRET", "_PASSWORD", "_PASSWD", "_CREDENTIALS")
_SECRET_ENV_NAMES = frozenset({"GITHUB_TOKEN", "GH_TOKEN", "AWS_SESSION_TOKEN", "AWS_SECRET_ACCESS_KEY",
                               "AWS_ACCESS_KEY_ID", "ANTHROPIC_AUTH_TOKEN"})

_COMMAND_FILE_ENV_NAMES = frozenset({
    "GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "GITHUB_STATE",
})
_LOCATION_ENV_NAMES = frozenset({
    "GITHUB_WORKSPACE", "GITHUB_ACTION_PATH", "RUNNER_TEMP", "RUNNER_TOOL_CACHE", "RUNNER_WORKSPACE",
    "SHARD_ACTION_SNAPSHOT_ROOT",
})
_CONTROL_SOCKET_ENV_NAMES = frozenset({
    "CONTAINER_CONNECTION", "CONTAINER_HOST", "DBUS_SESSION_BUS_ADDRESS", "DOCKER_CONTEXT",
    "DOCKER_HOST", "GNUPGHOME", "GPG_AGENT_INFO", "KUBECONFIG", "PODMAN_SOCKET",
    "SSH_AUTH_SOCK", "SSH_AGENT_PID", "XDG_RUNTIME_DIR",
})
_ENTRY_CAPABILITY_ENV_NAMES = (
    _COMMAND_FILE_ENV_NAMES | _LOCATION_ENV_NAMES | _CONTROL_SOCKET_ENV_NAMES
)


def _secret_env_name(name: str, configured=()) -> bool:
    upper = name.upper()
    configured_names = {str(item).upper() for item in configured if item}
    return (upper.startswith("INPUT_") or upper in _SECRET_ENV_NAMES or upper in configured_names
            or any(upper.endswith(suffix) for suffix in _SECRET_ENV_SUFFIXES))


def entry_env(base=None, *, secret_env_names=()) -> dict:
    import os

    source = os.environ if base is None else base
    out = {}
    for name, value in source.items():
        upper = name.upper()
        socket_address = isinstance(value, str) and value.lower().startswith(("unix:", "unix://"))
        if (_secret_env_name(name, secret_env_names) or upper in _ENTRY_CAPABILITY_ENV_NAMES
                or upper.endswith(("_SOCK", "_SOCKET")) or socket_address):
            continue
        out[name] = value
    return out


_REDACT_MIN_LEN = 8


def secret_values(base=None, *, secret_env_names=()) -> tuple[str, ...]:
    import os

    source = os.environ if base is None else base
    values = {v for name, v in source.items()
              if (_secret_env_name(name, secret_env_names) and isinstance(v, str)
                  and len(v) >= _REDACT_MIN_LEN)}
    return tuple(sorted(values, key=len, reverse=True))


def _secret_spellings(value: str) -> tuple[str, ...]:
    import base64
    import urllib.parse

    raw = value.encode("utf-8", "surrogateescape")
    forms = {value}
    for encoder in (base64.b64encode, base64.urlsafe_b64encode):
        encoded = encoder(raw).decode("ascii")
        forms.add(encoded)
        forms.add(encoded.rstrip("="))
    forms.add(raw.hex())
    forms.add(raw.hex().upper())
    forms.add(urllib.parse.quote(value, safe=""))
    return tuple(sorted(forms, key=len, reverse=True))


def redact_secrets(text: str, base=None, *, secret_env_names=()) -> str:
    if not text:
        return text
    for value in secret_values(base, secret_env_names=secret_env_names):
        for spelling in _secret_spellings(value):
            if spelling in text:
                text = text.replace(spelling, "[redacted]")
    return text



_CONTAINMENT_PATHS_ENV = "_SHARD_CONTAINMENT_PATHS"
_CONTAINMENT_ERROR = "shard containment setup failed: "

_NAMESPACE_INIT = f"""\
import ctypes
import errno
import json
import os
import sys

ERROR = {_CONTAINMENT_ERROR!r}
PATHS_ENV = {_CONTAINMENT_PATHS_ENV!r}

def fail(message):
    os.write(2, (ERROR + message + "\\n").encode("utf-8", "replace"))
    raise SystemExit(125)

if os.getpid() != 1 or len(sys.argv) < 2:
    fail("namespace init did not become PID 1")

try:
    manifest = json.loads(os.environ.pop(PATHS_ENV, "{{}}"))
    readonly = manifest.get("readonly", [])
    writable = manifest.get("writable", [])
    execution_cwd = manifest.get("execution_cwd")
    jail_root = manifest.get("jail_root", "")
    overlay = manifest.get("overlay")
    bind_files = manifest.get("bind_files", [])
    protected_relatives = manifest.get("protected_relatives", [])
    if overlay is not None:
        overlay_paths = [overlay.get(name, "") for name in
                         ("lower", "target", "upper", "work", "storage")]
        writable = writable + [overlay_paths[4]]
    else:
        overlay_paths = []
    # Ancestors first, then descendants. Binding an ancestor after its child hides the child's mount
    # and makes the later remount address an ordinary dentry (EINVAL). Both nesting directions occur:
    # witness trials protect descendants of writable scratch, while run_entry writes a scratch child
    # beneath a read-only checkout.
    paths = sorted(set(writable + readonly), key=lambda path: (path.count(os.sep), path))
    if (not isinstance(manifest, dict) or not isinstance(readonly, list)
            or not isinstance(writable, list)
            or not isinstance(bind_files, list)
            or not all(isinstance(pair, list) and len(pair) == 2
                       and all(isinstance(path, str) and path for path in pair)
                       for pair in bind_files)
            or not isinstance(protected_relatives, list)
            or not all(isinstance(path, str) and path and not path.startswith("/")
                       and ".." not in path.split("/") for path in protected_relatives)
            or (overlay is not None and not isinstance(overlay, dict))
            or (execution_cwd is not None and not isinstance(execution_cwd, str))
            or not isinstance(jail_root, str) or not jail_root
            or not all(isinstance(path, str) and path for path in paths + overlay_paths)):
        fail("invalid protected-path manifest")
    if any(path in ("/", "/home", "/root", "/run", "/tmp", "/var", "/var/run")
           for path in paths):
        fail("a declared execution root is too broad")
except (TypeError, ValueError) as exc:
    fail("invalid protected-path manifest: " + str(exc))

libc = ctypes.CDLL(None, use_errno=True)
libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                       ctypes.c_ulong, ctypes.c_void_p]
libc.mount.restype = ctypes.c_int
MS_RDONLY = 1
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384

class MountAttr(ctypes.Structure):
    _fields_ = [("attr_set", ctypes.c_uint64), ("attr_clr", ctypes.c_uint64),
                ("propagation", ctypes.c_uint64), ("userns_fd", ctypes.c_uint64)]
try:
    mount_setattr = libc.mount_setattr
except AttributeError:
    def mount_setattr(directory, path, flags, attr, size):
        return libc.syscall(442, directory, path, flags, attr, size)
mount_setattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
                          ctypes.POINTER(MountAttr), ctypes.c_size_t]
mount_setattr.restype = ctypes.c_int
AT_FDCWD = -100
AT_RECURSIVE = 0x8000
MOUNT_ATTR_RDONLY = 1
MOUNT_ATTR_NOSUID = 2
MOUNT_ATTR_NODEV = 4

if overlay is not None:
    lower, target, upper, work, storage = overlay_paths
    MS_NOSUID = 2
    MS_NODEV = 4
    MS_NOEXEC = 8
    # The outer Action filesystem is itself overlayfs. Linux refuses an overlay whose upper/work
    # directories sit on that same overlay (EINVAL), which made containment pass on the host and fail
    # in the shipping image. Put the private upper on tmpfs first; after mounting the trial overlay, a
    # second empty read-only tmpfs hides those bookkeeping paths from customer code without removing
    # the mounted overlay's references to them.
    if libc.mount(b"tmpfs", os.fsencode(storage), b"tmpfs", MS_NOSUID | MS_NODEV,
                  ctypes.c_char_p(b"size=64m")) != 0:
        fail("could not allocate private trial storage: errno " + str(ctypes.get_errno()))
    try:
        os.mkdir(upper, 0o700)
        os.mkdir(work, 0o700)
    except OSError as exc:
        fail("could not prepare private trial storage: " + str(exc))
    upper_fd = os.open(upper, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    options = "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work
    if libc.mount(b"overlay", os.fsencode(target), b"overlay", 0,
                  ctypes.c_char_p(os.fsencode(options))) != 0:
        fail("could not mount a private writable trial: errno " + str(ctypes.get_errno()))
    if libc.mount(b"tmpfs", os.fsencode(storage), b"tmpfs",
                  MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                  ctypes.c_char_p(b"size=4096")) != 0:
        fail("could not hide private trial storage: errno " + str(ctypes.get_errno()))

# Bind retained evidence over its historical path only inside this namespace. The command therefore
# sees the same argv and BASH_SOURCE/$0 layout as the customer contract, while a live-path rewrite
# cannot change which bytes execute or which candidate bytes the harness opens.
for source, target in bind_files:
    if not os.path.exists(target):
        try:
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        except OSError as exc:
            fail("could not create an immutable file target: " + str(exc))
    if (not os.path.isabs(source) or not os.path.isabs(target)
            or not os.path.isfile(source) or not os.path.isfile(target)):
        fail("an immutable file binding disappeared before execution")
    if libc.mount(os.fsencode(source), os.fsencode(target), None, MS_BIND, None) != 0:
        fail("could not bind immutable evidence: errno " + str(ctypes.get_errno()))
    if libc.mount(None, os.fsencode(target), None, MS_BIND | MS_REMOUNT | MS_RDONLY, None) != 0:
        fail("could not make immutable evidence read-only: errno " + str(ctypes.get_errno()))

# A read-only host root still exposes every path whose name an attacker knows. Build a new root from
# an allowlist instead: runtimes, the explicitly declared read/write roots, a private procfs and the
# minimum device files ordinary commands need. Nothing else is mounted, so an arbitrary host path is
# absent rather than merely immutable. The caller owns ``jail_root`` and removes it after this mount
# namespace exits; mounting tmpfs over it keeps all root construction out of the host filesystem.
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
if (not os.path.isabs(jail_root) or jail_root == "/" or not os.path.isdir(jail_root)
        or os.path.islink(jail_root)):
    fail("the private execution root is unavailable")
if libc.mount(b"tmpfs", os.fsencode(jail_root), b"tmpfs", MS_NOSUID | MS_NODEV,
              ctypes.c_char_p(b"size=128m")) != 0:
    fail("could not allocate the private execution root: errno " + str(ctypes.get_errno()))
new_root = os.path.join(jail_root, "root")
try:
    os.mkdir(new_root, 0o700)
except OSError as exc:
    fail("could not prepare the private execution root: " + str(exc))
if libc.mount(os.fsencode(new_root), os.fsencode(new_root), None, MS_BIND, None) != 0:
    fail("could not bind the private execution root: errno " + str(ctypes.get_errno()))

def target_for(path, directory):
    target = new_root + path
    try:
        os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
        if directory:
            os.makedirs(target, mode=0o755, exist_ok=True)
        elif not os.path.exists(target):
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
    except OSError as exc:
        fail("could not prepare an allowed path: " + str(exc))
    return target

def expose(path, readonly_path, harden=False):
    if not os.path.isabs(path) or not os.path.exists(path):
        fail("an allowed path disappeared before execution")
    directory = os.path.isdir(path)
    target = target_for(path, directory)
    flags = MS_BIND | (MS_REC if directory else 0)
    if libc.mount(os.fsencode(path), os.fsencode(target), None, flags, None) != 0:
        fail("could not expose an allowed path: errno " + str(ctypes.get_errno()))
    if readonly_path or harden:
        attrs = (MOUNT_ATTR_RDONLY if readonly_path else 0)
        if harden:
            attrs |= MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV
        attr = MountAttr(attrs, 0, 0, 0)
        recursive = AT_RECURSIVE if directory else 0
        if mount_setattr(AT_FDCWD, os.fsencode(target), recursive,
                         ctypes.byref(attr), ctypes.sizeof(attr)) != 0:
            fail("could not make an allowed path read-only: errno " + str(ctypes.get_errno()))

# Keep command availability without carrying the host root into the namespace. These are executable
# distribution roots, not customer or runner state. Debian's /bin and /lib are symlinks into /usr,
# but binding the historical names preserves shebangs and dynamic-loader paths on both layouts.
runtime_roots = [path for path in ("/usr", "/bin", "/lib", "/lib64", "/sbin")
                 if os.path.exists(path)]
runtime_roots += [path for path in ("/etc/alternatives", "/etc/ld.so.cache")
                  if os.path.exists(path)]
# Debian-family JDKs deliberately keep their runtime security policy outside /usr and link
# ``$JAVA_HOME/conf`` into one versioned directory here. Omitting it leaves ``java`` executable but
# breaks ObjectInputStream, XML parsing and other ordinary standard-library operations with
# ``InternalError: Error loading java.security file``. Expose only the versioned distribution
# configuration, never /etc itself or a symlink that could redirect this exception to host state.
try:
    java_configs = [
        os.path.join("/etc", name) for name in os.listdir("/etc")
        if (name.startswith("java-") and name.endswith("-openjdk")
            and name[5:-8].isdigit()
            and os.path.isdir(os.path.join("/etc", name))
            and not os.path.islink(os.path.join("/etc", name)))
    ]
except OSError:
    java_configs = []
runtime_roots += java_configs
for path in runtime_roots:
    expose(path, True)

# Parent mounts precede descendants. A writable trial may contain a retained read-only input, and a
# read-only checkout may contain a disposable writable scratch child; the deeper binding decides.
allowed = [(path, False) for path in writable]
allowed += [(path, True) for path in readonly]
if overlay is not None:
    allowed.append((overlay_paths[1], False))
allowed.sort(key=lambda item: (item[0].count(os.sep), item[0], item[1]))
for path, readonly_path in allowed:
    expose(path, readonly_path, True)

# A fresh procfs is tied to this PID namespace. Only ordinary character devices are carried across;
# /dev/shm, disks and host sockets are deliberately absent.
proc_target = target_for("/proc", True)
if libc.mount(b"proc", os.fsencode(proc_target), b"proc", MS_NOSUID | MS_NODEV | MS_NOEXEC,
              None) != 0:
    fail("could not mount the private procfs: errno " + str(ctypes.get_errno()))
target_for("/dev", True)
for device in ("/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"):
    if os.path.exists(device):
        expose(device, False)
try:
    # Compilers and language runtimes expect a writable /tmp even when the declared workdir lives
    # elsewhere. This directory belongs to the private tmpfs root; exposing the host's /tmp would
    # recover cross-trial state and every pathname socket placed there.
    os.makedirs(new_root + "/tmp", mode=0o1777, exist_ok=True)
    os.chmod(new_root + "/tmp", 0o1777)
    os.makedirs(new_root + "/etc", mode=0o755, exist_ok=True)
    with open(new_root + "/etc/passwd", "w", encoding="utf-8") as stream:
        stream.write("root:x:0:0:root:/root:/bin/sh\\n")
    with open(new_root + "/etc/group", "w", encoding="utf-8") as stream:
        stream.write("root:x:0:\\n")
    for link, target in (("/dev/fd", "/proc/self/fd"), ("/dev/stdin", "/proc/self/fd/0"),
                         ("/dev/stdout", "/proc/self/fd/1"), ("/dev/stderr", "/proc/self/fd/2")):
        os.symlink(target, new_root + link)
except OSError as exc:
    fail("could not prepare private runtime files: " + str(exc))

if execution_cwd is not None:
    visible = writable + readonly + ([overlay_paths[1]] if overlay is not None else [])
    if not any(execution_cwd == root or execution_cwd.startswith(root.rstrip("/") + "/")
               for root in visible):
        fail("the execution directory is outside the allowed roots")

old_root = os.path.join(new_root, ".old-root")
try:
    os.mkdir(old_root, 0o700)
except OSError as exc:
    fail("could not prepare the old-root detachment: " + str(exc))
try:
    pivot_root = libc.pivot_root
except AttributeError:
    fail("pivot_root is unavailable on this runner")
pivot_root.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
pivot_root.restype = ctypes.c_int
if pivot_root(os.fsencode(new_root), os.fsencode(old_root)) != 0:
    fail("could not pivot into the private execution root: errno " + str(ctypes.get_errno()))
try:
    os.chdir("/")
except OSError as exc:
    fail("could not enter the private execution root: " + str(exc))
libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
libc.umount2.restype = ctypes.c_int
MNT_DETACH = 2
if libc.umount2(b"/.old-root", MNT_DETACH) != 0:
    fail("could not detach the host root: errno " + str(ctypes.get_errno()))
try:
    os.rmdir("/.old-root")
except OSError as exc:
    fail("could not remove the detached host root: " + str(exc))
if execution_cwd is not None:
    try:
        os.chdir(execution_cwd)
    except OSError as exc:
        fail("could not enter the contained working directory: " + str(exc))

# Namespace root is needed only to construct the mounts. Customer code must not retain CAP_SYS_ADMIN:
# it could otherwise unmount the read-only bind and reach the live checkout underneath it. NOROOT
# prevents uid 0 from regaining capabilities on exec; the bounding and ambient sets close the other
# routes, and no_new_privs makes the transition permanent for descendants.
PR_SET_SECUREBITS = 28
PR_CAPBSET_DROP = 24
PR_SET_NO_NEW_PRIVS = 38
PR_SET_DUMPABLE = 4
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_CLEAR_ALL = 4
SECURE_LOCKED = 1 | 2 | 4 | 8
# PID 1 retains the overlay-verification descriptor until the hostile child exits. Making the trusted
# init non-dumpable prevents that same-UID child reaching it through /proc/1/fd; exec restores the
# ordinary dumpable state for the child itself.
if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
    fail("could not protect the namespace init descriptors: errno " + str(ctypes.get_errno()))
if libc.prctl(PR_SET_SECUREBITS, SECURE_LOCKED, 0, 0, 0) != 0:
    fail("could not lock root capability semantics: errno " + str(ctypes.get_errno()))
for capability in range(64):
    if libc.prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 and ctypes.get_errno() != errno.EINVAL:
        fail("could not drop the capability bounding set: errno " + str(ctypes.get_errno()))
libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)

class CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
class CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32)]
header = CapHeader(0x20080522, 0)
data = (CapData * 2)()
if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
    fail("could not clear process capabilities: errno " + str(ctypes.get_errno()))
if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
    fail("could not set no_new_privs: errno " + str(ctypes.get_errno()))

child = os.fork()
if child == 0:
    os.execvp(sys.argv[1], sys.argv[1:])
_, status = os.waitpid(child, 0)
if overlay is not None:
    for relative in protected_relatives:
        try:
            os.stat(relative, dir_fd=upper_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            fail("could not verify private trial changes: " + str(exc))
        fail("protected trial state changed while the entry point was running: witness execution "
             "transiently changed pristine source: " + relative)
if os.WIFEXITED(status):
    code = os.WEXITSTATUS(status)
    # 128+signal is reserved for a signal the supervisor observed through waitpid. A hostile shell can
    # `exit 139`; remapping ordinary high exits makes that textually identical forgery distinguishable
    # from an exec'd target that the kernel actually terminated with SIGSEGV.
    raise SystemExit(code if code < 128 else 124)
raise SystemExit(128 + os.WTERMSIG(status))
"""

_PID_NAMESPACE = (
    "unshare", "--user", "--map-root-user", "--pid", "--fork", "--kill-child", "--mount-proc",
    "--propagation", "private",
)
_PID_INIT = ("--", sys.executable, "-c", _NAMESPACE_INIT)
PID_ISOLATION: tuple[str, ...] = (*_PID_NAMESPACE, *_PID_INIT)

NETWORK_ISOLATION: tuple[str, ...] = (
    *_PID_NAMESPACE, "--net", *_PID_INIT,
)

_PRIVILEGED_PID_NAMESPACE = (
    "unshare", "--pid", "--fork", "--kill-child", "--mount-proc", "--propagation", "private",
)
PRIVILEGED_NETWORK_ISOLATION: tuple[str, ...] = (
    *_PRIVILEGED_PID_NAMESPACE, "--net", *_PID_INIT,
)
_NETWORK_PREFIXES = (NETWORK_ISOLATION, PRIVILEGED_NETWORK_ISOLATION)


def network_isolated(prefix: tuple[str, ...]) -> bool:
    return prefix in _NETWORK_PREFIXES

_ISOLATION_CACHE: tuple[str, ...] | None = None

CONTAINMENT_CAPABILITIES: tuple[str, ...] = ("CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "CAP_SETPCAP")

_ISOLATION_DIAGNOSIS: tuple[str, ...] = ()


def isolation_prefix(runner=None) -> tuple[str, ...]:
    global _ISOLATION_CACHE
    if runner is not None:
        return _probe_isolation(runner)
    if _ISOLATION_CACHE is None:
        _ISOLATION_CACHE = _probe_isolation(subprocess.run)
    return _ISOLATION_CACHE


def containment_unavailable(runner=None) -> str:
    if network_isolated(isolation_prefix(runner)):
        return ""
    measured = "; ".join(line for line in _ISOLATION_DIAGNOSIS if line)
    return ("this runner cannot build the private user/PID/mount/procfs/network boundary, so no "
            "attacker-authored code may be executed here: it needs either an unprivileged user "
            "namespace or a launcher granting " + ", ".join(CONTAINMENT_CAPABILITIES)
            + (" — measured: " + measured if measured else ""))


def _probe_isolation(runner) -> tuple[str, ...]:
    global _ISOLATION_DIAGNOSIS
    diagnosis: list[str] = []
    with tempfile.TemporaryDirectory(prefix="shard-containment-probe-") as probe_root:
        root = pathlib.Path(probe_root)
        protected = root / "protected"
        hidden = root / "hidden"
        lower, target = root / "lower", root / "target"
        storage, upper, work = root / "storage", root / "storage/upper", root / "storage/work"
        jail = root / "jail"
        for path in (protected, lower, target, upper, work, jail):
            path.mkdir(parents=True, exist_ok=True)
        hidden.write_text("must not be visible", encoding="utf-8")
        env = _contained_entry_env(
            protected,
            jail_root=jail,
            overlay=(lower, target, upper, work, storage),
            execution_cwd=target,
            base={"PATH": os.environ.get("PATH", "")},
        )
        check = ("[ ! -e \"$1\" ] && [ ! -S /var/run/docker.sock ] "
                 "&& [ ! -S /run/docker.sock ]")
        for prefix in _NETWORK_PREFIXES:
            try:
                proc = runner(
                    [*prefix, "bash", "-c", check, "bash", str(hidden)],
                    capture_output=True, text=True, errors="replace", timeout=10, env=env,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                diagnosis.append(f"{prefix[0]}: {exc}")
                continue
            if proc.returncode == 0:
                _ISOLATION_DIAGNOSIS = ()
                return prefix
            said = (getattr(proc, "stderr", "") or "").strip().splitlines()
            diagnosis.append(said[-1] if said else f"exit {proc.returncode}")
    _ISOLATION_DIAGNOSIS = tuple(diagnosis)
    return ()


def _resolved_existing_paths(candidates) -> list[str]:
    resolved = []
    for candidate in candidates:
        if not candidate:
            continue
        try:
            path = pathlib.Path(candidate).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        rendered = str(path)
        if rendered not in resolved:
            resolved.append(rendered)
    return resolved


def _resolved_bindings(bind_files) -> list[list[str]]:
    bindings = []
    for source_path, target_path in bind_files:
        try:
            binding_source = str(pathlib.Path(source_path).resolve(strict=True))
            target_candidate = pathlib.Path(target_path)
            try:
                target = str(target_candidate.resolve(strict=True))
            except FileNotFoundError:
                target = str(target_candidate.parent.resolve(strict=True) / target_candidate.name)
        except (OSError, RuntimeError):
            continue
        pair = [binding_source, target]
        if pair not in bindings:
            bindings.append(pair)
    return bindings


def _resolved_overlay(overlay) -> dict[str, str] | None:
    if overlay is None:
        return None
    names = ("lower", "target", "upper", "work", "storage")
    try:
        values = [str(pathlib.Path(path).resolve(strict=True)) for path in overlay]
    except (OSError, RuntimeError):
        return None
    return dict(zip(names, values, strict=True)) if len(values) == len(names) else None


def _contained_entry_env(*readonly_paths, jail_root, writable_paths=(), bind_files=(),
                         protected_relatives=(), overlay=None,
                         execution_cwd=None, base=None, secret_env_names=()) -> dict:
    import json

    source = os.environ if base is None else base
    protected = _resolved_existing_paths(readonly_paths)
    writable = _resolved_existing_paths(writable_paths)
    bindings = _resolved_bindings(bind_files)
    env = entry_env(source, secret_env_names=secret_env_names)
    env.update({"TMPDIR": "/tmp", "TMP": "/tmp", "TEMP": "/tmp"})
    env[_CONTAINMENT_PATHS_ENV] = json.dumps({
        "jail_root": str(pathlib.Path(jail_root).resolve(strict=True)),
        "readonly": protected,
        "writable": writable,
        "bind_files": bindings,
        "protected_relatives": list(protected_relatives),
        "overlay": _resolved_overlay(overlay),
        "execution_cwd": (str(pathlib.Path(execution_cwd).resolve(strict=True))
                          if execution_cwd is not None else None),
    }, separators=(",", ":"))
    return env


def reset_isolation_cache() -> None:
    global _ISOLATION_CACHE, _ISOLATION_DIAGNOSIS
    _ISOLATION_CACHE = None
    _ISOLATION_DIAGNOSIS = ()


EXPECTATIONS = ("fatal_signal", "output_marker")

UNMEASURED_EXPECTATIONS = ("unhandled_exception",)

DIFFERENTIAL_NONZERO_EXIT = False

UNHANDLED_EXCEPTION = False

DEFAULT_TIMEOUT = 60

MAX_CAPTURED_BYTES = 16 * 1024 * 1024

TRUNCATION_NOTE = "\n[shard: output truncated at {} bytes]\n"


def _finished_capture(chunks: list[bytes], seen: list[int], *, cap: int,
                      text: bool, errors: str | None) -> str | bytes:
    raw = b"".join(chunks)
    if seen[0] > cap:
        raw += TRUNCATION_NOTE.format(seen[0]).encode()
    return raw.decode("utf-8", errors or "replace") if text else raw


def bounded_run(argv, *, cwd=None, capture_output=True, text=True, errors="replace",
                timeout=None, env=None, cap: int = MAX_CAPTURED_BYTES, **kw):
    import threading

    def drain(stream, sink: list, seen: list) -> None:
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                room = cap - seen[0]
                if room > 0:
                    sink.append(chunk[:room])
                seen[0] += len(chunk)
        except (OSError, ValueError):
            return
        finally:
            try:
                stream.close()
            except OSError:
                pass

    kw["start_new_session"] = True
    stdin = kw.pop("stdin", subprocess.DEVNULL)
    proc = subprocess.Popen(argv, cwd=cwd, stdin=stdin, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env, **kw)
    out: list[bytes] = []
    err: list[bytes] = []
    out_seen, err_seen = [0], [0]
    readers = [threading.Thread(target=drain, args=(proc.stdout, out, out_seen), daemon=True),
               threading.Thread(target=drain, args=(proc.stderr, err, err_seen), daemon=True)]
    for r in readers:
        r.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_group(proc.pid)
        proc.wait()
        for r in readers:
            r.join(timeout=5)
        raise
    _kill_process_group(proc.pid)
    for r in readers:
        r.join(timeout=5)

    return subprocess.CompletedProcess(argv, proc.returncode,
                                       stdout=_finished_capture(out, out_seen, cap=cap, text=text,
                                                                errors=errors),
                                       stderr=_finished_capture(err, err_seen, cap=cap, text=text,
                                                                errors=errors))


class ContainmentUnavailable(RuntimeError):
    pass


def contained_run(argv, *, cwd, readonly_paths=(), writable_paths=(), timeout=None,
                  base_env=None, secret_env_names=()):
    prefix = isolation_prefix()
    if not network_isolated(prefix):
        raise ContainmentUnavailable(
            "the required private PID, mount, procfs and network boundary is unavailable"
        )
    with tempfile.TemporaryDirectory(prefix="shard-host-command-root-") as jail_root:
        proc = bounded_run(
            [*prefix, *argv], cwd=str(cwd), capture_output=True, text=True, errors="replace",
            timeout=timeout,
            env=_contained_entry_env(
                *readonly_paths, jail_root=jail_root, writable_paths=writable_paths,
                execution_cwd=cwd, base=base_env, secret_env_names=secret_env_names,
            ),
        )
    stdout = redact_secrets(proc.stdout or "", secret_env_names=secret_env_names)
    stderr = redact_secrets(proc.stderr or "", secret_env_names=secret_env_names)
    if proc.returncode == 125 and stderr.startswith(_CONTAINMENT_ERROR):
        raise ContainmentUnavailable(stderr.strip())
    return subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)


def _kill_process_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


MAX_EVIDENCE_CHARS = 4000

TRACEBACK_TOKENS = ("Traceback (most recent call last):",)


def offered_expectations() -> tuple[str, ...]:
    return (EXPECTATIONS
            + (("nonzero_exit",) if DIFFERENTIAL_NONZERO_EXIT else ())
            + (UNMEASURED_EXPECTATIONS if UNHANDLED_EXCEPTION else ()))


@dataclass(frozen=True)
class WitnessSpec:

    entry: str
    expectation: str
    payload: bytes = b""
    marker: str = ""


@dataclass(frozen=True)
class _TrialPlan:
    snapshot: SourceSnapshot
    prefix: tuple[str, ...]
    runner: object
    timeout: int
    input_path: pathlib.Path
    run_path: pathlib.Path
    digest: str
    protected: tuple[tuple[str, pathlib.Path, bytes], ...]
    secret_env_names: tuple[str, ...]


@dataclass(frozen=True)
class _TrialExecution:

    prefix: tuple[str, ...]
    runner: object
    timeout: int
    protected: tuple[tuple[str, pathlib.Path, bytes], ...] = ()
    logical_input: str | None = None
    verify_original: bool = True
    expected_input: bytes | None = None
    secret_env_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ProtectedInput:
    label: str
    path: pathlib.Path
    expected: bytes
    device: int
    inode: int


@dataclass(frozen=True)
class Witness:

    demonstrated: bool
    expectation: str
    exit_code: int | None = None
    entry_digest: str = ""
    evidence: str = ""
    refusal: str = ""
    why_not: str = ""
    controls: tuple[str, ...] = ()
    timed_out: bool = False
    input_path: str = ""
    input_bytes: bytes | None = None

    @property
    def gate_eligible(self) -> bool:
        return self.demonstrated


def resolve_entry(repo, entry: str) -> pathlib.Path | None:
    raw = (entry or "").strip()
    if not raw or pathlib.PurePath(raw).is_absolute():
        return None
    root = pathlib.Path(repo).resolve()
    try:
        resolved = (root / raw).resolve()
        resolved.relative_to(root)
    except (ValueError, OSError):
        return None
    if resolved.name.startswith("-"):
        return None
    return resolved


BENIGN_SUFFIX = ".benign"

MAX_BENIGN_CONTROLS = 8


def benign_controls(repo, entry: str) -> tuple[tuple[pathlib.Path, ...], int]:
    resolved = resolve_entry(repo, (entry or "") + BENIGN_SUFFIX)
    if resolved is None:
        return (), 0
    try:
        if resolved.is_file():
            return (resolved,), 0
        if not resolved.is_dir():
            return (), 0
        found = sorted(p for p in resolved.iterdir() if p.is_file())
    except OSError:
        return (), 0
    return tuple(found[:MAX_BENIGN_CONTROLS]), max(0, len(found) - MAX_BENIGN_CONTROLS)


def witness_contract(repo, entry: str | None) -> tuple[str, ...]:
    if not entry:
        return ()
    root = pathlib.Path(repo).resolve()
    out = {entry}
    controls, _dropped = benign_controls(repo, entry)
    for path in controls:
        try:
            out.add(path.resolve().relative_to(root).as_posix())
        except (OSError, ValueError):
            continue
    return tuple(sorted(out))


_PY_FRAME = re.compile(r'File "([^"]+)", line (\d+)')

_PATH_LINE = re.compile(r"([\w./+-]+\.[A-Za-z][\w+]*):(\d+)(?::\d+)?")

_NODE_FRAME = re.compile(r"^\s+at (?:.*?\()?([^\s()]+):(\d+):\d+\)?$", re.M)

FIRST, LAST = 0, -1

_JVM_FRAME = re.compile(r"^\s+at\s+\S+\((\S+?):(\d+)\)\s*$", re.M)

_RUBY_FRAME = re.compile(r"^\s*(?:from\s+)?(\S+?):(\d+):in[ \t]", re.M)

_GO_FRAME = re.compile(r"^\t(\S+?\.go):(\d+)(?:\s|$)", re.M)

_CLR_FRAME = re.compile(r"^\s+at\s+.*?\sin\s(\S+?):line\s+(\d+)\s*$", re.M)

_SAN_FRAME = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+in\s+.+?\s+(\S+?):(\d+)(?::\d+)?\s*$", re.M)

_RUNTIME_FRAMES: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("cpython", _PY_FRAME, LAST),
    ("v8", _NODE_FRAME, FIRST),
    ("jvm", _JVM_FRAME, FIRST),
    ("ruby", _RUBY_FRAME, FIRST),
    ("go", _GO_FRAME, FIRST),
    ("clr", _CLR_FRAME, FIRST),
    ("sanitizer", _SAN_FRAME, FIRST),
)


def payload_readings(payload: bytes) -> tuple[str, ...]:
    if not payload:
        return ("",)
    readings = [
        payload.decode("utf-8", errors="replace"),
        payload.decode("utf-8", errors="ignore"),
        payload.decode("latin-1"),
        bytes(b for b in payload if b < 0x80).decode("ascii"),
        bytes(b for b in payload if 0x20 <= b <= 0x7e).decode("ascii"),
        payload.decode("utf-16-le", errors="ignore"),
        payload.decode("utf-16-be", errors="ignore"),
    ]
    return tuple(dict.fromkeys(readings))


def observed_location(evidence: str, repo, *, payload: bytes = b"") -> tuple[str, int] | None:
    if not evidence:
        return None
    root = pathlib.Path(repo).resolve()

    def _locations(pattern, text):
        return [(rel, int(m.group(2))) for m in pattern.finditer(text)
                if (rel := _inside(root, m.group(1))) is not None]

    forged = set()
    for payload_text in payload_readings(payload):
        forged |= set(_locations(_PATH_LINE, payload_text))
        for _name, _pattern, _end in _RUNTIME_FRAMES:
            forged |= set(_locations(_pattern, payload_text))

    def _claims(pattern):
        return [loc for loc in _locations(pattern, evidence) if loc not in forged]

    for _name, _pattern, _end in _RUNTIME_FRAMES:
        if _name == "sanitizer" and any(loc in forged for loc in _locations(_pattern, evidence)):
            return None

    other = set(_claims(_PATH_LINE))
    runtimes = [(name, _claims(pattern), end) for name, pattern, end in _RUNTIME_FRAMES]

    answers, covered = set(), set()
    for _name, claims, end in runtimes:
        if claims:
            answers.add(claims[end])
            covered |= set(claims)

    if len(answers) == 1 and not (other - covered):
        return answers.pop()

    found = other | covered
    return found.pop() if len(found) == 1 else None


def _inside(root: pathlib.Path, raw: str) -> str | None:
    try:
        resolved = (root / raw).resolve() if not pathlib.PurePath(raw).is_absolute() else \
            pathlib.Path(raw).resolve()
        rel = resolved.relative_to(root)
    except (ValueError, OSError):
        return None
    return str(rel) if resolved.is_file() else None


def entry_digest(repo, entry: str) -> str | None:
    resolved = resolve_entry(repo, entry)
    if resolved is None:
        return None
    try:
        data = resolved.read_bytes()
    except OSError:
        return None
    return hashlib.sha256(data).hexdigest()[:16]


def controls_digest(repo, entry: str | None) -> str:
    controls, dropped = benign_controls(repo, entry or "")
    root = pathlib.Path(repo).resolve()
    digest = hashlib.sha256()
    digest.update(f"dropped:{dropped}\n".encode())
    for path in controls:
        try:
            name = path.resolve().relative_to(root).as_posix()
        except (OSError, ValueError):
            name = path.name
        try:
            data = path.read_bytes()
        except OSError:
            data = b"\x00SHARD-UNREADABLE-CONTROL"
        digest.update(f"{len(name)}:{name}:{len(data)}:".encode())
        digest.update(data)
    return digest.hexdigest()[:16]


def adjudicate(spec: WitnessSpec, repo, *, baseline_digest: str | None,
               baseline_controls: str | None = None,
               runner=bounded_run, timeout: int = DEFAULT_TIMEOUT,
               workdir=None, source_snapshot: SourceSnapshot | None = None,
               protected_inputs: tuple[tuple[str, pathlib.Path, bytes], ...] = (),
               secret_env_names: tuple[str, ...] = ()) -> Witness:
    owned = source_snapshot is None
    if source_snapshot is None:
        try:
            source_snapshot = SourceSnapshot.capture(repo)
        except SnapshotError as e:
            return _refuse(spec, SOURCE_ISOLATION_REFUSAL +
                           f"source could not be staged as a pristine tree: {e}; "
                           f"nothing was adjudicated")
    try:
        return _adjudicate_pristine(spec, source_snapshot, baseline_digest=baseline_digest,
                                    baseline_controls=baseline_controls, runner=runner,
                                    timeout=timeout, workdir=workdir,
                                    protected_inputs=protected_inputs,
                                    secret_env_names=secret_env_names)
    finally:
        if owned:
            source_snapshot.close()


def _adjudicate_pristine(spec: WitnessSpec, snapshot: SourceSnapshot, *,
                         baseline_digest: str | None, baseline_controls: str | None,
                         runner, timeout: int, workdir,
                         protected_inputs: tuple[tuple[str, pathlib.Path, bytes], ...],
                         secret_env_names: tuple[str, ...]) -> Witness:
    repo = snapshot.source
    try:
        snapshot.verify_original()
        snapshot.verify_source()
    except SnapshotError as e:
        return _refuse(spec, SOURCE_ISOLATION_REFUSAL +
                       f"pristine source verification failed: {e}; nothing was adjudicated")

    refusal, _resolved, digest = _preconditions(spec, repo, baseline_digest)
    if refusal is not None:
        return refusal
    if changed := _controls_changed(spec, repo, baseline_controls, digest,
                                    when="before this claim was adjudicated"):
        return changed

    try:
        input_path = _stage_payload(spec.payload, workdir)
    except OSError as e:
        return _refuse(spec, f"could not stage the payload: {e}", digest=digest)

    run_path = input_path.with_name("shard_witness_run")
    try:
        run_path.write_bytes(spec.payload)
    except OSError as e:
        return _refuse(spec, f"could not stage the payload for execution: {e}", digest=digest)
    prefix = isolation_prefix()
    if not network_isolated(prefix):
        return _refuse(
            spec,
            CONTAINMENT_REFUSAL + "this runner cannot create the private PID, mount, procfs and "
            "network boundary, so no customer-authored entry point was executed",
            digest=digest,
        )
    try:
        protected = (*protected_inputs,
                     ("preserved witness input", input_path, spec.payload))
        proc = _execute_trial(snapshot, spec.entry, run_path, _TrialExecution(
            prefix, runner, timeout, protected=protected, expected_input=spec.payload,
            secret_env_names=secret_env_names,
        ))
    except subprocess.TimeoutExpired:
        return Witness(demonstrated=False, expectation=spec.expectation, entry_digest=digest,
                       evidence=f"the entry point did not finish within {timeout}s",
                       why_not=f"the entry point did not finish within {timeout}s, and a hang is not "
                               f"a demonstration",
                       timed_out=True, input_path=str(input_path), input_bytes=spec.payload)
    except SnapshotError as e:
        return _refuse(spec, SOURCE_ISOLATION_REFUSAL +
                       f"pristine witness trial was refused: {e}; nothing was adjudicated",
                       digest=digest)
    except (OSError, subprocess.SubprocessError) as e:
        return _refuse(spec, f"the entry point could not be executed: {e}", digest=digest)

    output = redact_secrets(
        original_paths((proc.stdout or "") + (proc.stderr or ""), snapshot),
        secret_env_names=secret_env_names,
    )
    if refused := _nothing_adjudicated(spec, proc, output, digest=digest, input_path=input_path):
        return refused
    plan = _TrialPlan(snapshot, prefix, runner, timeout, input_path, run_path, digest, protected,
                      secret_env_names)
    return _controlled_verdict(spec, plan, proc=proc, output=output)


def _preconditions(spec: WitnessSpec, repo, baseline_digest: str | None
                   ) -> tuple[Witness, None, None] | tuple[None, pathlib.Path, str]:
    if spec.expectation not in offered_expectations():
        return _refuse(spec, f"unknown expectation {spec.expectation!r}"), None, None
    if spec.expectation == "output_marker" and not spec.marker:
        return _refuse(spec, "output_marker requires a marker to look for"), None, None

    resolved = resolve_entry(repo, spec.entry)
    if resolved is None:
        return _refuse(spec, f"entry point {spec.entry!r} is not a repository-relative path inside "
                             f"the checkout; the customer declares it in .shard/"), None, None
    digest = entry_digest(repo, spec.entry)
    if digest is None:
        return (_refuse(spec, f"no entry point at {spec.entry!r}; the customer declares it in .shard/"),
                None, None)
    if baseline_digest is None:
        return _refuse(spec, "the entry point did not exist when the run started"), None, None
    if digest != baseline_digest:
        return _refuse(spec, "the entry point changed during the run", digest=digest), None, None
    return None, resolved, digest


def _controls_changed(spec: WitnessSpec, repo, baseline_controls: str | None, digest: str, *,
                      when: str) -> Witness | None:
    if baseline_controls is None or controls_digest(repo, spec.entry) == baseline_controls:
        return None
    return _refuse(spec, f"the benign controls declared at {spec.entry}{BENIGN_SUFFIX} changed "
                         f"{when}, so this finding would be graded against different controls from "
                         f"the ones this repository declared, and nothing was adjudicated",
                   digest=digest)


def _stage_payload(payload: bytes, workdir) -> pathlib.Path:
    if workdir is not None:
        parent = pathlib.Path(workdir)
        parent.mkdir(parents=True, exist_ok=True)
        work = pathlib.Path(tempfile.mkdtemp(prefix="claim-", dir=parent))
        input_path = work / "shard_witness_input"
        input_path.write_bytes(payload)
    else:
        scratch = tempfile.mkdtemp(prefix="shard-witness-")
        input_path = pathlib.Path(scratch) / "shard_witness_input"
        input_path.write_bytes(payload)
    return input_path


def _nothing_adjudicated(spec: WitnessSpec, proc, output: str, *, digest: str,
                         input_path: pathlib.Path) -> Witness | None:
    if missing := _missing_runtime(proc.returncode, output):
        return _refuse(spec, f"the entry point could not run: {missing}. Nothing was adjudicated, so "
                             f"this is NOT a clean result — the release image does not carry every "
                             f"runtime or build SDK. Build the target in an earlier trusted step or "
                             f"use an adapter supported by the image; preflight reports its runtime "
                             f"inventory", digest=digest)

    code = _normalise(proc.returncode)
    if code in TIMEOUT_KILL_CODES:
        return Witness(
            demonstrated=False, expectation=spec.expectation, exit_code=proc.returncode,
            entry_digest=digest, evidence=output[-MAX_EVIDENCE_CHARS:], input_path=str(input_path),
            input_bytes=spec.payload,
            refusal=f"the entry point was KILLED (rc={code}) rather than finishing, so nothing was "
                    f"adjudicated and this is NOT a clean result. The commonest cause is the reported "
                    f"input itself — a payload that kills or hangs the entry point leaves no exit "
                    f"status and no output to observe, so it destroys the evidence it was meant to "
                    f"produce. Read the preserved input in the bundle before suspecting the machine")
    return None


def _controlled_verdict(spec: WitnessSpec, plan: _TrialPlan, *, proc, output: str) -> Witness:
    demonstrated, why_not = _adjudge(spec, proc.returncode, output)
    ran: list[str] = []
    repo = plan.snapshot.source

    if demonstrated and _baseline_required(spec):
        try:
            controls, dropped = _stage_controls(repo, spec)
        except OSError as e:
            return _refuse(spec, f"the benign control declared at {spec.entry}{BENIGN_SUFFIX} could not "
                                 f"be staged ({e}), so nothing was adjudicated", digest=plan.digest)
        if dropped:
            output += (f"\n[shard] {dropped} further benign control(s) beyond the first "
                       f"{MAX_BENIGN_CONTROLS} were NOT run; this verdict is checked against fewer "
                       f"controls than {spec.entry}{BENIGN_SUFFIX} declares")
        for what, control in controls:
            try:
                plan.run_path.write_bytes(control)
            except OSError as e:
                return _refuse(spec, f"the run on {what} could not be staged: {e}",
                               digest=plan.digest)
            try:
                baseline = _run_trial(
                    plan.snapshot, spec.entry, plan.run_path, prefix=plan.prefix,
                    runner=plan.runner, timeout=plan.timeout,
                    protected=plan.protected, expected_input=control,
                    secret_env_names=plan.secret_env_names,
                )
            except SnapshotError as e:
                return _refuse(spec, SOURCE_ISOLATION_REFUSAL +
                               f"the run on {what} was refused: {e}; nothing was adjudicated",
                               digest=plan.digest)
            if baseline is None:
                return _refuse(spec, f"the run on {what} could not be completed, so "
                                     f"{_OBSERVED[spec.expectation]} could not be attributed to the "
                                     f"payload", digest=plan.digest)
            ran.append(what)
            contradiction = _baseline_contradicts(spec, *baseline, control=what)
            if contradiction:
                demonstrated = False
                why_not = f"{contradiction}, so it was not caused by the reported input"
                hint = _payload_sentinels(spec.payload, output, baseline[1])
                if hint:
                    why_not += (f". These string(s) came from the payload, appear in this run's "
                                f"output and are ABSENT from the control: {hint} — one of them is "
                                f"the marker that would discriminate")
                output += f"\n[shard] {why_not}"
                break

    return Witness(
        demonstrated=demonstrated,
        expectation=spec.expectation,
        exit_code=proc.returncode,
        entry_digest=plan.digest,
        evidence=output[-MAX_EVIDENCE_CHARS:],
        input_path=str(plan.input_path),
        input_bytes=spec.payload,
        controls=tuple(ran),
        why_not=why_not,
    )


INHERITED, INTRODUCED, UNATTRIBUTED = "inherited", "introduced", "unattributed"


def attribute(spec: WitnessSpec, base_repo, *, runner=bounded_run, timeout: int = DEFAULT_TIMEOUT,
              workdir=None, source_snapshot: SourceSnapshot | None = None,
              protected_inputs: tuple[tuple[str, pathlib.Path, bytes], ...] = (),
              secret_env_names: tuple[str, ...] = ()) -> tuple[str, str]:
    if base_repo is None:
        return UNATTRIBUTED, "no base revision was available to compare against"
    owned = source_snapshot is None
    if source_snapshot is None:
        try:
            source_snapshot = SourceSnapshot.capture(base_repo)
        except SnapshotError as e:
            return UNATTRIBUTED, SOURCE_ISOLATION_REFUSAL + \
                f"the base revision could not be snapshotted: {e}"
    try:
        try:
            return _attribute_pristine(spec, source_snapshot, runner=runner, timeout=timeout,
                                       workdir=workdir, protected_inputs=protected_inputs,
                                       secret_env_names=secret_env_names)
        except SnapshotError as e:
            return UNATTRIBUTED, SOURCE_ISOLATION_REFUSAL + str(e)
    finally:
        if owned:
            source_snapshot.close()


def _attribute_pristine(spec: WitnessSpec, snapshot: SourceSnapshot, *, runner, timeout: int,
                        workdir,
                        protected_inputs: tuple[tuple[str, pathlib.Path, bytes], ...],
                        secret_env_names: tuple[str, ...],
                        ) -> tuple[str, str]:
    base_repo = snapshot.source
    try:
        snapshot.verify_original()
        snapshot.verify_source()
    except SnapshotError as e:
        raise SnapshotError(f"the base revision's pristine source could not be verified: {e}") from e
    digest = entry_digest(base_repo, spec.entry)
    if digest is None:
        return UNATTRIBUTED, (f"{spec.entry} did not exist at the base revision, so the defect could "
                              f"not be re-run against the code as it was")

    base_controls = controls_digest(base_repo, spec.entry)

    try:
        probe = _base_control(spec, snapshot, runner=runner, timeout=timeout, workdir=workdir,
                              protected_inputs=protected_inputs,
                              secret_env_names=secret_env_names)
    except SnapshotError as e:
        return UNATTRIBUTED, SOURCE_ISOLATION_REFUSAL + \
            f"the defect could not be re-run at the base revision: {e}"
    if probe != 0:
        return UNATTRIBUTED, (f"the entry point did not run cleanly at the base revision "
                              f"(exit {probe}), so a non-reproduction there is not evidence the "
                              f"defect is new — a base checkout carries no build artifacts")

    before = adjudicate(spec, base_repo, baseline_digest=digest, baseline_controls=base_controls,
                        runner=runner, timeout=timeout, workdir=workdir,
                        source_snapshot=snapshot, protected_inputs=protected_inputs,
                        secret_env_names=secret_env_names)
    if before.refusal:
        if before.refusal.startswith(SOURCE_ISOLATION_REFUSAL):
            return UNATTRIBUTED, before.refusal
        return UNATTRIBUTED, f"the defect could not be re-run at the base revision: {before.refusal}"
    if before.timed_out:
        return UNATTRIBUTED, (f"the defect could not be re-run at the base revision: "
                              f"{before.evidence}, so a non-reproduction there is not evidence the "
                              f"defect is new")
    if before.demonstrated:
        return INHERITED, ("the same input demonstrates the same defect at the base revision, so this "
                           "change did not introduce it")
    return INTRODUCED, ("the same input does NOT demonstrate at the base revision, so this change "
                        "introduced it")


def _base_control(spec: WitnessSpec, snapshot: SourceSnapshot, *, runner, timeout, workdir,
                  protected_inputs: tuple[tuple[str, pathlib.Path, bytes], ...],
                  secret_env_names: tuple[str, ...]) -> int | None:
    base_repo = snapshot.source
    resolved = resolve_entry(base_repo, spec.entry)
    if resolved is None:
        return None
    controls, _dropped = benign_controls(base_repo, spec.entry)
    try:
        scratch = pathlib.Path(workdir) if workdir is not None else pathlib.Path(
            tempfile.mkdtemp(prefix="shard-attribute-"))
        scratch.mkdir(parents=True, exist_ok=True)
        probe = scratch / "shard_base_control"
        probe_bytes = controls[0].read_bytes() if controls else b""
        probe.write_bytes(probe_bytes)
    except OSError:
        return None
    protected = (*protected_inputs, ("base control input", probe, probe_bytes))
    prefix = isolation_prefix()
    if not network_isolated(prefix):
        return None
    result = _run_trial(
        snapshot, spec.entry, probe, prefix=prefix, runner=runner, timeout=timeout,
        protected=protected, expected_input=probe_bytes, secret_env_names=secret_env_names,
    )
    return None if result is None else result[0]


def _stage_controls(repo, spec: WitnessSpec) -> tuple[list[tuple[str, bytes]], int]:
    controls = [("an empty payload", b"")]
    benign, dropped = benign_controls(repo, spec.entry)
    root = pathlib.Path(repo).resolve()
    for source in benign:
        data = source.read_bytes()
        controls.append((f"the benign input this repository declares at {source.relative_to(root)}",
                         data))
    return controls, dropped


def _execute_trial(snapshot: SourceSnapshot, entry: str, input_path: pathlib.Path,
                   execution: _TrialExecution):
    if not network_isolated(execution.prefix):
        raise SnapshotError(
            "the private PID, mount, procfs and network boundary is unavailable; the entry point "
            "was not executed"
        )
    if execution.verify_original:
        snapshot.verify_original()
    expected_input, sealed, staged_input, staged_identity = _prepare_trial_input(
        snapshot, input_path, execution.expected_input, execution.protected,
    )
    repo = snapshot.materialize()
    resolved = resolve_entry(repo, entry)
    if resolved is None:
        raise SnapshotError(f"entry point {entry!r} disappeared from a materialised trial")
    if execution.logical_input is None:
        bindings = ((staged_input, input_path),)
        executed_entry, executed_input = str(resolved), str(input_path)
        visible_inputs = (input_path,)
    else:
        logical_target = repo / execution.logical_input
        bindings = ((staged_input, logical_target),)
        executed_entry, executed_input = entry, execution.logical_input
        visible_inputs = ()
    argv = [*execution.prefix, "bash", "--", executed_entry, executed_input]
    failure = None
    proc = None
    with tempfile.TemporaryDirectory(prefix="shard-witness-overlay-") as overlay_storage:
        private = pathlib.Path(overlay_storage)
        storage, jail = private / "overlay", private / "jail"
        upper, work = storage / "upper", storage / "work"
        for path in (upper, work, jail):
            path.mkdir(parents=True, exist_ok=True)
        try:
            proc = execution.runner(
                argv, cwd=str(repo), capture_output=True, text=True, errors="replace",
                timeout=execution.timeout,
                env=_contained_entry_env(
                    *visible_inputs,
                    jail_root=jail,
                    writable_paths=(),
                    bind_files=bindings,
                    protected_relatives=(entry.path for entry in snapshot.manifest
                                         if entry.kind != "dir"),
                    overlay=(snapshot.source, repo, upper, work, storage),
                    execution_cwd=repo,
                    secret_env_names=execution.secret_env_names,
                ),
            )
        except (OSError, subprocess.SubprocessError) as e:
            failure = e
        failures = _trial_boundary_failures(
            snapshot, sealed, staged_input, expected_input, staged_identity, upper,
            verify_original=execution.verify_original,
        )
    if failures:
        raise SnapshotError(
            "protected trial state changed while the entry point was running: " + "; ".join(failures)
        )
    if failure is not None:
        raise failure
    stderr = redact_secrets(proc.stderr or "", secret_env_names=execution.secret_env_names)
    if (getattr(proc, "returncode", None) == 125
            and stderr.startswith(_CONTAINMENT_ERROR)):
        raise SnapshotError(stderr.strip())
    return proc


def _prepare_trial_input(snapshot: SourceSnapshot, input_path: pathlib.Path,
                         expected: bytes | None,
                         protected: tuple[tuple[str, pathlib.Path, bytes], ...],
                         ) -> tuple[bytes, tuple[_ProtectedInput, ...], pathlib.Path,
                                    _ProtectedInput]:
    if expected is None:
        try:
            expected = input_path.read_bytes()
        except OSError as exc:
            raise SnapshotError(f"trial input became unreadable: {exc}") from exc
    input_identity = _read_protected_input("trial input", input_path, expected)
    sealed = (*_seal_protected_inputs(protected), input_identity)
    staged = snapshot.materialize_input(expected)
    staged_identity = _read_protected_input("fresh trial input", staged, expected)
    return expected, sealed, staged, staged_identity


def _trial_boundary_failures(snapshot: SourceSnapshot, sealed: tuple[_ProtectedInput, ...],
                             staged: pathlib.Path, expected: bytes,
                             staged_identity: _ProtectedInput, upper: pathlib.Path, *,
                             verify_original: bool) -> list[str]:
    checks = [
        lambda: _verify_protected_inputs(sealed),
        lambda: _read_protected_input("fresh trial input", staged, expected,
                                      identity=staged_identity),
        lambda: _verify_overlay(snapshot, upper),
        snapshot.verify_trial,
        snapshot.verify_source,
    ]
    if verify_original:
        checks.append(snapshot.verify_original)
    failures = []
    for check in checks:
        try:
            check()
        except SnapshotError as exc:
            failures.append(str(exc))
    return failures


def _verify_overlay(snapshot: SourceSnapshot, upper: pathlib.Path) -> None:
    for expected in snapshot.manifest:
        if expected.kind == "dir":
            continue
        candidate = upper.joinpath(*pathlib.PurePosixPath(expected.path).parts)
        if os.path.lexists(candidate):
            raise SnapshotError(
                f"witness execution transiently changed pristine source: {expected.path}"
            )


def _seal_protected_inputs(
        protected: tuple[tuple[str, pathlib.Path, bytes], ...]) -> tuple[_ProtectedInput, ...]:
    return tuple(_read_protected_input(label, path, expected) for label, path, expected in protected)


def _verify_protected_inputs(protected: tuple[_ProtectedInput, ...]) -> None:
    for sealed in protected:
        _read_protected_input(sealed.label, sealed.path, sealed.expected, identity=sealed)


def _read_protected_input(label: str, path: pathlib.Path, expected: bytes, *,
                          identity: _ProtectedInput | None = None) -> _ProtectedInput:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as e:
        raise SnapshotError(f"{label} became unreadable or stopped being a regular file: {e}") from e
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise SnapshotError(f"{label} stopped being one private regular file")
        if status.st_size != len(expected):
            raise SnapshotError(f"{label} no longer has the size supplied to the entry point")
        if identity is not None and (status.st_dev, status.st_ino) != (
                identity.device, identity.inode):
            raise SnapshotError(f"{label} was replaced after it was staged")
        chunks = []
        remaining = len(expected)
        while remaining:
            block = os.read(descriptor, min(remaining, 1024 * 1024))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        actual = b"".join(chunks)
        if remaining or os.read(descriptor, 1) or actual != expected:
            raise SnapshotError(f"{label} no longer contains the bytes supplied to the entry point")
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    return _ProtectedInput(label, path, expected, status.st_dev, status.st_ino)


def _run_trial(snapshot: SourceSnapshot, entry: str, input_path: pathlib.Path, *,
               prefix: tuple[str, ...], runner, timeout: int,
               protected: tuple[tuple[str, pathlib.Path, bytes], ...] = (),
               expected_input: bytes | None = None,
               secret_env_names: tuple[str, ...] = (),
               ) -> tuple[int | None, str] | None:
    try:
        proc = _execute_trial(snapshot, entry, input_path, _TrialExecution(
            prefix, runner, timeout, protected=protected, expected_input=expected_input,
            secret_env_names=secret_env_names,
        ))
    except (OSError, subprocess.SubprocessError):
        return None
    rendered = original_paths((proc.stdout or "") + (proc.stderr or ""), snapshot)
    return proc.returncode, redact_secrets(rendered, secret_env_names=secret_env_names)


def _run(runner, argv: list[str], repo, timeout: int, *,
         secret_env_names: tuple[str, ...] = ()) -> tuple[int | None, str] | None:
    try:
        proc = runner(argv, cwd=str(repo), capture_output=True, text=True, errors="replace",
                      timeout=timeout, env=entry_env(secret_env_names=secret_env_names))
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.returncode, redact_secrets(
        (proc.stdout or "") + (proc.stderr or ""), secret_env_names=secret_env_names,
    )


_OBSERVED = {
    "output_marker": "the marker",
    "nonzero_exit": "the failure",
    "unhandled_exception": "the traceback",
    "fatal_signal": "the fatal signal",
}


def _baseline_required(spec: WitnessSpec) -> bool:
    if spec.expectation == "nonzero_exit":
        return DIFFERENTIAL_NONZERO_EXIT
    return spec.expectation in ("output_marker", "unhandled_exception", "fatal_signal")


MIN_SENTINEL_CHARS = 4

MAX_SENTINELS = 3


def _payload_sentinels(payload: bytes, attack_output: str, control_output: str) -> str:
    words: set[str] = set()
    for reading in payload_readings(payload):
        words |= set(re.findall(r"[A-Za-z0-9_]{%d,}" % MIN_SENTINEL_CHARS, reading))
    found = sorted(w for w in words if w in attack_output and w not in control_output)
    found.sort(key=len, reverse=True)
    return ", ".join(repr(w) for w in found[:MAX_SENTINELS])


def _baseline_contradicts(spec: WitnessSpec, rc: int | None, output: str, *, control: str) -> str:
    if spec.expectation == "output_marker":
        if spec.marker in output:
            return f"the marker {spec.marker!r} is also present when the entry point runs on {control}"
        return ""
    if spec.expectation == "fatal_signal":
        code = _normalise(rc) if rc is not None else None
        if code in FATAL_SIGNAL_CODES:
            return (f"the entry point also dies on a fatal signal (rc={code}) when it runs on "
                    f"{control}, so the payload is not what causes the fault")
        return ""
    if spec.expectation == "nonzero_exit":
        code = _normalise(rc) if rc is not None else None
        if code != 0:
            return f"the entry point also exits non-zero (rc={code}) when it runs on {control}"
        return ""
    if _traceback_not_from_payload(spec, output):
        return f"a traceback is also produced when the entry point runs on {control}"
    return ""


def _adjudge(spec: WitnessSpec, rc: int | None, output: str) -> tuple[bool, str]:
    if rc is None:
        return False, "the entry point produced no exit status"
    code = _normalise(rc)
    if code in TIMEOUT_KILL_CODES:
        return False, (f"the entry point was killed (rc={code}) rather than finishing, and a kill is "
                       f"not a demonstration whatever the expectation was")
    if spec.expectation == "fatal_signal":
        if code in FATAL_SIGNAL_CODES:
            return True, ""
        return False, f"the entry point exited {code} rather than dying on a fatal signal"
    if spec.expectation == "nonzero_exit":
        if code != 0:
            return True, ""
        return False, "the entry point exited 0"
    if spec.expectation == "unhandled_exception":
        if code == 0:
            return False, "the entry point exited 0, so no exception went unhandled"
        if not _traceback_not_from_payload(spec, output):
            if any(token in output for token in TRACEBACK_TOKENS):
                return False, ("the only traceback in the output is text the payload itself carried, "
                               "so it is not evidence the entry point raised anything")
            return False, (f"the entry point exited {code} but printed no traceback, which is a "
                           f"designed rejection rather than an unhandled exception")
        return True, ""
    if not spec.marker:
        return False, "no marker was proposed, so there was nothing to look for"
    if self_defeating := self_defeating_marker(spec.marker, spec.payload):
        return False, self_defeating
    if spec.marker in output:
        return True, ""
    if near := _near_miss(spec.marker, output):
        return False, (f"the marker {spec.marker!r} is not present in the entry point's output, but "
                       f"{near!r} is — they differ only in their digits, so this looks like a marker "
                       f"whose numbers were WORKED OUT rather than read")
    return False, f"the marker {spec.marker!r} is not present in the entry point's output"


_DIGITS = re.compile(r"\d+")


def _near_miss(marker: str, output: str) -> str:
    if not marker or not _DIGITS.search(marker):
        return ""
    shape = _DIGITS.sub("#", marker)
    for line in output.splitlines():
        line = line.strip()
        if line and line != marker and _DIGITS.sub("#", line) == shape:
            return line
    return ""


def _traceback_not_from_payload(spec: WitnessSpec, output: str) -> str:
    readings = payload_readings(spec.payload)
    for token in TRACEBACK_TOKENS:
        if token in output and not any(token in text for text in readings):
            return token
    return ""


def _marker_is_not_the_payload(spec: WitnessSpec, output: str) -> bool:
    if not spec.marker:
        return False
    if self_defeating_marker(spec.marker, spec.payload):
        return False
    return spec.marker in output


def self_defeating_marker(marker: str, payload: bytes) -> str:
    if not marker:
        return ""
    if any(marker in text for text in payload_readings(payload)):
        return (f"the marker {marker!r} appears in the payload itself, so an entry point that merely "
                f"echoed the input would produce it — a marker has to be text the program's OWN code "
                f"prints, not text the payload carries")
    return ""


def _normalise(rc: int) -> int:
    return 128 - rc if rc < 0 else rc


def _refuse(spec: WitnessSpec, why: str, *, digest: str = "") -> Witness:
    return Witness(demonstrated=False, expectation=spec.expectation, entry_digest=digest, refusal=why)


__all__ = [
    "BENIGN_SUFFIX", "DEFAULT_TIMEOUT", "DIFFERENTIAL_NONZERO_EXIT", "EXPECTATIONS",
    "FATAL_SIGNAL_CODES", "INHERITED", "INTRODUCED", "MAX_BENIGN_CONTROLS", "MAX_EVIDENCE_CHARS",
    "CONTAINMENT_CAPABILITIES",
    "NETWORK_ISOLATION", "PID_ISOLATION", "PRIVILEGED_NETWORK_ISOLATION",
    "TIMEOUT_KILL_CODES", "TRACEBACK_TOKENS", "UNATTRIBUTED", "UNHANDLED_EXCEPTION",
    "UNMEASURED_EXPECTATIONS", "Witness", "WitnessSpec", "adjudicate", "attribute", "benign_controls",
    "containment_unavailable", "controls_digest",
    "entry_digest", "entry_env", "isolation_prefix", "network_isolated", "observed_location",
    "offered_expectations",
    "payload_readings", "redact_secrets", "reset_isolation_cache", "resolve_entry",
    "secret_values",
    "self_defeating_marker", "witness_contract",
]


_NOT_FOUND = re.compile(r"(?:^|\n)[^\n]*?:\s*(?:line \d+:\s*)?([\w./+-]+):\s*(?:command )?not found",
                        re.I)


def _missing_runtime(code: int, output: str) -> str:
    found = _NOT_FOUND.search(output or "")
    if found:
        return f"{found.group(1)!r} is not installed in the image running it"
    if code == 127:
        return ("the shell exited 127, which is 'command not found' — the entry point asked for a "
                "program that is not installed in the image running it")
    return ""
