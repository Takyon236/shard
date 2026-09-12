
from __future__ import annotations

import json
import math
import os
import re
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Protocol

from shard.diag import get_logger
from shard.providermetrics import attempt as _provider_attempt, merge as _merge_provider_usage

_log = get_logger(__name__)


@dataclass(frozen=True)
class _ProviderUsage:
    input_tokens: int
    output_tokens: int
    cached_tokens: int
    total_tokens: int
    cost_usd: float
    cache_write_tokens: int
    unpriced: int
    reported: bool
    tokens_reported: bool
    input_reported: bool = field(default=False, compare=False)
    output_reported: bool = field(default=False, compare=False)
    cached_reported: bool = field(default=False, compare=False)


class _UsageIntegrityError(ValueError):
    pass


class _StreamIntegrityError(ValueError):
    pass


class _WallTimerStartError(RuntimeError):
    pass


_USAGE_INTEGRITY_CODE = -1
_STREAM_INTEGRITY_CODE = -2
_TURN_CEILING_CODE = -3
_PRE_WIRE_TRANSIENT_CODE = -4
_POST_WIRE_TIMEOUT_CODE = -5
_POST_WIRE_TRANSPORT_CODE = -6
_MALFORMED_STREAM_CODE = -7
_PRE_WIRE_CONFIG_CODE = -8
_PRE_WIRE_TIMEOUT_CODE = -9
_PRE_WIRE_CODES = (_PRE_WIRE_TRANSIENT_CODE, _PRE_WIRE_CONFIG_CODE, _PRE_WIRE_TIMEOUT_CODE)
_NO_ABANDON_CODES = (_TURN_CEILING_CODE, *_PRE_WIRE_CODES)
_TOOL_CHOICE_REJECTION_CODES = frozenset({400, 404, 422})

_MAX_DNS_THREADS = 4
_DNS_THREAD_SLOTS = threading.BoundedSemaphore(_MAX_DNS_THREADS)


def _tool_choice_rejection(code: int, error: str, tool_choice) -> bool:
    if tool_choice is None or code not in _TOOL_CHOICE_REJECTION_CODES:
        return False
    prefix = f"http {code}: "
    if not error.casefold().startswith(prefix):
        return False
    detail = error[len(prefix):].strip()
    try:
        document = json.loads(detail)
    except (json.JSONDecodeError, RecursionError, ValueError):
        pass
    else:
        provider_error = document.get("error") if isinstance(document, dict) else None
        if isinstance(provider_error, dict) and isinstance(provider_error.get("message"), str):
            detail = provider_error["message"]
        elif isinstance(provider_error, str):
            detail = provider_error
    normalized = re.sub(r"[_-]+", " ", detail.casefold()).strip()
    normalized = normalized.removesuffix(".")
    patterns = (
        r"(?:the )?(?:provided )?tool choice(?: parameter| field)?(?: [:=] \S+)? "
        r"(?:is |was )?(?:not supported|unsupported|invalid|not allowed|rejected)",
        r"(?:invalid|unsupported|unrecognized) (?:value for )?(?:the )?(?:provided )?"
        r"tool choice(?: parameter| field)?",
        r"no endpoints? (?:were )?(?:found (?:that )?)?supports? (?:the )?(?:provided )?"
        r"tool choice",
    )
    return any(re.fullmatch(pattern, normalized) for pattern in patterns)


def _usage_integer(value, field_name: str) -> int:
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} is not an integer")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{field_name} is not finite")
    integer = int(value)
    if value < 0 or value != integer:
        raise ValueError(f"{field_name} is negative or fractional")
    return integer


def _optional_usage_integer(usage: dict, field_name: str) -> tuple[bool, int]:
    value = usage.get(field_name)
    return (False, 0) if value is None else (True, _usage_integer(value, field_name))


def _provider_usage(usage) -> _ProviderUsage:
    if usage is None:
        usage = {}
    if not isinstance(usage, dict):
        raise ValueError("usage is not an object")
    details = usage.get("prompt_tokens_details")
    if details is None:
        details = {}
    if not isinstance(details, dict):
        raise ValueError("prompt_tokens_details is not an object")
    raw_cost = usage.get("cost")
    if isinstance(raw_cost, bool) or (raw_cost is not None and not isinstance(raw_cost, (int, float))):
        raise ValueError("cost is not a number")
    try:
        cost = float(raw_cost or 0.0)
    except OverflowError as e:
        raise ValueError("cost is not finite") from e
    if not math.isfinite(cost) or cost < 0:
        raise ValueError("cost is non-finite or negative")
    input_reported, input_tokens = _optional_usage_integer(usage, "prompt_tokens")
    output_reported, output_tokens = _optional_usage_integer(usage, "completion_tokens")
    total_reported, total_tokens = _optional_usage_integer(usage, "total_tokens")
    if not total_reported and input_reported and output_reported:
        total_tokens = input_tokens + output_tokens
        total_reported = True
    if total_reported and total_tokens < input_tokens + output_tokens:
        raise ValueError(
            f"total_tokens {total_tokens} is less than prompt_tokens + completion_tokens "
            f"({input_tokens + output_tokens})")
    return _ProviderUsage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cached_tokens=_usage_integer(details.get("cached_tokens"), "cached_tokens"),
        total_tokens=total_tokens,
        cost_usd=cost,
        cache_write_tokens=_usage_integer(details.get("cache_write_tokens"), "cache_write_tokens"),
        unpriced=int(raw_cost is None),
        reported=bool(usage),
        tokens_reported=total_reported,
        input_reported=input_reported,
        output_reported=output_reported,
        cached_reported=details.get("cached_tokens") is not None,
    )


def _provider_result_fields(usage: _ProviderUsage, served: str,
                            identity_verdict: str, seconds: float = 0.0) -> dict:
    return {
        "cost_usd": usage.cost_usd,
        "tokens": usage.total_tokens,
        "unpriced_attempts": usage.unpriced,
        "served_model": served,
        "identity_verdict": identity_verdict,
        "tokens_reported": usage.tokens_reported,
        "cost_reported": not usage.unpriced,
        "provider_usage": _provider_attempt(usage, seconds),
    }


def _incomplete_error_message(data: dict) -> str:
    stream_error = data.get("_stream_error")
    detail = f": {str(stream_error)[:200]}" if stream_error is not None else ""
    return f"incomplete response: finish_reason=error{detail}"


def _combined_reported(flags: list[bool | None]) -> bool | None:
    if any(flag is False for flag in flags):
        return False
    return True if flags and all(flag is True for flag in flags) else None

if TYPE_CHECKING:
    from collections.abc import Mapping

MODEL_TIERS = {"reasoner": "opus", "worker": "sonnet", "cheap": "haiku"}

DEFAULT_ANTHROPIC_MODELS = {
    "opus": "claude-opus-4-8",
    "sonnet": "claude-sonnet-4-6",
    "haiku": "claude-haiku-4-5-20251001",
}
DEFAULT_OPENROUTER_MODELS = {
    "glm": "z-ai/glm-5.2",
    "glm-5.2": "z-ai/glm-5.2",
    "opus": "anthropic/claude-opus-4.8",
    "sonnet": "anthropic/claude-sonnet-4.6",
    "haiku": "anthropic/claude-haiku-4.5",
}


def _is_openrouter_endpoint(url: str) -> bool:
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
    except (TypeError, ValueError):
        return False
    return host == "openrouter.ai" or host.endswith(".openrouter.ai")


_PROVIDER_ENV = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "google": "GEMINI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "ollama": "",
}

TRANSPORT_ERROR_KINDS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("upstream", re.compile(r"\Ahttp 5\d\d", re.I)),
    ("credit", re.compile(r"http 402|insufficient[_ ]?(?:credit|quota|balance|funds)"
                          r"|exceeded your current quota|billing", re.I)),
    ("auth", re.compile(r"http 40[13]\b|no [A-Z_]*API_KEY|no api_key for provider"
                        r"|user not found|invalid[_ ]api[_ ]key|authentication|unauthorized", re.I)),
    ("rate", re.compile(r"http 429|rate[_ ]?limit|too many requests", re.I)),
    ("model", re.compile(r"http 404|no endpoint|model[_ ]not[_ ]found|is not a valid model"
                         r"|unknown model|\bmodel\w*\b[^\n]{0,40}?does not exist", re.I)),
    ("stall", re.compile(r"idle/stall timeout|throughput|min_tps", re.I)),
)


def classify_transport_error(text: str) -> str:
    for kind, pattern in TRANSPORT_ERROR_KINDS:
        if pattern.search(text or ""):
            return kind
    return ""


@dataclass
class LLMResult:
    text: str
    cost_usd: float = 0.0
    model: str = ""
    ok: bool = True
    error: str = ""
    tokens: int = 0
    finish_reason: str = ""
    abandoned_attempts: int = 0
    unpriced_attempts: int = 0
    served_model: str = ""
    identity_verdict: str = ""
    tokens_reported: bool | None = None
    cost_reported: bool | None = None
    provider_usage: dict | None = None


class LLMBackend(Protocol):
    def complete(self, system: str, user: str, *, model: str = "sonnet", timeout: int = 600) -> LLMResult: ...


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict


def _parsed_tool_calls(message: dict) -> tuple[list[ToolCall], str]:
    calls = []
    call_ids = set()
    for raw in (message.get("tool_calls") or []):
        if not isinstance(raw, dict):
            raise _StreamIntegrityError("tool call is not an object")
        call_type = raw.get("type", "function")
        if call_type != "function":
            raise _StreamIntegrityError(f"tool call carried unsupported type {call_type!r}")
        call_id = raw.get("id")
        if not isinstance(call_id, str) or not call_id:
            raise _StreamIntegrityError("tool call has no nonempty id")
        if call_id in call_ids:
            raise _StreamIntegrityError(f"tool call id {call_id!r} is duplicated")
        call_ids.add(call_id)
        function = raw.get("function") or {}
        try:
            arguments = json.loads(function.get("arguments") or "{}")
        except RecursionError as e:
            raise _StreamIntegrityError(
                "tool-call arguments exceeded the JSON nesting limit") from e
        except json.JSONDecodeError:
            return [], "malformed tool-call arguments"
        except ValueError as e:
            raise _StreamIntegrityError(
                f"tool-call arguments exceeded the JSON value limit: {e}") from e
        except TypeError:
            return [], "malformed tool-call arguments"
        if not isinstance(arguments, dict):
            return [], "tool-call arguments were not an object"
        calls.append(ToolCall(id=call_id, name=function.get("name") or "", arguments=arguments))
    return calls, ""


@dataclass
class ChatResult:
    text: str = ""
    tool_calls: list = field(default_factory=list)
    raw_message: dict = field(default_factory=dict)
    ok: bool = True
    error: str = ""
    tokens: int = 0
    model: str = ""
    served_model: str = ""
    finish_reason: str = ""
    cost_usd: float = 0.0
    abandoned_attempts: int = 0
    unpriced_attempts: int = 0
    identity_verdict: str = ""
    tokens_reported: bool | None = None
    cost_reported: bool | None = None
    forcing_retry_safe: bool = False
    empty_retry_safe: bool = False
    stall_retry_safe: bool = False
    provider_usage: dict | None = None


class ToolCallingBackend(Protocol):
    def chat(self, messages: list, tools: list, *, model: str = "sonnet",
             timeout: int = 600, tool_choice=None) -> ChatResult: ...


def _chat_turn_verdict(data: dict, text: str, refusal, finish: str, native: str, model: str,
                       fields: dict) -> tuple[ChatResult, int] | None:
    if refusal or finish == "content_filter" or native == "refusal":
        return ChatResult(ok=False, error=f"model refused the prompt (finish={finish or native})",
                          model=model, finish_reason=finish, tool_calls=[], raw_message={},
                          forcing_retry_safe=False, **fields), 403
    if finish == "error":
        return ChatResult(ok=False, error=_incomplete_error_message(data), model=model,
                          finish_reason=finish, tool_calls=[], raw_message={},
                          forcing_retry_safe=False, **fields), 200
    if finish == "length":
        return ChatResult(text=text, tool_calls=[], raw_message={}, ok=True, model=model,
                          finish_reason=finish, **fields), 200
    return None


class ClaudeCliBackend:

    def __init__(self, binary: str = "claude", *, retries: int = 3, backoff: float = 3.0,
                 sleep=time.sleep, prefer_subscription: bool = True) -> None:
        self.binary = binary
        self.retries = retries
        self.backoff = backoff
        self._sleep = sleep
        self.prefer_subscription = prefer_subscription

    def _child_env(self, base: "Mapping[str, str] | None" = None) -> dict[str, str]:
        env = dict(os.environ if base is None else base)
        if self.prefer_subscription:
            for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"):
                env.pop(key, None)
        return env

    def _once(self, system: str, user: str, model: str, timeout: int) -> LLMResult:
        cmd = [
            self.binary, "-p",
            "--model", model,
            "--append-system-prompt", system,
            "--output-format", "json",
            "--max-turns", "1",
        ]
        try:
            proc = subprocess.run(cmd, input=user, capture_output=True, text=True, errors="replace",
                                  timeout=timeout, env=self._child_env())
        except subprocess.TimeoutExpired:
            return LLMResult("", 0.0, model, False, f"timeout after {timeout}s")
        except FileNotFoundError:
            return LLMResult("", 0.0, model, False, f"{self.binary!r} not found")
        except OSError as e:
            return LLMResult("", 0.0, model, False, f"spawn failed: {type(e).__name__}: {e}")
        if proc.returncode != 0:
            return LLMResult("", 0.0, model, False, f"claude exited {proc.returncode}: {proc.stderr[:300]}")
        try:
            events = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return LLMResult("", 0.0, model, False, f"unparseable output: {proc.stdout[:200]}")
        rv = next((e for e in reversed(events) if e.get("type") == "result"), None)
        if not rv:
            return LLMResult("", 0.0, model, False, "no result event")
        return LLMResult(rv.get("result", ""), float(rv.get("total_cost_usd", 0.0) or 0.0), model, True)

    def complete(self, system: str, user: str, *, model: str = "sonnet", timeout: int = 600) -> LLMResult:
        last = LLMResult("", 0.0, model, False, "no attempt")
        for attempt in range(self.retries + 1):
            last = self._once(system, user, model, timeout)
            if last.ok or "not found" in last.error:
                return last
            if attempt < self.retries:
                self._sleep(self.backoff * (2 ** attempt))
        return last




def _sse_data(raw) -> str | None:
    line = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
    line = line.strip()
    if not line or line[0] == ":" or not line.startswith("data:"):
        return None
    return line[5:].strip()


class _RejectRedirects(urllib.request.HTTPRedirectHandler):

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _owned_http_connection(owner):
    import http.client

    class OwnedHTTPConnection(http.client.HTTPConnection):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._shard_ready = False
            self._create_connection = lambda address, timeout, source_address: (
                _owned_create_connection(owner, address, timeout, source_address))
            owner.own(self)

        def connect(self):
            owner.require_open()
            super().connect()
            owner.require_open()
            self._shard_ready = True

        def send(self, data):
            if self.sock is None and self.auto_open:
                self.connect()
            if self.sock is not None and self._shard_ready:
                owner.require_open()
                owner.mark_sent()
            return super().send(data)

    return OwnedHTTPConnection


def _owned_https_connection(owner):
    import http.client

    class OwnedHTTPSConnection(http.client.HTTPSConnection):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._shard_ready = False
            self._create_connection = lambda address, timeout, source_address: (
                _owned_create_connection(owner, address, timeout, source_address))
            owner.own(self)

        def connect(self):
            owner.require_open()
            super().connect()
            owner.require_open()
            self._shard_ready = True

        def send(self, data):
            if self.sock is None and self.auto_open:
                self.connect()
            if self.sock is not None and self._shard_ready:
                owner.require_open()
                owner.mark_sent()
            return super().send(data)

    return OwnedHTTPSConnection


def _open_stream(req, timeout: float):
    owner = getattr(req, "_shard_wall_owner", None)
    if owner is None:
        return urllib.request.build_opener(_RejectRedirects()).open(req, timeout=timeout)
    http_connection = _owned_http_connection(owner)
    https_connection = _owned_https_connection(owner)

    class _OwnedHTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, request):
            return self.do_open(http_connection, request)

    class _OwnedHTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, request):
            return self.do_open(https_connection, request, context=self._context)

    return urllib.request.build_opener(
        _RejectRedirects(), _OwnedHTTPHandler(), _OwnedHTTPSHandler()).open(req, timeout=timeout)


def _response_socket(response):
    current = response
    seen = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        raw = getattr(current, "raw", None)
        sock = (getattr(raw, "_sock", None) or getattr(current, "_sock", None)
                or getattr(current, "sock", None))
        if sock is not None:
            return sock
        current = getattr(current, "fp", None)
    return None


class _WallResponseOwner:

    def __init__(self, remaining: float, message: str) -> None:
        self._lock = threading.Lock()
        self._targets = []
        self._closed = False
        self._sent = False
        self._wake = threading.Event()
        self._deadline = time.monotonic() + remaining
        self._message = message

    @staticmethod
    def _close(target) -> None:
        import socket

        sock = _response_socket(target)
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        close = getattr(target, "close", None)
        if callable(close):
            try:
                close()
            except OSError:
                pass

    def own(self, target):
        if time.monotonic() >= self._deadline:
            self.close()
        with self._lock:
            closed = self._closed
            if not closed:
                self._targets.append(target)
        if closed:
            self._close(target)
            raise TimeoutError(self._message)
        return target

    def require_open(self) -> float:
        remaining = self._deadline - time.monotonic()
        with self._lock:
            closed = self._closed
        if closed or remaining <= 0:
            self.close()
            raise TimeoutError(self._message)
        return remaining

    def timeout(self) -> TimeoutError:
        return TimeoutError(self._message)

    def mark_sent(self) -> None:
        with self._lock:
            if self._closed:
                raise TimeoutError(self._message)
            self._sent = True

    @property
    def sent(self) -> bool:
        with self._lock:
            return self._sent

    def wake(self) -> None:
        self._wake.set()

    def wait(self) -> None:
        self._wake.wait(self.require_open())
        self.require_open()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            targets = tuple(reversed(self._targets))
            self._targets.clear()
        self._wake.set()
        for target in targets:
            self._close(target)


def _owned_getaddrinfo(owner, address):
    import queue
    import socket

    if not _DNS_THREAD_SLOTS.acquire(timeout=owner.require_open()):
        raise owner.timeout()
    resolved = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            try:
                answer = socket.getaddrinfo(address[0], address[1], 0, socket.SOCK_STREAM)
            except OSError as error:
                answer = error
            try:
                resolved.put_nowait(answer)
            except queue.Full:
                pass
        finally:
            _DNS_THREAD_SLOTS.release()
            owner.wake()

    thread = threading.Thread(target=resolve, name="shard-model-dns", daemon=True)
    try:
        thread.start()
    except (OSError, RuntimeError) as error:
        _DNS_THREAD_SLOTS.release()
        raise OSError(f"could not start bounded model DNS resolver: {error}") from error
    try:
        owner.wait()
        answer = resolved.get_nowait()
    except queue.Empty as error:
        raise owner.timeout() from error
    if isinstance(answer, OSError):
        raise answer
    return answer


def _owned_create_connection(owner, address, timeout, source_address=None):
    import socket

    failures = []
    for family, socktype, proto, _canonname, socket_address in _owned_getaddrinfo(owner, address):
        owner.require_open()
        sock = None
        try:
            sock = owner.own(socket.socket(family, socktype, proto))
            connect_timeout = owner.require_open()
            if timeout is not None and timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                connect_timeout = min(connect_timeout, float(timeout))
            sock.settimeout(connect_timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(socket_address)
            owner.require_open()
            return sock
        except OSError as error:
            failures.append(error)
            if sock is not None:
                sock.close()
    if not failures:
        raise OSError("getaddrinfo returned no stream addresses")
    raise failures[-1]


def _call_before_wall_deadline(response, remaining: float, operation, message: str):
    import socket

    if remaining <= 0:
        raise TimeoutError(message)
    expired = threading.Event()

    def abort() -> None:
        expired.set()
        sock = _response_socket(response)
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        close = getattr(response, "close", None)
        if callable(close):
            try:
                close()
            except OSError:
                pass

    timer = threading.Timer(remaining, abort)
    timer.daemon = True
    try:
        timer.start()
    except RuntimeError as e:
        raise _WallTimerStartError(f"could not start model wall timer: {e}") from e
    try:
        result = operation()
    except BaseException as e:
        if expired.is_set():
            raise TimeoutError(message) from e
        raise
    finally:
        timer.cancel()
    if expired.is_set():
        raise TimeoutError(message)
    return result


def _bounded_sse_lines(resp, max_bytes: int, max_lines: int, before_read=None):
    readline = getattr(resp, "readline", None)
    iterator = None if callable(readline) else iter(resp)
    total = 0
    count = 0
    while True:
        if iterator is None:
            if before_read is not None:
                before_read()
            raw = readline(max_bytes + 1)
            if not raw:
                break
        else:
            try:
                raw = next(iterator)
            except StopIteration:
                break
        count += 1
        if count > max_lines:
            raise _StreamIntegrityError(f"SSE response exceeded {max_lines} lines")
        if isinstance(raw, str):
            total += len(raw.encode("utf-8", "replace"))
        elif isinstance(raw, (bytes, bytearray)):
            total += len(raw)
        else:
            raise TypeError("SSE line is not bytes or text")
        if total > max_bytes:
            raise _StreamIntegrityError(f"SSE response exceeded {max_bytes} bytes")
        yield raw


class _StreamPace:

    def __init__(self, backend: OpenRouterBackend, deadline: float) -> None:
        self.backend = backend
        self.deadline = deadline
        self.tps_on = backend.min_tps is not None and backend.min_tps > 0
        self.t_first: float | None = None
        self.t_anchor = 0.0
        self.chars_anchor = 0

    def tick(self, now: float, out_chars: int) -> None:
        if now > self.deadline:
            raise TimeoutError(f"absolute stream ceiling {self.backend.absolute_timeout}s exceeded")
        if self.tps_on and self.t_first is not None and (now - self.t_first) >= self.backend.tps_grace \
                and (now - self.t_anchor) >= self.backend.tps_window:
            tps = ((out_chars - self.chars_anchor) / self.backend._CHARS_PER_TOK) / (now - self.t_anchor)
            if tps < self.backend.min_tps:
                raise TimeoutError(
                    f"stream throughput ~{tps:.0f} tok/s < {self.backend.min_tps:.0f} floor over "
                    f"{now - self.t_anchor:.0f}s (slow-drip → reroute)")
            self.t_anchor, self.chars_anchor = now, out_chars

    def mark_output(self, now: float, out_chars: int) -> None:
        if self.tps_on and self.t_first is None and out_chars > 0:
            self.t_first = self.t_anchor = now


@dataclass
class _SseAssembly:

    content: list[str] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)
    refusal: str | None = None
    finish: str = ""
    native: str = ""
    usage: object = field(default_factory=dict)
    _validated_usage: _ProviderUsage | None = field(default=None, repr=False)
    _usage_seen: bool = field(default=False, repr=False)
    frags: dict[int, dict] = field(default_factory=dict)
    out_chars: int = 0
    model: str = ""
    response_id: str = ""
    role: str = ""
    _models: list[str] = field(default_factory=list, repr=False)
    _model_error: str = field(default="", repr=False)
    _choice_index: int | None = field(default=None, repr=False)
    _stream_error: object | None = field(default=None, repr=False)

    def add(self, chunk: dict) -> None:
        if not isinstance(chunk, dict):
            raise TypeError("SSE chunk is not an object")
        chunk_response_id = self._add_metadata(chunk)
        if chunk.get("error") is not None:
            self._record_stream_error(chunk["error"])
            return
        if self._stream_error is not None:
            return
        choice = self._choice(chunk)
        if choice is None:
            return
        if not chunk_response_id:
            raise _StreamIntegrityError("SSE choice carried no response id")
        delta, finish, native = choice
        if self.finish:
            self._check_after_finish(delta, finish, native)
            return
        self._add_delta(delta)
        if finish:
            self.finish = finish
        if native:
            self.native = native

    def _record_stream_error(self, error: object) -> None:
        if self._stream_error is None:
            self._stream_error = error
        self.content.clear()
        self.reasoning.clear()
        self.refusal = None
        self.frags.clear()
        self.role = ""
        self.native = ""
        self.finish = "error"

    def _add_metadata(self, chunk: dict) -> str:
        if chunk.get("usage") is not None:
            try:
                candidate = _provider_usage(chunk["usage"])
            except ValueError as e:
                raise _UsageIntegrityError(str(e)) from e
            if self._usage_seen and candidate != self._validated_usage:
                raise _UsageIntegrityError("conflicting SSE usage records")
            self.usage = chunk["usage"]
            self._validated_usage = candidate
            self._usage_seen = True
        named = chunk.get("model")
        if named is not None and not isinstance(named, str):
            self._model_error = "carried a non-string SSE model identity"
        elif named:
            if named not in self._models:
                self._models.append(named)
            if len(self._models) > 1:
                self._model_error = f"named conflicting SSE models: {self._models!r}"
            if not self.model:
                self.model = named
        response_id = chunk.get("id")
        if response_id is not None and not isinstance(response_id, str):
            raise _StreamIntegrityError("SSE response id is not a string")
        if response_id:
            if self.response_id and response_id != self.response_id:
                raise _StreamIntegrityError(
                    f"SSE response id changed from {self.response_id!r} to {response_id!r}")
            self.response_id = response_id
        return response_id or ""

    def _choice(self, chunk: dict) -> tuple[dict, str, str] | None:
        choices = chunk.get("choices")
        if choices is None:
            choices = []
        if not isinstance(choices, list):
            raise TypeError("SSE choices is not a list")
        if not choices:
            return None
        if len(choices) != 1:
            raise _StreamIntegrityError("SSE chunk carried more than one choice")
        ch = choices[0]
        if not isinstance(ch, dict):
            raise TypeError("SSE choice is not an object")
        index = ch.get("index", 0)
        if isinstance(index, bool) or not isinstance(index, int):
            raise _StreamIntegrityError("SSE choice index is not an integer")
        if self._choice_index is None:
            self._choice_index = index
        elif index != self._choice_index:
            raise _StreamIntegrityError(
                f"SSE choice index changed from {self._choice_index} to {index}")
        delta = ch.get("delta")
        if delta is None:
            delta = {}
        if not isinstance(delta, dict):
            raise TypeError("SSE choice delta is not an object")
        finish = ch.get("finish_reason") or ""
        native = ch.get("native_finish_reason") or ""
        if not isinstance(finish, str) or not isinstance(native, str):
            raise TypeError("SSE finish reason is not a string")
        return delta, finish, native

    def _check_after_finish(self, delta: dict, finish: str, native: str) -> None:
        if delta:
            raise TypeError("SSE choice carried a nonempty delta after finish_reason")
        if finish and finish != self.finish:
            raise TypeError("SSE choice changed finish_reason after completion")
        if native and native != self.native:
            raise TypeError("SSE choice changed native_finish_reason after completion")

    def _add_delta(self, delta: dict) -> None:
        role = delta.get("role")
        if role is not None and not isinstance(role, str):
            raise _StreamIntegrityError("SSE delta role is not a string")
        if role:
            if role != "assistant":
                raise _StreamIntegrityError(f"SSE delta carried unsupported role {role!r}")
            if self.role and role != self.role:
                raise _StreamIntegrityError(
                    f"SSE delta role changed from {self.role!r} to {role!r}")
            self.role = role
        if delta.get("content"):
            self.content.append(delta["content"])
            self.out_chars += len(delta["content"])
        if delta.get("reasoning"):
            self.reasoning.append(delta["reasoning"])
            self.out_chars += len(delta["reasoning"])
        if delta.get("refusal"):
            self.refusal = (self.refusal or "") + delta["refusal"]
            self.out_chars += len(delta["refusal"])
        tool_calls = delta.get("tool_calls")
        if tool_calls is None:
            tool_calls = []
        if not isinstance(tool_calls, list):
            raise TypeError("SSE tool_calls is not a list")
        for tc in tool_calls:
            self._merge_tool_call(tc)

    def _merge_tool_call(self, tc: dict) -> None:
        index, slot = self._tool_call_slot(tc)
        fn = tc.get("function")
        if fn is None:
            fn = {}
        if not isinstance(fn, dict):
            raise TypeError("SSE tool-call function is not an object")
        name = fn.get("name")
        if name is not None and not isinstance(name, str):
            raise _StreamIntegrityError("SSE tool-call name is not a string")
        if name:
            if slot["name"] is not None and slot["name"] != name:
                raise _StreamIntegrityError(
                    f"SSE tool-call index {index} changed name from {slot['name']!r} to {name!r}")
            slot["name"] = name
        arguments = fn.get("arguments")
        if arguments is not None and not isinstance(arguments, str):
            raise TypeError("SSE tool-call arguments are not a string")
        if arguments:
            slot["args"].append(arguments)
            self.out_chars += len(arguments)

    def _tool_call_slot(self, tc: dict) -> tuple[int, dict]:
        if not isinstance(tc, dict):
            raise TypeError("SSE tool call is not an object")
        index = tc.get("index", 0)
        if isinstance(index, bool) or not isinstance(index, int):
            raise _StreamIntegrityError("SSE tool-call index is not an integer")
        slot = self.frags.setdefault(index, {"id": None, "type": None, "name": None, "args": []})
        call_id = tc.get("id")
        if call_id is not None and not isinstance(call_id, str):
            raise _StreamIntegrityError("SSE tool-call id is not a string")
        if call_id:
            if slot["id"] is not None and slot["id"] != call_id:
                raise _StreamIntegrityError(
                    f"SSE tool-call index {index} changed id from {slot['id']!r} to {call_id!r}")
            if any(other_index != index and other["id"] == call_id
                   for other_index, other in self.frags.items()):
                raise _StreamIntegrityError(f"SSE tool-call id {call_id!r} is duplicated")
            slot["id"] = call_id
        call_type = tc.get("type")
        if call_type is not None and not isinstance(call_type, str):
            raise _StreamIntegrityError("SSE tool-call type is not a string")
        if call_type is not None:
            if call_type != "function":
                raise _StreamIntegrityError(
                    f"SSE tool-call index {index} carried unsupported type {call_type!r}")
            if slot["type"] is not None and slot["type"] != call_type:
                raise _StreamIntegrityError(
                    f"SSE tool-call index {index} changed type from {slot['type']!r} "
                    f"to {call_type!r}")
            slot["type"] = call_type
        return index, slot

    def _assembled_tool_calls(self) -> list[dict]:
        calls = []
        call_ids = set()
        for index in sorted(self.frags):
            fragment = self.frags[index]
            call_id = fragment["id"]
            if not call_id:
                raise _StreamIntegrityError(f"SSE tool-call index {index} has no nonempty id")
            if call_id in call_ids:
                raise _StreamIntegrityError(f"SSE tool-call id {call_id!r} is duplicated")
            call_ids.add(call_id)
            calls.append({
                "id": call_id,
                "type": fragment["type"] or "function",
                "function": {"name": fragment["name"] or "",
                             "arguments": "".join(fragment["args"])},
            })
        return calls

    def response(self) -> dict:
        message: dict = {"role": self.role or "assistant", "content": "".join(self.content)}
        if self.reasoning:
            message["reasoning"] = "".join(self.reasoning)
        if self.refusal is not None:
            message["refusal"] = self.refusal
        if self.frags:
            message["tool_calls"] = self._assembled_tool_calls()
        choice: dict = {"message": message, "finish_reason": self.finish}
        if self.native:
            choice["native_finish_reason"] = self.native
        response = {"choices": [choice], "usage": self.usage, "model": self.model}
        if self._stream_error is not None:
            response["_stream_error"] = self._stream_error
        if self.response_id:
            response["id"] = self.response_id
        if self._model_error:
            response["_model_identity_error"] = self._model_error
            response["_model_identities"] = list(self._models)
        return response


class OpenRouterBackend:

    ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
    _RETRY_CODES = (429, 500, 502, 503, 504, 520, 521, 522, 523, 524, 598, 599,
                    _PRE_WIRE_TRANSIENT_CODE, _PRE_WIRE_TIMEOUT_CODE, _POST_WIRE_TIMEOUT_CODE,
                    _POST_WIRE_TRANSPORT_CODE, _MALFORMED_STREAM_CODE)

    _CHARS_PER_TOK = 4.0

    _MAX_STREAM_BYTES = 4 * 1024 * 1024
    _MAX_STREAM_LINES = 4 * 32768
    _MAX_ERROR_BYTES = 4096

    def __init__(self, *, api_key: str | None = None, model_map: dict[str, str] | None = None,
                 base_url: str | None = None, max_tokens: int = 32768, retries: int = 4,
                 backoff: float = 2.0, sleep=time.sleep, idle_timeout: int = 90,
                 absolute_timeout: int = 900, monotonic=time.monotonic,
                 provider_only: str | list[str] | None = None, allow_fallbacks: bool = False,
                 provider_sort: str | None = None,
                 provider_order: str | list[str] | None = None,
                 provider_quantizations: list[str] | None = None,
                 provider_min_throughput: dict | int | None = None,
                 provider_max_price: dict | None = None,
                 min_tps: float | None = None, tps_grace: float = 12.0, tps_window: float = 20.0,
                 temperature: float = 0.0, seed: int | None = None,
                 referer: str = "https://github.com/Takyon236/shard",
                 title: str = "Shard") -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("OPENROUTER_API_KEY", "")
        self.endpoint = (base_url.rstrip("/") + "/chat/completions") if base_url else self.ENDPOINT
        self.model_map = model_map or (DEFAULT_OPENROUTER_MODELS
                                       if _is_openrouter_endpoint(self.endpoint) else {})
        self.max_tokens = max_tokens
        self._usage = {"input_tokens": 0, "output_tokens": 0, "cached_tokens": 0,
                       "total_tokens": 0, "llm_requests": 0, "generation_sec": 0.0,
                       "cost_usd": 0.0, "cache_write_tokens": 0,
                       "priced_requests": 0,
                       "token_reported_requests": 0,
                       "abandoned_requests": 0}
        self._turn = threading.local()
        self._usage_lock = threading.Lock()
        self.retries = retries
        self.backoff = backoff
        self._sleep = sleep
        self.idle_timeout = idle_timeout
        self.absolute_timeout = absolute_timeout
        self._monotonic = monotonic
        self.provider_only = [provider_only] if isinstance(provider_only, str) else (provider_only or None)
        self.allow_fallbacks = allow_fallbacks
        self.provider_sort = provider_sort
        self.provider_order = [provider_order] if isinstance(provider_order, str) else (provider_order or None)
        self.provider_quantizations = provider_quantizations
        if isinstance(provider_min_throughput, int):
            provider_min_throughput = {"p90": provider_min_throughput}
        self.provider_min_throughput = provider_min_throughput
        self.provider_max_price = provider_max_price
        self.min_tps = min_tps
        self.tps_grace = tps_grace
        self.tps_window = tps_window
        self.temperature = temperature
        self.seed = seed
        self.referer = referer
        self.title = title

    def _resolve(self, model: str) -> str:
        return self.model_map.get(model, model)

    def _accumulate_usage(self, usage: _ProviderUsage, gen_sec: float = 0.0) -> None:
        with self._usage_lock:
            self._usage["llm_requests"] += 1
            self._usage["generation_sec"] += float(gen_sec or 0.0)
            if not usage.reported:
                return
            self._usage["input_tokens"] += usage.input_tokens
            self._usage["output_tokens"] += usage.output_tokens
            self._usage["cached_tokens"] += usage.cached_tokens
            self._usage["total_tokens"] += usage.total_tokens
            self._usage["cost_usd"] += usage.cost_usd
            self._usage["cache_write_tokens"] += usage.cache_write_tokens
            if usage.tokens_reported:
                self._usage["token_reported_requests"] += 1
            if not usage.unpriced:
                self._usage["priced_requests"] += 1

    def _data_less_accounting(self, code: int, gen_sec: float) -> tuple[int, int]:
        if code > 0:
            usage = _provider_usage(None)
            self._accumulate_usage(usage, gen_sec)
            return 0, usage.unpriced
        if code in _NO_ABANDON_CODES:
            return 0, 0
        self._record_abandoned(gen_sec)
        return 1, 0

    def _record_abandoned(self, gen_sec: float) -> None:
        with self._usage_lock:
            self._usage["llm_requests"] += 1
            self._usage["generation_sec"] += float(gen_sec or 0.0)
            self._usage["abandoned_requests"] += 1

    def _account_abandoned(self, result) -> int:
        return int(result.abandoned_attempts or 0)

    def _turn_ceiling(self):
        import contextlib

        @contextlib.contextmanager
        def _stamped():
            previous = getattr(self._turn, "deadline", None)
            self._turn.deadline = self._monotonic() + self.absolute_timeout
            try:
                yield self._turn.deadline
            finally:
                self._turn.deadline = previous

        return _stamped()

    def _turn_deadline(self, now: float | None = None) -> float:
        deadline = getattr(self._turn, "deadline", None)
        if deadline is not None:
            return deadline
        return (self._monotonic() if now is None else now) + self.absolute_timeout

    def _wait_for_retry(self, deadline: float, attempt: int, model: str, code: int,
                        error: str) -> bool:
        delay = self.backoff * (2 ** attempt)
        remaining = deadline - self._monotonic()
        if remaining <= 0 or delay >= remaining:
            return False
        route = "" if code in _PRE_WIRE_CODES else ", routing relaxed"
        _log.warning("provider %s failed with %d (%s); retry %d/%d in %.1fs%s",
                     model, code, error[:120], attempt + 1, self.retries, delay, route)
        self._sleep(delay)
        if self._monotonic() >= deadline:
            return False
        return True

    def usage_summary(self) -> dict:
        with self._usage_lock:
            return dict(self._usage)

    def _http_error(self, error, deadline: float, idle: float) -> tuple[None, int, str]:
        import http.client
        import socket

        ceiling_error = f"absolute error-body ceiling {self.absolute_timeout}s exceeded"
        try:
            raw = _call_before_wall_deadline(
                error, deadline - self._monotonic(),
                lambda: error.read(self._MAX_ERROR_BYTES + 1),
                ceiling_error)
            if self._monotonic() >= deadline:
                raise TimeoutError(ceiling_error)
        except (TimeoutError, socket.timeout) as body_error:
            return None, error.code, (
                f"http {error.code}: response body exceeded its bound: "
                f"{type(body_error).__name__}: {body_error}")
        except (http.client.HTTPException, OSError, _WallTimerStartError) as body_error:
            return None, error.code, (
                f"http {error.code}: response body could not be read within its bound: "
                f"{type(body_error).__name__}: {body_error}")
        decoded = raw[:self._MAX_ERROR_BYTES].decode("utf-8", "replace")
        detail = decoded[:300]
        if len(raw) > self._MAX_ERROR_BYTES or len(decoded) > len(detail):
            detail += " [response body truncated]"
        return None, error.code, f"http {error.code}: {detail}"

    def _read_stream_response(self, req, idle: float, deadline: float,
                              owner: _WallResponseOwner, ceiling_error: str) -> dict:
        previous_timeout = getattr(self._turn, "read_timeout", None)
        self._turn.read_timeout = idle

        def consume():
            with _open_stream(req, timeout=idle) as response:
                owner.mark_sent()
                owner.own(response)
                return self._read_sse(response, deadline)

        try:
            return _call_before_wall_deadline(
                owner, deadline - self._monotonic(), consume, ceiling_error)
        finally:
            self._turn.read_timeout = previous_timeout

    def _stream_request(self, payload: dict, timeout: int, relax: bool, deadline: float):
        import json as _json
        import urllib.request

        if deadline - self._monotonic() <= 0:
            return None, 0.0, 0.0
        endpoint = urllib.parse.urlsplit(self.endpoint)
        if endpoint.scheme not in ("http", "https") or not endpoint.hostname:
            raise ValueError("model endpoint must be an absolute HTTP(S) URL")
        if endpoint.username is not None or endpoint.password is not None:
            raise ValueError("model endpoint must not contain credentials")
        _port = endpoint.port
        provider = self._provider_block(relax)
        if provider:
            payload["provider"] = provider
        payload["stream"] = True
        payload["stream_options"] = {"include_usage": True}
        request_body = _json.dumps(payload).encode("utf-8")
        remaining = deadline - self._monotonic()
        if remaining <= 0:
            return None, 0.0, remaining
        idle = min(float(timeout), float(self.idle_timeout), remaining)
        request = urllib.request.Request(self.endpoint, data=request_body, method="POST", headers={
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": self.referer,
            "X-Title": self.title,
        })
        return request, idle, remaining

    @staticmethod
    def _postwire_or_config(owner: _WallResponseOwner, error: Exception,
                            post_code: int, post_detail: str) -> tuple[None, int, str]:
        if not owner.sent:
            return None, _PRE_WIRE_CONFIG_CODE, (
                f"invalid provider request: {type(error).__name__}: {error}")
        return None, post_code, post_detail

    @staticmethod
    def _url_error_result(error, owner: _WallResponseOwner,
                          idle: float) -> tuple[None, int, str]:
        import socket

        if isinstance(error.reason, (TimeoutError, socket.timeout)):
            code = _POST_WIRE_TIMEOUT_CODE if owner.sent else _PRE_WIRE_TIMEOUT_CODE
            return None, code, f"idle/stall timeout after {idle:g}s: {error.reason}"
        code = _POST_WIRE_TRANSPORT_CODE if owner.sent else _PRE_WIRE_TRANSIENT_CODE
        return None, code, f"{type(error).__name__}: {error}"

    @staticmethod
    def _http_parser_result(error, owner: _WallResponseOwner) -> tuple[None, int, str]:
        import http.client

        if not owner.sent:
            if isinstance(error, http.client.InvalidURL):
                return None, _PRE_WIRE_CONFIG_CODE, (
                    f"invalid provider request: {type(error).__name__}: {error}")
            return None, _PRE_WIRE_TRANSIENT_CODE, (
                f"pre-wire HTTP negotiation failed: {type(error).__name__}: {error}")
        return None, _MALFORMED_STREAM_CODE, (
            f"malformed HTTP response: {type(error).__name__}: {error}")

    def _post_open(self, req, idle: float, deadline: float, owner: _WallResponseOwner,
                   ceiling_error: str) -> tuple[dict | None, int, str]:
        import http.client
        import json as _json
        import socket
        import urllib.error

        try:
            data = self._read_stream_response(req, idle, deadline, owner, ceiling_error)
            return data, 200, ""
        except urllib.error.HTTPError as e:
            try:
                return self._http_error(e, deadline, idle)
            finally:
                try:
                    e.close()
                except OSError:
                    pass
        except (TimeoutError, socket.timeout) as e:
            code = _POST_WIRE_TIMEOUT_CODE if owner.sent else _PRE_WIRE_TIMEOUT_CODE
            return None, code, f"idle/stall timeout after {idle:g}s: {type(e).__name__}: {e}"
        except urllib.error.URLError as e:
            return self._url_error_result(e, owner, idle)
        except _UsageIntegrityError as e:
            return None, _USAGE_INTEGRITY_CODE, f"invalid provider usage: {e}"
        except _StreamIntegrityError as e:
            return None, _STREAM_INTEGRITY_CODE, f"invalid provider stream: {e}"
        except RecursionError as e:
            return None, _STREAM_INTEGRITY_CODE, f"invalid provider stream: JSON nesting limit: {e}"
        except _WallTimerStartError as e:
            code = _POST_WIRE_TRANSPORT_CODE if owner.sent else _PRE_WIRE_TRANSIENT_CODE
            return None, code, f"{type(e).__name__}: {e}"
        except (_json.JSONDecodeError, http.client.IncompleteRead, EOFError, TypeError) as e:
            return self._postwire_or_config(
                owner, e, _MALFORMED_STREAM_CODE,
                f"malformed stream: {type(e).__name__}: {e}")
        except ValueError as e:
            return self._postwire_or_config(
                owner, e, _STREAM_INTEGRITY_CODE,
                f"invalid provider stream: JSON value limit: {e}")
        except http.client.HTTPException as e:
            return self._http_parser_result(e, owner)
        except OSError as e:
            code = _POST_WIRE_TRANSPORT_CODE if owner.sent else _PRE_WIRE_TRANSIENT_CODE
            return None, code, f"{type(e).__name__}: {e}"

    def _post(self, payload: dict, timeout: int, relax: bool = False) -> tuple[dict | None, int, str]:
        import http.client
        now = self._monotonic()
        deadline = self._turn_deadline(now)
        try:
            req, idle, remaining = self._stream_request(payload, timeout, relax, deadline)
        except (RecursionError, TypeError, ValueError, http.client.HTTPException) as e:
            return None, _PRE_WIRE_CONFIG_CODE, f"invalid provider request: {type(e).__name__}: {e}"
        if req is None:
            return None, _TURN_CEILING_CODE, (
                f"turn ceiling {self.absolute_timeout}s reached before provider request")
        ceiling_error = f"absolute stream ceiling {self.absolute_timeout}s exceeded"
        owner = _WallResponseOwner(remaining, ceiling_error)
        req._shard_wall_owner = owner
        return self._post_open(req, idle, deadline, owner, ceiling_error)

    def _read_sse(self, resp, deadline: float) -> dict:
        import json as _json

        assembly = _SseAssembly()
        pace = _StreamPace(self, deadline)
        done = False

        def refresh_read_timeout():
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise TimeoutError(f"absolute stream ceiling {self.absolute_timeout}s exceeded")
            configured = getattr(self._turn, "read_timeout", None)
            limit = min(float(self.idle_timeout if configured is None else configured), remaining)
            sock = getattr(getattr(getattr(resp, "fp", None), "raw", None), "_sock", None)
            if sock is not None:
                sock.settimeout(limit)

        lines = _bounded_sse_lines(resp, self._MAX_STREAM_BYTES, self._MAX_STREAM_LINES,
                                   refresh_read_timeout)
        for raw in lines:
            now = self._monotonic()
            pace.tick(now, assembly.out_chars)
            body = _sse_data(raw)
            if body is None:
                continue
            if body == "[DONE]":
                done = True
                break
            chunk = _json.loads(body)
            assembly.add(chunk)
            pace.mark_output(now, assembly.out_chars)
        pace.tick(self._monotonic(), assembly.out_chars)
        if not done and not assembly.finish:
            raise EOFError("SSE ended before [DONE] or finish_reason")
        return assembly.response()

    def _once(self, system: str, user: str, model: str, timeout: int,
              relax: bool = False) -> tuple["LLMResult", int]:
        payload = {
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        if self.seed is not None:
            payload["seed"] = self.seed
        _gen_t0 = time.monotonic()
        data, code, err = self._post(payload, timeout, relax)
        _gen_sec = time.monotonic() - _gen_t0
        if data is None:
            abandoned, unpriced = self._data_less_accounting(code, _gen_sec)
            return LLMResult("", 0.0, model, False, err, tokens=0,
                             abandoned_attempts=abandoned,
                             unpriced_attempts=unpriced,
                             provider_usage=_provider_attempt(None, _gen_sec,
                                                               sent=code not in _NO_ABANDON_CODES),
                             tokens_reported=False, cost_reported=False), code
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message", {}) or {}
        finish = choice.get("finish_reason") or ""
        native = choice.get("native_finish_reason") or ""
        refusal = msg.get("refusal")
        served, identity, identity_detail = _response_model_identity(data, model)
        try:
            usage = _provider_usage(data.get("usage"))
        except ValueError as e:
            self._record_abandoned(_gen_sec)
            return LLMResult("", 0.0, model, False, f"invalid provider usage: {e}",
                             abandoned_attempts=1, served_model=served,
                             provider_usage=_provider_attempt(None, _gen_sec),
                             identity_verdict=identity, tokens_reported=False,
                             cost_reported=False), _USAGE_INTEGRITY_CODE
        self._accumulate_usage(usage, _gen_sec)
        fields = _provider_result_fields(usage, served, identity, _gen_sec)
        identity_error = identity_detail or _model_identity_error(model, served, identity)
        if identity_error:
            return LLMResult(text="", model=model, ok=False, error=identity_error,
                             **fields), 409
        text = msg.get("content") or msg.get("reasoning") or ""
        if refusal or finish == "content_filter" or native == "refusal":
            err = f"model refused the prompt (finish={finish or native})"
            return LLMResult(text="", model=model, ok=False,
                             error=f"{err}: {refusal}" if refusal else err,
                             finish_reason=finish, **fields), 403
        if finish == "error":
            return LLMResult(text="", model=model, ok=False,
                             error=_incomplete_error_message(data),
                             finish_reason=finish, **fields), 200
        if finish == "length":
            return LLMResult(text="", model=model, ok=False,
                             error="incomplete response: finish_reason=length",
                             finish_reason=finish, **fields), 200
        if not text:
            return LLMResult(text="", model=model, ok=False,
                             error=f"empty response: {str(data)[:200]}",
                             finish_reason=finish, **fields), 599
        return LLMResult(text=text, model=model, ok=True, finish_reason=finish, **fields), 200

    def complete(self, system: str, user: str, *, model: str = "sonnet", timeout: int = 600) -> "LLMResult":
        resolved = self._resolve(model)
        if not self.api_key:
            return LLMResult("", 0.0, resolved, False, "no OPENROUTER_API_KEY",
                             provider_usage=_merge_provider_usage(()))
        last = LLMResult("", 0.0, resolved, False, "no attempt")
        made, spent_usd, spent_tokens, abandoned, unpriced = 0, 0.0, 0, 0, 0
        token_flags: list[bool | None] = []
        cost_flags: list[bool | None] = []
        measurements: list[dict | None] = []
        retry_window_closed = False
        with self._turn_ceiling() as deadline:
            for attempt in range(self.retries + 1):
                candidate, code = self._once(system, user, resolved, timeout, relax=made > 0)
                if code == _TURN_CEILING_CODE:
                    if made:
                        last = replace(last, error=f"{last.error} ({candidate.error})")
                    else:
                        last = candidate
                    retry_window_closed = True
                    break
                last = candidate
                measurements.append(last.provider_usage)
                if code not in _PRE_WIRE_CODES:
                    made += 1
                    spent_usd += float(last.cost_usd or 0.0)
                    spent_tokens += int(last.tokens or 0)
                    unpriced += int(last.unpriced_attempts or 0)
                    token_flags.append(last.tokens_reported)
                    cost_flags.append(last.cost_reported)
                    abandoned += self._account_abandoned(last)
                if last.ok or code not in self._RETRY_CODES:
                    return self._completion_bill(last, made, spent_usd, spent_tokens,
                                                 abandoned, unpriced,
                                                 _combined_reported(token_flags),
                                                 _combined_reported(cost_flags),
                                                 _merge_provider_usage(measurements))
                if attempt >= self.retries:
                    break
                if not self._wait_for_retry(deadline, attempt, resolved, code, last.error or ""):
                    last = replace(last, error=f"{last.error} (turn ceiling {self.absolute_timeout}s "
                                               f"leaves no retry window after {attempt + 1} attempt(s))")
                    retry_window_closed = True
                    _log.error("provider %s: turn ceiling %ds leaves no retry window after %d "
                               "attempt(s)", resolved, self.absolute_timeout, attempt + 1)
                    break
        if not last.ok and not retry_window_closed:
            _log.error("provider %s exhausted %d retries; last code %d (%s)",
                       resolved, self.retries, code, (last.error or "")[:200])
        return self._completion_bill(last, made, spent_usd, spent_tokens, abandoned, unpriced,
                                     _combined_reported(token_flags),
                                     _combined_reported(cost_flags), _merge_provider_usage(measurements))

    @staticmethod
    def _completion_bill(result: LLMResult, made: int, spent_usd: float, spent_tokens: int,
                         abandoned: int, unpriced: int, tokens_reported: bool | None,
                         cost_reported: bool | None, provider_usage: dict | None = None) -> LLMResult:
        if (made <= 1 and result.abandoned_attempts == abandoned
                and result.unpriced_attempts == unpriced
                and result.tokens_reported is tokens_reported
                and result.cost_reported is cost_reported):
            return (result if result.provider_usage == provider_usage
                    else replace(result, provider_usage=provider_usage))
        return replace(result, cost_usd=spent_usd, tokens=spent_tokens,
                       abandoned_attempts=abandoned,
                       unpriced_attempts=unpriced,
                       tokens_reported=tokens_reported,
                       cost_reported=cost_reported, provider_usage=provider_usage)

    def _provider_block(self, relax: bool = False) -> dict | None:
        block: dict = {}
        if self.provider_only and not relax:
            block["only"] = self.provider_only
            block["allow_fallbacks"] = self.allow_fallbacks
        else:
            order = self.provider_order or (self.provider_only if relax else None)
            if order:
                block["order"] = order
                block["allow_fallbacks"] = True
            if self.provider_sort:
                block["sort"] = self.provider_sort
                block.setdefault("allow_fallbacks", True)
            if relax:
                block["allow_fallbacks"] = True
        if self.provider_quantizations:
            block["quantizations"] = self.provider_quantizations
        if self.provider_min_throughput:
            block["preferred_min_throughput"] = self.provider_min_throughput
        if self.provider_max_price:
            block["max_price"] = self.provider_max_price
        return block or None

    def _chat_once(self, messages: list, tools: list, model: str, timeout: int,
                   relax: bool = False, tool_choice=None) -> tuple["ChatResult", int]:
        payload: dict = {"model": model, "messages": messages, "max_tokens": self.max_tokens,
                         "temperature": self.temperature}
        if self.seed is not None:
            payload["seed"] = self.seed
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice or "auto"
        _gen_t0 = time.monotonic()
        data, code, err = self._post(payload, timeout, relax)
        _gen_sec = time.monotonic() - _gen_t0
        if data is None:
            abandoned, unpriced = self._data_less_accounting(code, _gen_sec)
            return ChatResult(ok=False, error=err, model=model,
                              abandoned_attempts=abandoned,
                              unpriced_attempts=unpriced,
                              provider_usage=_provider_attempt(None, _gen_sec,
                                                                sent=code not in _NO_ABANDON_CODES),
                              tokens_reported=False, cost_reported=False,
                              stall_retry_safe=code in (
                                  _PRE_WIRE_TIMEOUT_CODE, _POST_WIRE_TIMEOUT_CODE),
                              forcing_retry_safe=_tool_choice_rejection(
                                  code, err, tool_choice)), code
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message", {}) or {}
        served, identity, identity_detail = _response_model_identity(data, model)
        try:
            usage = _provider_usage(data.get("usage"))
        except ValueError as e:
            self._record_abandoned(_gen_sec)
            return ChatResult(ok=False, error=f"invalid provider usage: {e}", model=model,
                              served_model=served, identity_verdict=identity,
                              provider_usage=_provider_attempt(None, _gen_sec),
                              abandoned_attempts=1, tokens_reported=False,
                              cost_reported=False, forcing_retry_safe=False), _USAGE_INTEGRITY_CODE
        self._accumulate_usage(usage, _gen_sec)
        fields = _provider_result_fields(usage, served, identity, _gen_sec)
        identity_error = identity_detail or _model_identity_error(model, served, identity)
        if identity_error:
            return ChatResult(ok=False, error=identity_error, model=model,
                              forcing_retry_safe=False, **fields), 409
        refusal = msg.get("refusal")
        finish = choice.get("finish_reason") or ""
        native = choice.get("native_finish_reason") or ""
        text = msg.get("content") or msg.get("reasoning") or ""

        verdict = _chat_turn_verdict(data, text, refusal, finish, native, model, fields)
        if verdict is not None:
            return verdict

        try:
            calls, call_error = _parsed_tool_calls(msg)
        except _StreamIntegrityError as e:
            return (ChatResult(ok=False, error=f"invalid provider stream: {e}", model=model,
                               finish_reason=finish, forcing_retry_safe=False, **fields),
                    _STREAM_INTEGRITY_CODE)
        if call_error:
            return ChatResult(ok=False, error=call_error, model=model,
                              finish_reason=finish, **fields), 599
        if not text and not calls:
            return ChatResult(ok=False, error=f"empty response: {str(data)[:200]}", model=model,
                              finish_reason=finish, empty_retry_safe=True, **fields), 599
        return ChatResult(text=text, tool_calls=calls, raw_message=msg, ok=True, model=model,
                          finish_reason=finish, **fields), 200

    def chat(self, messages: list, tools: list, *, model: str = "sonnet", timeout: int = 600,
             tool_choice=None) -> ChatResult:
        resolved = self._resolve(model)
        if not self.api_key:
            return ChatResult(ok=False, error="no OPENROUTER_API_KEY", model=resolved,
                              provider_usage=_merge_provider_usage(()))
        last = ChatResult(ok=False, error="no attempt", model=resolved)
        made, spent_usd, spent_tokens, abandoned, unpriced = 0, 0.0, 0, 0, 0
        token_flags: list[bool | None] = []
        cost_flags: list[bool | None] = []
        measurements: list[dict | None] = []
        with self._turn_ceiling() as deadline:
            for attempt in range(self.retries + 1):
                candidate, code = self._chat_once(
                    messages, tools, resolved, timeout, relax=made > 0,
                    tool_choice=tool_choice)
                if code == _TURN_CEILING_CODE:
                    if made:
                        last = replace(last, error=f"{last.error} ({candidate.error})")
                    else:
                        last = candidate
                    break
                last = candidate
                measurements.append(last.provider_usage)
                if code not in _PRE_WIRE_CODES:
                    made += 1
                    spent_usd += float(last.cost_usd or 0.0)
                    spent_tokens += int(last.tokens or 0)
                    unpriced += int(last.unpriced_attempts or 0)
                    token_flags.append(last.tokens_reported)
                    cost_flags.append(last.cost_reported)
                    abandoned += self._account_abandoned(last)
                if last.ok or code not in self._RETRY_CODES or attempt >= self.retries:
                    break
                if not self._wait_for_retry(deadline, attempt, resolved, code, last.error or ""):
                    last = replace(last, error=f"{last.error} (turn ceiling {self.absolute_timeout}s "
                                               f"leaves no retry window after {attempt + 1} attempt(s))")
                    break
        return self._billed(last, made, spent_usd, spent_tokens, abandoned, unpriced,
                            _combined_reported(token_flags), _combined_reported(cost_flags),
                            _merge_provider_usage(measurements))

    @staticmethod
    def _billed(result: ChatResult, made: int, spent_usd: float, spent_tokens: int,
                abandoned: int, unpriced: int, tokens_reported: bool | None,
                cost_reported: bool | None, provider_usage: dict | None = None) -> ChatResult:
        if (made <= 1 and result.abandoned_attempts == abandoned
                and result.unpriced_attempts == unpriced
                and result.tokens_reported is tokens_reported
                and result.cost_reported is cost_reported):
            return (result if result.provider_usage == provider_usage
                    else replace(result, provider_usage=provider_usage))
        return replace(result, cost_usd=spent_usd, tokens=spent_tokens,
                       abandoned_attempts=abandoned, unpriced_attempts=unpriced,
                       tokens_reported=tokens_reported, cost_reported=cost_reported,
                       provider_usage=provider_usage)


@dataclass
class EchoBackend:

    scripted: list[str] = field(default_factory=list)
    calls: list[tuple[str, str]] = field(default_factory=list)

    def complete(self, system: str, user: str, *, model: str = "sonnet", timeout: int = 600) -> LLMResult:
        self.calls.append((system, user))
        if not self.scripted:
            return LLMResult("", 0.0, model, False, "EchoBackend exhausted")
        return LLMResult(self.scripted.pop(0), 0.0, model, True)


@dataclass
class ScriptedChatBackend:

    scripted: list = field(default_factory=list)
    calls: list = field(default_factory=list)
    tool_choices: list = field(default_factory=list)

    def chat(self, messages: list, tools: list, *, model: str = "sonnet", timeout: int = 600,
             tool_choice=None) -> ChatResult:
        self.calls.append(list(messages))
        self.tool_choices.append(tool_choice)
        if not self.scripted:
            return ChatResult(ok=False, error="ScriptedChatBackend exhausted", model=model)
        turn = self.scripted.pop(0)
        if isinstance(turn, ChatResult):
            return turn
        if turn is None:
            return ChatResult(ok=False, error="empty response: simulated glitch", model=model, tokens=1,
                              empty_retry_safe=True)
        if isinstance(turn, str):
            return ChatResult(text=turn, tool_calls=[], raw_message={"role": "assistant", "content": turn},
                              ok=True, model=model, tokens=1)
        tcs = [ToolCall(id=f"call_{i}", name=name, arguments=args) for i, (name, args) in enumerate(turn)]
        raw = {"role": "assistant", "content": None, "tool_calls": [
            {"id": tc.id, "type": "function",
             "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)}} for tc in tcs]}
        return ChatResult(text="", tool_calls=tcs, raw_message=raw, ok=True, model=model, tokens=1)


_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
_THINK_TAG = re.compile(r"(</?)think(?:ing)?>", re.IGNORECASE)


def _strip_reasoning(text: str) -> str:
    spans: list[tuple[int, int]] = []
    depth = 0
    start = 0
    for m in _THINK_TAG.finditer(text):
        if m.group(1) == "<":
            if depth == 0:
                start = m.start()
            depth += 1
        elif depth:
            depth -= 1
            if depth == 0:
                spans.append((start, m.end()))
    if depth:
        spans.append((start, len(text)))
    if not spans:
        return text
    kept: list[str] = []
    prev = 0
    for a, b in spans:
        kept.append(text[prev:a])
        prev = b
    kept.append(text[prev:])
    return "".join(kept)


def _balanced_objects(text: str):
    dec = json.JSONDecoder()
    idx = text.find("{")
    while idx != -1:
        try:
            _, end = dec.raw_decode(text, idx)
            yield text[idx:end]
            idx = text.find("{", end)
        except ValueError:
            idx = text.find("{", idx + 1)


def extract_json(text: str) -> dict | None:
    if not text:
        return None
    text = _strip_reasoning(text)
    candidates: list = []
    for m in _FENCE.finditer(text):
        try:
            candidates.append(json.loads(m.group(1)))
        except json.JSONDecodeError:
            pass
    for chunk in _balanced_objects(text):
        try:
            candidates.append(json.loads(chunk))
        except json.JSONDecodeError:
            pass
    dicts = [c for c in candidates if isinstance(c, dict)]
    actionable = [c for c in dicts if "action" in c or "final" in c]
    if actionable:
        return actionable[-1]
    return dicts[-1] if dicts else None



PROBE_TOOL = [{
    "type": "function",
    "function": {"name": "shard_probe", "description": "Call this with any string to confirm the "
                                                       "endpoint supports native tool calling.",
                 "parameters": {"type": "object",
                                "properties": {"note": {"type": "string"}}}},
}]

VALIDATED, COMPATIBLE, UNSUPPORTED = "validated", "compatible", "unsupported"


def _model_identity_parts(identity: str) -> tuple[str, str]:
    parts = (identity or "").rsplit("/", 1)
    return (parts[0], parts[1]) if len(parts) == 2 else ("", parts[0])


def _explicit_vendor_mismatch(left: str, right: str) -> bool:
    left_vendor, _ = _model_identity_parts(left)
    right_vendor, _ = _model_identity_parts(right)
    return bool(left_vendor and right_vendor and left_vendor != right_vendor)


def _same_model_identity(left: str, right: str) -> bool:
    _, left_leaf = _model_identity_parts(left)
    _, right_leaf = _model_identity_parts(right)
    if not left_leaf or not right_leaf:
        return False
    if _explicit_vendor_mismatch(left, right):
        return False
    if right_leaf == left_leaf:
        return True
    prefix = left_leaf + "-"
    if not right_leaf.startswith(prefix):
        return False
    suffix = right_leaf[len(prefix):]
    return bool(re.fullmatch(r"(?:\d{4}|\d{4}-\d{2}-\d{2})", suffix))


def _model_identity_verdict(requested: str, served: str) -> str:
    if not served:
        return "missing"
    return "matched" if _same_model_identity(requested, served) else "substituted"


def _response_model_identity(data: dict, requested: str) -> tuple[str, str, str]:
    conflict = data.get("_model_identity_error")
    if conflict:
        identities = data.get("_model_identities")
        served = " | ".join(identities) if isinstance(identities, list) else ""
        return served, "conflicting", str(conflict)
    served = data.get("model") if isinstance(data.get("model"), str) else ""
    return served, _model_identity_verdict(requested, served), ""


def _model_identity_error(requested: str, served: str, verdict: str) -> str:
    if verdict == "matched":
        return ""
    if verdict == "missing":
        return (f"provider response did not identify the model that answered; requested "
                f"{requested!r} cannot be verified")
    if verdict == "conflicting":
        return f"provider response named conflicting model identities: {served or 'invalid value'}"
    return f"provider served {served!r}, not the requested model {requested!r}"


def _substituted(observed: dict) -> bool:
    asked = observed.get("requested") or ""
    served = observed.get("model") or ""
    return bool(asked and served) and not _same_model_identity(asked, served)


def probe_endpoint(backend, *, model: str = "", validated_model: str = "",
                   timeout: int = 60) -> dict:
    observed: dict = {"tool_calls": 0, "model": "", "requested": "", "substituted": False,
                      "identity_verdict": "", "error": ""}
    try:
        result = backend.chat(
            [{"role": "user", "content": "Call shard_probe with any note to confirm this endpoint "
                                         "supports native tool calling."}],
            PROBE_TOOL, model=model, timeout=timeout, tool_choice="auto")
    except Exception as e:
        return {"verdict": UNSUPPORTED, "why": f"the request failed ({e.__class__.__name__}: {e})",
                "observed": observed | {"error": str(e)[:200]}}

    observed["requested"] = getattr(result, "model", "") or model
    observed["model"] = getattr(result, "served_model", "") or ""
    observed["identity_verdict"] = (
        getattr(result, "identity_verdict", "")
        or _model_identity_verdict(observed["requested"], observed["model"]))
    observed["substituted"] = observed["identity_verdict"] == "substituted"
    observed["tool_calls"] = len(getattr(result, "tool_calls", ()) or ())
    if not getattr(result, "ok", False):
        return {"verdict": UNSUPPORTED,
                "why": f"the endpoint answered with an error: {getattr(result, 'error', '')[:200]}",
                "observed": observed}
    if not observed["tool_calls"]:
        return {"verdict": UNSUPPORTED,
                "why": "the endpoint answered without a tool call, so it does not support native "
                       "tool calling. Shard's solver requires it — a review here would find nothing "
                       "and look like a clean repository.",
                "observed": observed}
    identity_error = _model_identity_error(observed["requested"], observed["model"],
                                           observed["identity_verdict"])
    if identity_error:
        return {"verdict": UNSUPPORTED,
                "why": f"native tool calling cannot be accepted: {identity_error}",
                "observed": observed}

    measured_id = observed["model"] or observed["requested"] or ""
    vendor_mismatch = _explicit_vendor_mismatch(observed["requested"], observed["model"])
    measured = (measured_id if vendor_mismatch else measured_id.split("/")[-1]) \
        or "the endpoint's default"
    if validated_model and not vendor_mismatch and _same_model_identity(validated_model, measured_id):
        return {"verdict": VALIDATED,
                "why": f"native tool calling works and {measured} is the configuration this project "
                       "has measured.", "observed": observed}
    return {"verdict": COMPATIBLE,
            "why": f"native tool calling works. {measured} is not a model this project has numbers "
                   f"for, which is a supported choice and not a warning — you supply the "
                   "inference.",
            "observed": observed}
