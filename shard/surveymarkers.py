
from __future__ import annotations

import re

_C_LIKE = frozenset({"c", "c++", "zig"})

MARKERS: tuple[tuple[str, frozenset[str] | None, re.Pattern[str]], ...] = (
    ("input_boundary", _C_LIKE,
     re.compile(r"\b(?:fread|recv|recvfrom|fgets|getline|read)\s*\(")),
    ("input_boundary", None, re.compile(r"\bmain\s*\(\s*int\s+argc")),
    ("input_boundary", frozenset({"python"}),
     re.compile(r"\b(?:sys\.argv|input\s*\(|\.read\s*\(|request\.(?:args|form|data|json))")),
    ("input_boundary", frozenset({"go"}), re.compile(r"\b(?:os\.Args|bufio\.NewReader|r\.Body)")),

    ("unsafe_op", _C_LIKE,
     re.compile(r"\b(?:strcpy|strcat|sprintf|gets|alloca|sscanf|memcpy|memmove)\s*\(")),

    ("parser", None,
     re.compile(r"\b(?:(?:parse|decode|unmarshal|demarshal)[A-Za-z_]*|deserial\w*)\s*\(")),

    ("ffi", frozenset({"rust"}), re.compile(r"\bunsafe\s*\{|\bextern\s+\"C\"")),
    ("ffi", frozenset({"go"}), re.compile(r"^\s*import\s+\"C\"", re.M)),
    ("ffi", frozenset({"python"}), re.compile(r"\b(?:ctypes|cffi)\b")),
    ("ffi", frozenset({"java"}), re.compile(r"\bnative\s+\w+\s+\w+\s*\(")),

    ("deserialiser", frozenset({"python"}),
     re.compile(r"\b(?:pickle\.loads?|yaml\.load\s*\(|eval\s*\(|exec\s*\()")),
    ("deserialiser", frozenset({"javascript", "typescript"}),
     re.compile(r"\beval\s*\(|\bvm\.runIn\w+|\bFunction\s*\(")),
    ("deserialiser", frozenset({"java"}), re.compile(r"\breadObject\s*\(")),
    ("deserialiser", frozenset({"ruby"}),
     re.compile(r"\b(?:Marshal\.load|YAML\.load)\s*\(|\bunsafe_load(?:_file)?\s*\(")),
    ("deserialiser", frozenset({"php"}), re.compile(r"\bunserialize\s*\(")),


    ("command_exec", frozenset({"python"}),
     re.compile(r"\bos\.(?:system|popen)\s*\(|\bshell\s*=\s*True\b")),

    ("template_injection", frozenset({"python"}),
     re.compile(r"\brender_template_string\s*\(")),

    ("sql_injection", frozenset({"python"}),
     re.compile(r"\.execute\s*\(\s*f[\"']")),

    ("command_exec", frozenset({"javascript", "typescript"}),
     re.compile(r"\bexecSync\s*\(|\bexecFile(?:Sync)?\s*\(|\bshell\s*:\s*true\b")),


    ("deserialiser", frozenset({"c#"}),
     re.compile(r"\bBinaryFormatter\b|\bTypeNameHandling\s*[.=]|\bLosFormatter\b|"
                r"\bNetDataContractSerializer\b|\bObjectStateFormatter\b")),
    ("ffi", frozenset({"c#"}), re.compile(r"\[\s*DllImport")),
    ("command_exec", frozenset({"c#"}), re.compile(r"\bUseShellExecute\s*=\s*true\b")),
    ("sql_injection", frozenset({"c#"}),
     re.compile(r"new\s+SqlCommand\s*\(\s*[$\"].*[+{]|\.CommandText\s*=\s*[$\"].*[+{]")),

    ("command_exec", frozenset({"php"}),
     re.compile(r"(?<![>:$\w])\b(?:exec|system|shell_exec|passthru|popen|proc_open)\s*\(")),
    ("file_inclusion", frozenset({"php"}),
     re.compile(r"\b(?:include|include_once|require|require_once)\s*\(?\s*"
                r"(?:(?:[A-Za-z_\\][A-Za-z0-9_\\]*|'[^'\n]*')\s*\.\s*)*"
                r"(?:\$|\"[^\"\n]*\$)")),

    ("sql_injection", frozenset({"java"}),
     re.compile(r"\.execute(?:Query|Update)?\s*\(\s*\"[^\"]*\"\s*\+|"
                r"\.execute(?:Query|Update)?\s*\(\s*String\.format\s*\(")),

    ("sql_injection", frozenset({"ruby"}),
     re.compile("\\.(?:where|find_by_sql|order|group)\\s*\\(?\\s*\"[^\"\n]*#\\{")),


    ("command_exec", frozenset({"java"}),
     re.compile(r"getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(")),
    ("xxe", frozenset({"java"}),
     re.compile(r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\s*\.\s*newInstance\s*\(")),

    ("sql_injection", frozenset({"go"}),
     re.compile(r"\.(?:Query|QueryRow|Exec)(?:Context)?\s*\(\s*fmt\.Sprintf\s*\(")),


    ("sql_injection", frozenset({"php"}),
     re.compile(r"(?:->query|->exec|mysqli_query|pg_query)\s*\(\s*[\"'][^\"']*\$")),

    ("prototype_pollution", frozenset({"javascript", "typescript"}),
     re.compile(r"\[\s*[\"']__proto__[\"']\s*\]\s*=|\.__proto__\s*=|"
                r"\[\s*[\"']constructor[\"']\s*\]\s*\[\s*[\"']prototype[\"']\s*\]")),

    ("xss", frozenset({"javascript", "typescript"}),
     re.compile(r"\.(?:inner|outer)HTML\s*=(?!=)\s*(?![\"'\s;])|"
                r"\.(?:inner|outer)HTML\s*=(?!=)\s*`[^`]*\$\{|"
                r"\binsertAdjacentHTML\s*\(|\bdangerouslySetInnerHTML\b|\bv-html\b|"
                r"\bdocument\.write(?:ln)?\s*\(")),

    ("xss", frozenset({"php"}), re.compile(r"\{!!|<\?=\s*\$")),

    ("xss", frozenset({"ruby"}), re.compile(r"\braw\s*\(")),

    ("sql_injection", frozenset({"javascript", "typescript"}),
     re.compile(r"\.(?:query|raw|unprepared)\s*\(\s*`[^`]*\$\{")),
)

MARKER_LANGUAGES = frozenset(lang for _kind, langs, _pattern in MARKERS if langs for lang in langs)


def _is_comment(stripped: str, language: str) -> bool:
    if language == "python" or language == "ruby":
        return stripped.startswith("#")
    if language == "asm":
        return stripped.startswith((";", "#", "//", "/*", "*"))
    if stripped.startswith("*"):
        return stripped.lstrip("*")[:1].strip() in ("", "/")
    return stripped.startswith(("//", "/*", "#"))


def kind_of(line: str, stripped: str, language: str) -> str | None:
    if not stripped or _is_comment(stripped, language):
        return None
    for kind, langs, pattern in MARKERS:
        if langs is not None and language not in langs:
            continue
        if pattern.search(line):
            return kind
    return None


__all__ = ["MARKERS", "MARKER_LANGUAGES", "kind_of"]
