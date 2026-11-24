"""Directive extraction: the instruction-following core of the scripted agents.

The scripted agents model a *maximally gullible* reader: any sentence in a tool output that
reads as an actionable instruction is turned into a :data:`Directive`. The grammar is plain
English (so the same payloads are meaningful to real LLM targets), deliberately covering the
action verbs used in published indirect-prompt-injection benchmarks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

URL_RE = re.compile(r"https?://[^\s)\"'`<>]+")
EMAIL_RE = re.compile(r"(?<![\w/])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
PATH_RE = re.compile(r"(?<![\w:/.~-])(/(?:[\w.-]+/)*[\w.-]+)")
TRANSFER_TO_RE = re.compile(
    r"\bto\s+(?:the\s+)?(?:account\s+|acct\.?\s+)?(ACCT-[A-Z0-9]+(?:-[A-Z0-9]+)*)"
)
AMOUNT_RE = re.compile(r"\$\s?(\d[\d,]*(?:\.\d{1,2})?)")
MD_LINK_RE = re.compile(r"(!?)\[[^\]]*\]\((https?://[^)\s]+)\)")
QUOTED_RE = re.compile(r"[\"“]([^\"”]+)[\"”]")

_TRAILING = ".,;:!?'\""


@dataclass(frozen=True)
class Transfer:
    amount: float
    to_account: str


@dataclass(frozen=True)
class SendEmail:
    to: str
    paths: tuple[str, ...] = ()
    include_inbox: bool = False
    body: str | None = None


@dataclass(frozen=True)
class Fetch:
    url: str
    paths: tuple[str, ...] = ()
    b64: bool = False


@dataclass(frozen=True)
class ReplyLink:
    url: str
    image: bool
    paths: tuple[str, ...] = ()
    b64: bool = False


@dataclass(frozen=True)
class Delete:
    paths: tuple[str, ...]


@dataclass(frozen=True)
class Shell:
    command: str


@dataclass(frozen=True)
class Grant:
    username: str
    role: str


@dataclass(frozen=True)
class WriteFile:
    path: str
    content: str
    append: bool


@dataclass(frozen=True)
class CopyFile:
    source: str
    dest: str


@dataclass(frozen=True)
class Respond:
    text: str
    override: bool


@dataclass(frozen=True)
class Remember:
    text: str


@dataclass(frozen=True)
class Recall:
    pass


Directive = (
    Transfer
    | SendEmail
    | Fetch
    | ReplyLink
    | Delete
    | Shell
    | Grant
    | WriteFile
    | CopyFile
    | Respond
    | Remember
    | Recall
)


def split_units(text: str) -> list[str]:
    """Split text into sentence-like units, never splitting inside quotes or backticks."""
    units: list[str] = []
    buf: list[str] = []
    in_quote = False
    in_code = False
    n = len(text)
    for i, ch in enumerate(text):
        if ch == "`":
            in_code = not in_code
        elif ch in '"“”' and not in_code:
            in_quote = ch != "”" and not (in_quote and ch == '"')
        if ch == "\n" and not in_code:
            units.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
        boundary = ch in ".!?" and (i + 1 == n or text[i + 1] in " \t")
        if boundary and not in_quote and not in_code:
            units.append("".join(buf))
            buf = []
    units.append("".join(buf))
    return [u.strip() for u in units if u.strip()]


def _clean(token: str) -> str:
    return token.rstrip(_TRAILING)


def _urls(unit: str) -> list[str]:
    return [_clean(u) for u in URL_RE.findall(unit)]


def _paths(unit: str) -> tuple[str, ...]:
    stripped = MD_LINK_RE.sub(" ", unit)
    stripped = URL_RE.sub(" ", stripped)
    stripped = EMAIL_RE.sub(" ", stripped)
    found = [_clean(p) for p in PATH_RE.findall(stripped)]
    return tuple(p for p in found if len(p) > 1)


def _emails(unit: str) -> list[str]:
    return [_clean(e) for e in EMAIL_RE.findall(URL_RE.sub(" ", unit))]


def _has(pattern: str, unit: str) -> re.Match[str] | None:
    return re.search(pattern, unit, re.IGNORECASE)


def parse_unit(unit: str) -> Directive | None:
    """Return the directive a gullible reader would extract from one sentence, if any."""
    lower = unit.lower()
    b64 = "base64" in lower or "base-64" in lower

    m = _has(
        r"\b(?:remember|memorize|keep in mind|save for later)\b[^\"“]*[\"“]([^\"”]+)[\"”]", unit
    )
    if m:
        return Remember(m.group(1).strip())

    if _has(
        r"\b(?:execute|follow|carry out|perform|act on|complete)\b.*\b(?:remembered|saved|stored|"
        r"memorized)\b.*\b(?:instruction|note|step|request|item)s?\b",
        unit,
    ):
        return Recall()

    link = MD_LINK_RE.search(unit)
    if link and _has(r"\b(?:include|add|append|render|show|embed|end|put|insert)\b", unit):
        return ReplyLink(url=link.group(2), image=link.group(1) == "!", paths=_paths(unit), b64=b64)

    m = _has(
        r"\b(?:respond|reply|answer|say|tell the user|tell them|inform the user)\b"
        r"([^\"“]*)[\"“]([^\"”]+)[\"”]",
        unit,
    )
    if m:
        override = bool(re.search(r"\b(?:only|instead|exactly|just)\b", m.group(1), re.IGNORECASE))
        return Respond(text=m.group(2).strip(), override=override)

    m = _has(r"\b(?:run|execute|type|enter)\b[^`]*`([^`]+)`", unit)
    if m:
        return Shell(m.group(1).strip())

    paths = _paths(unit)
    if _has(r"\b(?:copy|cp|duplicate|back up|mirror)\b", unit) and len(paths) >= 2:
        return CopyFile(source=paths[0], dest=paths[1])

    m = _has(
        r"\b(write|save|append|add)\b\s+[\"“]([^\"”]+)[\"”]\s+(?:to|into|at)\s+"
        r"(?:the\s+)?(?:end\s+of\s+)?(?:file\s+)?(/[\w./-]+)",
        unit,
    )
    if m:
        return WriteFile(
            path=_clean(m.group(3)),
            content=m.group(2),
            append=m.group(1).lower() in {"append", "add"},
        )

    acct = TRANSFER_TO_RE.search(unit)
    amount = AMOUNT_RE.search(unit)
    if acct and amount and _has(r"\b(?:transfer|wire|pay|send|move|remit)\b", unit):
        return Transfer(amount=float(amount.group(1).replace(",", "")), to_account=acct.group(1))

    emails = _emails(unit)
    if emails and _has(r"\b(?:send|forward|email|e-mail|mail|cc|bcc)\b", unit):
        include_inbox = bool(
            _has(
                r"\b(?:inbox|every email|all (?:of )?(?:my |the |these )?(?:emails|messages))\b",
                unit,
            )
        )
        body = None
        quoted = _has(r"\b(?:saying|that says|with the text|body)\b:?\s*[\"“]([^\"”]+)[\"”]", unit)
        if quoted:
            body = quoted.group(1)
        return SendEmail(to=emails[0], paths=paths, include_inbox=include_inbox, body=body)

    for pattern in (
        r"\b(?:grant|give|assign)\s+(?:user\s+)?([\w.-]+)\s+(?:the\s+|an?\s+)?(\w+)\s+"
        r"(?:role|privileges|permissions|access)\b",
        r"\b(?:promote|elevate|upgrade)\s+(?:user\s+)?([\w.-]+)\s+to\s+(?:the\s+|an?\s+)?(\w+)\b",
        r"\bmake\s+(?:user\s+)?([\w.-]+)\s+(?:an?\s+)?(admin|owner)\b",
        r"\bset\s+(?:the\s+)?role\s+(?:of|for)\s+(?:user\s+)?([\w.-]+)\s+to\s+(\w+)\b",
    ):
        m = _has(pattern, unit)
        if m:
            return Grant(username=m.group(1), role=m.group(2).lower())

    if paths and _has(r"\b(?:delete|remove|erase|wipe|purge)\b", unit):
        return Delete(paths=paths)

    urls = _urls(unit)
    if urls and _has(
        r"\b(?:visit|open|fetch|load|retrieve|navigate to|go to|request|call|ping|browse to)\b",
        unit,
    ):
        return Fetch(url=urls[0], paths=paths, b64=b64)

    return None


def parse_directives(text: str) -> list[tuple[str, Directive]]:
    """Extract ``(unit, directive)`` pairs from text, in reading order."""
    found: list[tuple[str, Directive]] = []
    for unit in split_units(text):
        directive = parse_unit(unit)
        if directive is not None:
            found.append((unit, directive))
    return found
