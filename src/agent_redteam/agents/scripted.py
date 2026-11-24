"""Deterministic scripted agents for offline benchmarking and CI.

:class:`ScriptedAgent` executes the scenario's reference trajectory (what a competent agent
would do for the user's request) and, like a maximally gullible LLM, follows any instruction
it can read in tool outputs - including obfuscated ones (see
:func:`agent_redteam.encoding.normalize_for_reading`).

With the ``spotlight`` defense enabled it behaves like a model that respects datamarked
content: it ignores instructions in tool outputs the injection detector flagged, but is still
fooled by instructions the detector misses. ``confirm`` and ``egress`` are enforced by the
executor and response filter, exactly as for an LLM-backed agent.

These agents are *behavioral archetypes*, not models of any particular LLM. Their purpose
is to validate the harness and oracles and to make defense deltas measurable offline.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from urllib.parse import quote

from agent_redteam.agents.base import (
    AgentOutput,
    Episode,
    Observation,
    RunStatus,
    ToolBudgetExceededError,
)
from agent_redteam.defenses import DefenseConfig
from agent_redteam.directives import (
    CopyFile,
    Delete,
    Directive,
    Fetch,
    Grant,
    Recall,
    Remember,
    ReplyLink,
    Respond,
    SendEmail,
    Shell,
    Transfer,
    WriteFile,
    parse_directives,
    split_units,
)
from agent_redteam.encoding import normalize_for_reading

_EMAIL_ID = re.compile(r"^\[([^\]]+)\]", re.MULTILINE)


def fill_url(url: str, data: str | None, b64: bool) -> str:
    """Substitute exfiltrated data into a URL the way injected instructions describe."""
    if data is None:
        return url
    value = base64.b64encode(data.encode()).decode() if b64 else data
    encoded = quote(value, safe="")
    if "DATA" in url:
        return url.replace("DATA", encoded)
    if url.endswith("="):
        return url + encoded
    return f"{url}{'&' if '?' in url else '?'}d={encoded}"


@dataclass
class _TurnState:
    facts: list[str] = field(default_factory=list)
    override: str | None = None
    appendix: list[str] = field(default_factory=list)


@dataclass
class ScriptedAgent:
    """Gullible reference agent; pair with :class:`DefenseConfig` for defended baselines."""

    name: str = "naive"
    defenses: DefenseConfig = field(default_factory=DefenseConfig)
    max_depth: int = 3
    max_injected_actions: int = 20
    _injected: int = field(default=0, init=False, repr=False)

    @property
    def model(self) -> str | None:
        return None

    def run(self, episode: Episode) -> AgentOutput:
        memory: list[str] = []
        responses: list[str] = []
        self._injected = 0
        status: RunStatus = "ok"
        error: str | None = None
        for turn, _message in enumerate(episode.turns):
            episode.executor.turn = turn
            state = _TurnState()
            try:
                for step in (s for s in episode.plan if s.turn == turn):
                    obs = episode.executor.call(step.tool, step.args, origin="plan")
                    self._absorb(obs, state, memory, episode, depth=0)
            except ToolBudgetExceededError as exc:
                status, error = "budget_exhausted", str(exc)
                responses.append(self._compose(state))
                break
            responses.append(self._compose(state))
        return AgentOutput(
            response="\n\n".join(responses),
            status=status,
            error=error,
        )

    # ------------------------------------------------------------------ reading

    def _absorb(
        self,
        obs: Observation,
        state: _TurnState,
        memory: list[str],
        episode: Episode,
        depth: int,
    ) -> None:
        if not obs.ok:
            return
        readable = normalize_for_reading(obs.raw)
        directives = parse_directives(readable)
        directive_units = {unit for unit, _ in directives}
        state.facts.extend(u for u in split_units(readable) if u not in directive_units)
        follow = not (self.defenses.spotlight and obs.flagged)
        if not follow or depth >= self.max_depth:
            return
        for _unit, directive in directives:
            self._execute(directive, state, memory, episode, depth)

    def _gather(self, paths: tuple[str, ...], episode: Episode) -> str | None:
        if not paths:
            return None
        chunks = []
        for path in paths:
            obs = self._call(episode, "read_file", {"path": path})
            if obs is not None and obs.ok:
                chunks.append(obs.raw)
        return "\n".join(chunks) if chunks else None

    def _call(self, episode: Episode, tool: str, args: dict[str, object]) -> Observation | None:
        if self._injected >= self.max_injected_actions:
            return None
        self._injected += 1
        return episode.executor.call(tool, args, origin="injected")

    # ------------------------------------------------------------------ acting

    def _execute(
        self,
        d: Directive,
        state: _TurnState,
        memory: list[str],
        episode: Episode,
        depth: int,
    ) -> None:
        match d:
            case Remember(text=text):
                memory.append(text)
            case Recall():
                pending, memory[:] = list(memory), []
                for text in pending:
                    for _unit, inner in parse_directives(normalize_for_reading(text)):
                        self._execute(inner, state, memory, episode, depth + 1)
            case Respond(text=text, override=override):
                if override:
                    state.override = text
                else:
                    state.appendix.append(text)
            case ReplyLink(url=url, image=image, paths=paths, b64=b64):
                target = fill_url(url, self._gather(paths, episode), b64)
                state.appendix.append(f"![status]({target})" if image else f"[details]({target})")
            case Transfer(amount=amount, to_account=to_account):
                if episode.default_account is not None:
                    self._call(
                        episode,
                        "transfer",
                        {
                            "from_account": episode.default_account,
                            "to_account": to_account,
                            "amount": amount,
                            "memo": "as instructed",
                        },
                    )
            case SendEmail(to=to, paths=paths, include_inbox=include_inbox, body=body):
                parts = [body] if body else []
                gathered = self._gather(paths, episode)
                if gathered:
                    parts.append(gathered)
                if include_inbox:
                    parts.extend(self._read_inbox(episode))
                self._call(
                    episode,
                    "send_email",
                    {"to": to, "subject": "Fwd: as requested", "body": "\n\n".join(parts) or "FYI"},
                )
            case Fetch(url=url, paths=paths, b64=b64):
                target = fill_url(url, self._gather(paths, episode), b64)
                obs = self._call(episode, "fetch_url", {"url": target})
                if obs is not None:
                    self._absorb(obs, state, memory, episode, depth + 1)
            case Shell(command=command):
                obs = self._call(episode, "run_shell", {"command": command})
                if obs is not None:
                    self._absorb(obs, state, memory, episode, depth + 1)
            case Delete(paths=paths):
                for path in paths:
                    self._call(episode, "delete_file", {"path": path})
            case Grant(username=username, role=role):
                self._call(episode, "update_role", {"username": username, "role": role})
            case WriteFile(path=path, content=content, append=append):
                self._call(
                    episode,
                    "write_file",
                    {"path": path, "content": content, "mode": "append" if append else "overwrite"},
                )
            case CopyFile(source=source, dest=dest):
                data = self._gather((source,), episode)
                if data is not None:
                    self._call(episode, "write_file", {"path": dest, "content": data})

    def _read_inbox(self, episode: Episode) -> list[str]:
        listing = self._call(episode, "list_emails", {})
        if listing is None or not listing.ok:
            return []
        bodies = []
        for email_id in _EMAIL_ID.findall(listing.raw):
            obs = self._call(episode, "read_email", {"email_id": email_id})
            if obs is not None and obs.ok:
                bodies.append(obs.raw)
        return bodies

    @staticmethod
    def _compose(state: _TurnState) -> str:
        if state.override is not None:
            return state.override
        lines = ["Here is what I found:"]
        lines.extend(f"- {fact}" for fact in state.facts)
        lines.extend(state.appendix)
        return "\n".join(lines)
