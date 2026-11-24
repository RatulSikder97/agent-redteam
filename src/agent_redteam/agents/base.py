"""Agent adapter interface and the defended tool executor every adapter goes through."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from agent_redteam.defenses import DefenseConfig, DefensePipeline
from agent_redteam.tools import TOOLS, ToolError, execute_tool
from agent_redteam.world import World

CallStatus = Literal["ok", "error", "denied", "blocked"]
Origin = Literal["plan", "injected", "model"]
RunStatus = Literal["ok", "refused", "error", "truncated", "budget_exhausted"]


class ToolCallRecord(BaseModel):
    """One attempted tool call, whether or not it was allowed to execute."""

    model_config = ConfigDict(extra="forbid")

    turn: int
    tool: str
    args: dict[str, Any]
    origin: Origin
    status: CallStatus
    output: str
    flagged: list[str] = Field(default_factory=list)
    layer: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class Observation:
    """What an agent gets back from a tool call."""

    text: str  # model-facing (possibly spotlighted) text
    raw: str  # underlying tool output
    status: CallStatus
    flagged: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.status == "ok"


class ToolBudgetExceededError(Exception):
    """Raised when an agent exceeds the per-episode tool-call budget."""


def _is_external(world: World, tool: str, args: Mapping[str, Any]) -> bool:
    if tool == "fetch_url":
        return True
    if tool == "send_email":
        return world.is_external_address(str(args.get("to", "")))
    if tool == "run_shell":
        command = str(args.get("command", "")).lower()
        return any(k in command for k in ("curl", "wget", "http://", "https://", " nc "))
    return False


@dataclass
class ToolExecutor:
    """Executes tool calls against the world, applying the configured defenses."""

    world: World
    defenses: DefensePipeline
    max_calls: int = 60
    turn: int = 0
    calls: list[ToolCallRecord] = field(default_factory=list)

    def call(self, tool: str, args: Mapping[str, Any], origin: Origin) -> Observation:
        if len(self.calls) >= self.max_calls:
            raise ToolBudgetExceededError(f"tool-call budget of {self.max_calls} exhausted")
        clean_args = dict(args)
        decision = self.defenses.authorize(
            tool, clean_args, self.turn, _is_external(self.world, tool, clean_args)
        )
        if not decision.allowed:
            status: CallStatus = "denied" if decision.layer == "confirm" else "blocked"
            message = f"Action not performed: {decision.reason}."
            self._record(
                tool, clean_args, origin, status, message, (), decision.layer, decision.reason
            )
            return Observation(text=message, raw=message, status=status)
        try:
            raw = execute_tool(self.world, tool, clean_args)
        except ToolError as exc:
            message = f"Error: {exc}"
            self._record(tool, clean_args, origin, "error", message, (), None, None)
            return Observation(text=message, raw=message, status="error")
        signatures = tuple(self.defenses.inspect(raw))
        text = self.defenses.present(tool, raw, signatures)
        self._record(tool, clean_args, origin, "ok", raw, signatures, None, None)
        return Observation(text=text, raw=raw, status="ok", flagged=signatures)

    def _record(
        self,
        tool: str,
        args: dict[str, Any],
        origin: Origin,
        status: CallStatus,
        output: str,
        flagged: Sequence[str],
        layer: str | None,
        reason: str | None,
    ) -> None:
        self.calls.append(
            ToolCallRecord(
                turn=self.turn,
                tool=tool,
                args=args,
                origin=origin,
                status=status,
                output=output[:2000],
                flagged=list(flagged),
                layer=layer,
                reason=reason,
            )
        )


class PlanStep(BaseModel):
    """One step of a scenario's reference (benign) trajectory."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    turn: int = 0


@dataclass(frozen=True)
class Episode:
    """Everything an agent needs to run one scenario."""

    turns: Sequence[str]
    executor: ToolExecutor
    plan: Sequence[PlanStep]
    default_account: str | None


@dataclass
class AgentOutput:
    response: str
    status: RunStatus = "ok"
    error: str | None = None
    usage: dict[str, int] = field(default_factory=dict)


class Agent(Protocol):
    """Pluggable agent adapter. Implementations must route every tool call through
    ``episode.executor.call`` so defenses and oracles see it."""

    name: str
    defenses: DefenseConfig

    @property
    def model(self) -> str | None: ...

    def run(self, episode: Episode) -> AgentOutput: ...


def tool_definitions() -> list[dict[str, Any]]:
    """Tool definitions in the provider-neutral JSON-schema form adapters can translate."""
    return [
        {"name": s.name, "description": s.description, "input_schema": s.input_schema()}
        for s in TOOLS.values()
    ]
