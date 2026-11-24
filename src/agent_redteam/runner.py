"""Run scenarios against agents and collect reproducible results."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from agent_redteam import __version__
from agent_redteam.agents.anthropic_agent import AgentAPIError
from agent_redteam.agents.base import (
    Agent,
    Episode,
    RunStatus,
    ToolCallRecord,
    ToolExecutor,
)
from agent_redteam.defenses import DefensePipeline
from agent_redteam.oracles import EvalContext
from agent_redteam.scenario import Scenario, ScenarioSuite, materialize
from agent_redteam.world import World

RecordStatus = RunStatus | Literal["harness_error"]


class RunRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    category: str
    attacked: bool
    repeat: int
    seed: int
    status: RecordStatus
    attack_success: bool
    utility: bool
    response: str
    calls: list[ToolCallRecord]
    removed_from_response: int = 0
    error: str | None = None
    usage: dict[str, int] = Field(default_factory=dict)

    @property
    def denied(self) -> int:
        return sum(c.status == "denied" for c in self.calls)

    @property
    def blocked(self) -> int:
        return sum(c.status == "blocked" for c in self.calls)

    @property
    def flagged(self) -> int:
        return sum(bool(c.flagged) for c in self.calls)

    @property
    def valid(self) -> bool:
        return self.status in {"ok", "refused", "budget_exhausted", "truncated"}


class SuiteMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent: str
    model: str | None
    defenses: list[str]
    seed: int
    repeats: int
    scenario_count: int
    suite_fingerprint: str
    harness_version: str = __version__
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))


class SuiteResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: SuiteMeta
    records: list[RunRecord]

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> SuiteResult:
        return cls.model_validate(json.loads(path.read_text(encoding="utf-8")))


def _default_account(world: World) -> str | None:
    accounts = world.user_accounts()
    return accounts[0].id if accounts else None


def run_episode(
    scenario: Scenario,
    suite: ScenarioSuite,
    agent: Agent,
    *,
    seed: int,
    attacked: bool,
    repeat: int = 0,
    payloads: Mapping[str, str] | None = None,
    mutators: Sequence[str] | None = None,
) -> RunRecord:
    """Run one (scenario, agent, attacked?) episode and score it with the oracles."""
    mat = materialize(
        scenario,
        suite.base_world,
        seed=seed,
        attacked=attacked,
        payloads=payloads,
        mutators=mutators,
    )
    world = World.from_spec(mat.world)
    pipeline = DefensePipeline(agent.defenses, scenario.authorized_by_turn())
    executor = ToolExecutor(world, pipeline)
    episode = Episode(
        turns=scenario.turns,
        executor=executor,
        plan=scenario.plan,
        default_account=_default_account(world),
    )
    try:
        output = agent.run(episode)
        status: RecordStatus = output.status
        response, error, usage = output.response, output.error, output.usage
    except AgentAPIError as exc:
        status, response, error, usage = "error", "", str(exc), {}
    response, removed = pipeline.filter_response(response)
    ctx = EvalContext(world=world, response=response, calls=executor.calls)
    try:
        attack_success = mat.attack_success.evaluate(ctx)
        utility = mat.utility.evaluate(ctx)
    except (KeyError, ValueError) as exc:
        status, error, attack_success, utility = "harness_error", f"oracle: {exc}", False, False
    return RunRecord(
        scenario_id=scenario.id,
        category=scenario.category.value,
        attacked=attacked,
        repeat=repeat,
        seed=seed,
        status=status,
        attack_success=attack_success,
        utility=utility,
        response=response,
        calls=executor.calls,
        removed_from_response=removed,
        error=error,
        usage=usage,
    )


ProgressFn = Callable[[RunRecord], None]


def run_suite(
    suite: ScenarioSuite,
    agent: Agent,
    *,
    seed: int = 0,
    repeats: int = 1,
    include_benign: bool = True,
    progress: ProgressFn | None = None,
) -> SuiteResult:
    """Run every scenario attacked (and, by default, un-attacked as a utility control)."""
    records: list[RunRecord] = []
    for scenario in suite.scenarios:
        for r in range(repeats):
            run_seed = seed + r
            modes = (False, True) if include_benign else (True,)
            for attacked in modes:
                record = run_episode(
                    scenario, suite, agent, seed=run_seed, attacked=attacked, repeat=r
                )
                records.append(record)
                if progress is not None:
                    progress(record)
    meta = SuiteMeta(
        agent=agent.name,
        model=agent.model,
        defenses=agent.defenses.names(),
        seed=seed,
        repeats=repeats,
        scenario_count=len(suite.scenarios),
        suite_fingerprint=suite.fingerprint(),
    )
    return SuiteResult(meta=meta, records=records)
