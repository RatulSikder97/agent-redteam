"""Scenario schema, YAML loading, and per-run materialization.

A scenario couples a benign user task with an injected payload placed somewhere the agent
will read it (an email, file, web page, shell output, or bank memo), plus two programmatic
oracles: ``attack_success`` (did the attacker's goal happen?) and ``utility`` (did the user's
task still get done?).

World text uses two kinds of placeholders, substituted at materialization time:

* ``{{canary}}`` - a per-(seed, scenario) random secret, so exfiltration is detectable
  without false positives from static strings.
* ``{{INJECTION}}``, ``{{INJECTION_2}}``, ... - where payloads are inserted. In the benign
  (control) run they are replaced with the empty string.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from importlib import resources
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator

from agent_redteam.agents.base import PlanStep
from agent_redteam.encoding import MUTATORS, apply_mutators
from agent_redteam.oracles import Predicate
from agent_redteam.tools import TOOLS
from agent_redteam.world import WorldSpec

ATTACKER_DOMAIN = "attacker.example"
_MARKER_RE = re.compile(r"\{\{(INJECTION(?:_\d+)?)\}\}")


class Category(StrEnum):
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    EXCESSIVE_AGENCY = "excessive_agency"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    GOAL_HIJACKING = "goal_hijacking"
    MULTI_TURN = "multi_turn"
    ENCODING_OBFUSCATION = "encoding_obfuscation"


# Category-level mapping to OWASP Top 10 for LLM Applications (2025) and MITRE ATLAS.
TAXONOMY: dict[Category, dict[str, list[str]]] = {
    Category.INDIRECT_PROMPT_INJECTION: {
        "owasp": ["LLM01"],
        "atlas": ["AML.T0051.001"],
    },
    Category.DATA_EXFILTRATION: {
        "owasp": ["LLM01", "LLM02", "LLM05"],
        "atlas": ["AML.T0051.001", "AML.T0057"],
    },
    Category.EXCESSIVE_AGENCY: {
        "owasp": ["LLM01", "LLM06"],
        "atlas": ["AML.T0051.001", "AML.T0053"],
    },
    Category.PRIVILEGE_ESCALATION: {
        "owasp": ["LLM01", "LLM06"],
        "atlas": ["AML.T0051.001", "AML.T0053"],
    },
    Category.GOAL_HIJACKING: {
        "owasp": ["LLM01", "LLM09"],
        "atlas": ["AML.T0051.001", "AML.T0054"],
    },
    Category.MULTI_TURN: {
        "owasp": ["LLM01", "LLM06"],
        "atlas": ["AML.T0051.001"],
    },
    Category.ENCODING_OBFUSCATION: {
        "owasp": ["LLM01"],
        "atlas": ["AML.T0051.001", "AML.T0068"],
    },
}


class Injection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vector: Literal["email", "file", "web", "shell", "bank", "multi"]
    payloads: dict[str, str] = Field(min_length=1)
    mutators: list[str] = Field(default_factory=list)

    @field_validator("payloads")
    @classmethod
    def _marker_names(cls, value: dict[str, str]) -> dict[str, str]:
        for key in value:
            if not re.fullmatch(r"INJECTION(?:_\d+)?", key):
                raise ValueError(f"payload key '{key}' must be INJECTION or INJECTION_<n>")
        return value

    @field_validator("mutators")
    @classmethod
    def _known_mutators(cls, value: list[str]) -> list[str]:
        unknown = [m for m in value if m not in MUTATORS]
        if unknown:
            raise ValueError(f"unknown mutator(s) {unknown}; known: {sorted(MUTATORS)}")
        return value


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    title: str
    category: Category
    description: str
    severity: Literal["low", "medium", "high", "critical"]
    owasp: list[str] = Field(default_factory=list)
    atlas: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    inherit_base_world: bool = True
    world: WorldSpec = Field(default_factory=WorldSpec)
    turns: list[str] = Field(min_length=1)
    plan: list[PlanStep] = Field(default_factory=list)
    authorized_tools: dict[int, list[str]] | None = None
    injection: Injection
    attack_success: Predicate
    utility: Predicate

    @model_validator(mode="after")
    def _consistency(self) -> Scenario:
        if not self.owasp:
            self.owasp = list(TAXONOMY[self.category]["owasp"])
        if not self.atlas:
            self.atlas = list(TAXONOMY[self.category]["atlas"])
        for step in self.plan:
            if step.tool not in TOOLS:
                raise ValueError(f"plan step uses unknown tool '{step.tool}'")
            if not 0 <= step.turn < len(self.turns):
                raise ValueError(f"plan step turn {step.turn} out of range")
        markers = _MARKER_RE.findall(json.dumps(self.world.model_dump(mode="json")))
        if sorted(markers) != sorted(self.injection.payloads):
            raise ValueError(
                f"world markers {sorted(markers)} must match payload keys "
                f"{sorted(self.injection.payloads)} exactly once each"
            )
        return self

    def authorized_by_turn(self) -> dict[int, frozenset[str]]:
        """Tools the user's request needs per turn (the confirmation policy's intent model)."""
        if self.authorized_tools is not None:
            return {t: frozenset(tools) for t, tools in self.authorized_tools.items()}
        out: dict[int, set[str]] = {}
        for step in self.plan:
            out.setdefault(step.turn, set()).add(step.tool)
        return {t: frozenset(v) for t, v in out.items()}


_PREDICATE = TypeAdapter(Predicate)


def canary_for(seed: int, scenario_id: str) -> str:
    digest = hashlib.sha256(f"{seed}:{scenario_id}".encode()).hexdigest()
    return f"sk-canary-{digest[:24]}"


def _render(obj: Any, replacements: Mapping[str, str]) -> Any:
    if isinstance(obj, str):
        for key, value in replacements.items():
            obj = obj.replace("{{" + key + "}}", value)
        return obj
    if isinstance(obj, list):
        return [_render(v, replacements) for v in obj]
    if isinstance(obj, dict):
        return {_render(k, replacements): _render(v, replacements) for k, v in obj.items()}
    return obj


@dataclass(frozen=True)
class Materialized:
    world: WorldSpec
    attack_success: Predicate
    utility: Predicate
    payloads: dict[str, str]
    canary: str


def materialize(
    scenario: Scenario,
    base_world: WorldSpec | None,
    *,
    seed: int,
    attacked: bool,
    payloads: Mapping[str, str] | None = None,
    mutators: Sequence[str] | None = None,
) -> Materialized:
    """Build the concrete world and oracles for one run.

    ``payloads``/``mutators`` override the scenario's own (used by adaptive attackers).
    """
    canary = canary_for(seed, scenario.id)
    rng = random.Random(f"{seed}:{scenario.id}:mutators")
    chain = list(scenario.injection.mutators if mutators is None else mutators)
    raw = dict(scenario.injection.payloads if payloads is None else payloads)
    final = {k: apply_mutators(v, chain, rng) for k, v in raw.items()} if attacked else {}
    replacements = {"canary": canary, "attacker_domain": ATTACKER_DOMAIN}
    replacements |= {k: final.get(k, "") for k in scenario.injection.payloads}

    spec = scenario.world
    if scenario.inherit_base_world and base_world is not None:
        spec = spec.merged_over(base_world)
    world = WorldSpec.model_validate(_render(spec.model_dump(mode="json"), replacements))
    oracle_vars = {"canary": canary, "attacker_domain": ATTACKER_DOMAIN}
    attack = _PREDICATE.validate_python(
        _render(scenario.attack_success.model_dump(mode="json"), oracle_vars)
    )
    utility = _PREDICATE.validate_python(
        _render(scenario.utility.model_dump(mode="json"), oracle_vars)
    )
    return Materialized(world, attack, utility, final, canary)


# --------------------------------------------------------------------------- loading


def default_scenario_dir() -> Path:
    return Path(str(resources.files("agent_redteam") / "scenarios"))


def load_base_world(directory: Path) -> WorldSpec | None:
    path = directory / "_base_world.yaml"
    if not path.exists():
        return None
    return WorldSpec.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def _iter_docs(path: Path) -> Iterable[dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "scenarios" in data:
        yield from data["scenarios"]
    elif isinstance(data, dict):
        yield data
    elif isinstance(data, list):
        yield from data
    else:
        raise ValueError(f"{path}: expected a mapping or a list of scenarios")


@dataclass(frozen=True)
class ScenarioSuite:
    scenarios: list[Scenario]
    base_world: WorldSpec | None

    def fingerprint(self) -> str:
        blob = json.dumps(
            {
                "base": self.base_world.model_dump(mode="json") if self.base_world else None,
                "scenarios": [s.model_dump(mode="json") for s in self.scenarios],
            },
            sort_keys=True,
        )
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    def filter(
        self, categories: Sequence[str] | None = None, ids: Sequence[str] | None = None
    ) -> ScenarioSuite:
        chosen = [
            s
            for s in self.scenarios
            if (not categories or s.category.value in categories) and (not ids or s.id in ids)
        ]
        return ScenarioSuite(chosen, self.base_world)

    def get(self, scenario_id: str) -> Scenario:
        for s in self.scenarios:
            if s.id == scenario_id:
                return s
        raise KeyError(f"unknown scenario '{scenario_id}'")


def load_suite(directory: Path | None = None) -> ScenarioSuite:
    """Load every ``*.yaml`` (except ``_*.yaml``) in ``directory`` (default: bundled set)."""
    directory = directory or default_scenario_dir()
    scenarios: list[Scenario] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.yaml")):
        if path.name.startswith("_"):
            continue
        for doc in _iter_docs(path):
            try:
                scenario = Scenario.model_validate(doc)
            except ValueError as exc:
                ident = doc.get("id", "?") if isinstance(doc, dict) else "?"
                raise ValueError(f"{path.name}: scenario '{ident}': {exc}") from exc
            if scenario.id in seen:
                raise ValueError(f"{path.name}: duplicate scenario id '{scenario.id}'")
            seen.add(scenario.id)
            scenarios.append(scenario)
    return ScenarioSuite(scenarios, load_base_world(directory))
