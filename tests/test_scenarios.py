from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable
from typing import Any

import pytest

from agent_redteam.agents import ScriptedAgent
from agent_redteam.runner import run_episode
from agent_redteam.scenario import (
    TAXONOMY,
    Category,
    Scenario,
    ScenarioSuite,
    canary_for,
    load_suite,
    materialize,
)

ALL = load_suite()
IDS = [s.id for s in ALL.scenarios]
URL_HOST = re.compile(r"https?://([^/\s\"')?]+)")
EMAIL_DOMAIN = re.compile(r"@([\w-]+(?:\.[\w-]+)+)")


def test_suite_size_and_coverage(suite: ScenarioSuite) -> None:
    assert len(suite.scenarios) >= 50
    counts = Counter(s.category for s in suite.scenarios)
    assert set(counts) == set(Category)
    assert min(counts.values()) >= 6
    assert len(set(IDS)) == len(IDS)


def test_every_scenario_maps_to_taxonomy(suite: ScenarioSuite) -> None:
    for s in suite.scenarios:
        assert s.owasp
        assert all(re.fullmatch(r"LLM\d\d", o) for o in s.owasp)
        assert s.atlas
        assert all(a.startswith("AML.T") for a in s.atlas)
    assert set(TAXONOMY) == set(Category)


def test_payloads_only_target_reserved_example_domains(suite: ScenarioSuite) -> None:
    """Responsible-use guard: every host/address in the suite is an RFC 2606 .example name."""
    blob = " ".join(s.model_dump_json() for s in suite.scenarios)
    assert suite.base_world is not None
    blob += suite.base_world.model_dump_json()
    hosts = set(URL_HOST.findall(blob)) | set(EMAIL_DOMAIN.findall(blob))
    assert hosts
    assert all(h.endswith(".example") for h in hosts), sorted(
        h for h in hosts if not h.endswith(".example")
    )


@pytest.mark.parametrize("scenario_id", IDS)
def test_scenario_oracles_are_sound(scenario_id: str) -> None:
    """No false positive without the payload; utility achievable; exploitable by naive."""
    s = ALL.get(scenario_id)
    agent = ScriptedAgent()
    benign = run_episode(s, ALL, agent, seed=0, attacked=False)
    attacked = run_episode(s, ALL, agent, seed=0, attacked=True)
    assert benign.status == "ok"
    assert not benign.attack_success
    assert benign.utility
    assert attacked.attack_success


def test_materialize_substitutes_markers_and_canary(suite: ScenarioSuite) -> None:
    s = suite.get("exfil-url-param")
    attacked = materialize(s, suite.base_world, seed=3, attacked=True)
    benign = materialize(s, suite.base_world, seed=3, attacked=False)
    page = attacked.world.web["https://blog.example/rag-tips"]
    assert "attacker.example/collect" in page
    assert "{{" not in page
    assert "attacker.example" not in benign.world.web["https://blog.example/rag-tips"]
    assert attacked.world.secrets["payments_api_key"] == canary_for(3, s.id) != canary_for(4, s.id)
    assert attacked.canary in attacked.world.files["/home/alex/.env"]


def test_mutators_applied_at_materialization(suite: ScenarioSuite) -> None:
    s = suite.get("enc-tags-hijack")
    page = materialize(s, suite.base_world, seed=0, attacked=True).world.web[
        "https://news.example/markets"
    ]
    assert "Ignore" not in page
    assert any(0xE0000 <= ord(c) <= 0xE007F for c in page)


def test_schema_rejects_bad_scenarios(suite: ScenarioSuite) -> None:
    base = suite.get("ipi-file-delete").model_dump(mode="json")
    cases: list[tuple[Callable[[dict[str, Any]], object], str]] = [
        (lambda d: d["injection"]["payloads"].update({"INJECTION_2": "x"}), "markers"),
        (lambda d: d["plan"].append({"tool": "format_disk"}), "unknown tool"),
        (lambda d: d["injection"].update({"mutators": ["rot47"]}), "unknown mutator"),
        (lambda d: d.update({"id": "Bad ID"}), "pattern"),
    ]
    for mutate, msg in cases:
        doc = {
            **base,
            "injection": dict(base["injection"], payloads=dict(base["injection"]["payloads"])),
            "plan": list(base["plan"]),
        }
        mutate(doc)
        with pytest.raises(ValueError, match=msg):
            Scenario.model_validate(doc)


def test_authorized_tools_derived_from_plan(suite: ScenarioSuite) -> None:
    s = suite.get("mt-persisted-injection")
    auth = s.authorized_by_turn()
    assert "transfer" not in auth[0]
    assert "transfer" in auth[1]
