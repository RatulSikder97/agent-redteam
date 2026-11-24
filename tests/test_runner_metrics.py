from __future__ import annotations

from pathlib import Path

import pytest

from agent_redteam.agents import build_agent
from agent_redteam.compare import compare
from agent_redteam.metrics import Rate, summarize, wilson
from agent_redteam.report import write_report
from agent_redteam.runner import SuiteResult, run_suite
from agent_redteam.scenario import ScenarioSuite


@pytest.fixture(scope="module")
def results(suite: ScenarioSuite) -> dict[str, SuiteResult]:
    return {
        name: run_suite(suite, build_agent(name), seed=0)
        for name in ("naive", "spotlight", "confirm", "egress", "defended")
    }


def _records(r: SuiteResult) -> list[dict[str, object]]:
    return [rec.model_dump() for rec in r.records]


def test_runs_are_reproducible(suite: ScenarioSuite, results: dict[str, SuiteResult]) -> None:
    again = run_suite(suite, build_agent("defended"), seed=0)
    assert _records(again) == _records(results["defended"])


def test_seed_changes_canaries_not_outcomes(
    suite: ScenarioSuite, results: dict[str, SuiteResult]
) -> None:
    other = run_suite(suite.filter(categories=["data_exfiltration"]), build_agent("naive"), seed=1)
    assert all(r.attack_success for r in other.records if r.attacked)
    base = [r for r in results["naive"].records if r.category == "data_exfiltration"]
    assert [r.response for r in other.records] != [r.response for r in base]


def test_defense_ablation_is_monotone(results: dict[str, SuiteResult]) -> None:
    asr = {k: summarize(v).overall.asr.value for k, v in results.items()}
    assert asr["naive"] == 1.0
    for single in ("spotlight", "confirm", "egress"):
        assert asr["defended"] <= asr[single] < asr["naive"]
    for s in map(summarize, results.values()):
        assert s.overall.benign_utility.value == 1.0
        assert s.benign_false_positive.k == 0
        assert s.errors == 0


def test_json_round_trip(tmp_path: Path, results: dict[str, SuiteResult]) -> None:
    path = tmp_path / "r.json"
    results["naive"].save(path)
    assert SuiteResult.load(path) == results["naive"]


def test_wilson_interval() -> None:
    lo, hi = wilson(0, 10)
    assert lo == 0.0
    assert 0.277 < hi < 0.278
    lo, hi = wilson(5, 10)
    assert pytest.approx(lo, abs=1e-3) == 0.2366
    assert pytest.approx(hi, abs=1e-3) == 0.7634
    assert wilson(0, 0) == (0.0, 1.0)
    assert Rate(k=1, n=4).fmt(ci=False) == "25.0%"
    assert Rate(k=0, n=0).fmt() == "n/a"


def test_compare_detects_regressions(results: dict[str, SuiteResult]) -> None:
    worse = compare(results["defended"], results["naive"])
    assert not worse.passed
    assert any("overall: ASR" in r for r in worse.regressions)
    assert any("newly compromised" in w for w in worse.warnings)
    better = compare(results["naive"], results["defended"])
    assert better.passed
    assert better.improvements
    assert compare(results["defended"], results["defended"]).passed
    tolerant = compare(
        results["defended"],
        results["naive"],
        max_asr_increase=1.0,
        max_utility_drop=1.0,
        per_category=False,
    )
    assert tolerant.passed
    assert "Regression gate" in worse.to_markdown()


def test_report_files(tmp_path: Path, results: dict[str, SuiteResult]) -> None:
    md, html = write_report(list(results.values()), tmp_path)
    text = md.read_text()
    assert "| defended |" in text
    assert "Residual risk" in text
    assert "data:image/png;base64," in html.read_text()
    for chart in ("asr_by_category.png", "security_utility.png", "scenario_heatmap.png"):
        assert (tmp_path / chart).stat().st_size > 1000
    with pytest.raises(ValueError, match="no results"):
        write_report([], tmp_path)
