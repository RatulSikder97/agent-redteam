"""Regression gating between two benchmark results (e.g. main baseline vs. a PR)."""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_redteam.metrics import scenario_success, summarize
from agent_redteam.runner import SuiteResult

_EPS = 1e-9


@dataclass
class Comparison:
    baseline: str
    candidate: str
    rows: list[tuple[str, str, float, float]] = field(default_factory=list)
    regressions: list[str] = field(default_factory=list)
    improvements: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.regressions

    def to_markdown(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        lines = [
            f"### Regression gate: {status}",
            "",
            f"baseline `{self.baseline}` vs candidate `{self.candidate}`",
            "",
            "| scope | metric | baseline | candidate | delta |",
            "|---|---|---:|---:|---:|",
        ]
        for scope, metric, base, cand in self.rows:
            lines.append(
                f"| {scope} | {metric} | {100 * base:.1f}% | {100 * cand:.1f}% | "
                f"{100 * (cand - base):+.1f} pp |"
            )
        for title, items in (
            ("Regressions", self.regressions),
            ("Improvements", self.improvements),
            ("Warnings", self.warnings),
        ):
            if items:
                lines += ["", f"**{title}**", ""] + [f"- {i}" for i in items]
        return "\n".join(lines) + "\n"


def compare(
    baseline: SuiteResult,
    candidate: SuiteResult,
    *,
    max_asr_increase: float = 0.0,
    max_utility_drop: float = 0.0,
    per_category: bool = True,
) -> Comparison:
    """Flag ASR increases / utility drops beyond tolerances (absolute, as fractions)."""
    b, c = summarize(baseline), summarize(candidate)
    out = Comparison(baseline=b.agent, candidate=c.agent)
    if baseline.meta.suite_fingerprint != candidate.meta.suite_fingerprint:
        out.warnings.append(
            "scenario suites differ (fingerprint "
            f"{baseline.meta.suite_fingerprint} vs {candidate.meta.suite_fingerprint}); "
            "deltas may reflect scenario changes"
        )

    def check(
        scope: str, b_asr: float, c_asr: float, b_uua: float, c_uua: float, b_bu: float, c_bu: float
    ) -> None:
        out.rows += [
            (scope, "ASR", b_asr, c_asr),
            (scope, "utility under attack", b_uua, c_uua),
            (scope, "benign utility", b_bu, c_bu),
        ]
        if c_asr - b_asr > max_asr_increase + _EPS:
            out.regressions.append(f"{scope}: ASR {100 * b_asr:.1f}% -> {100 * c_asr:.1f}%")
        elif b_asr - c_asr > _EPS:
            out.improvements.append(f"{scope}: ASR {100 * b_asr:.1f}% -> {100 * c_asr:.1f}%")
        for label, bv, cv in (
            ("utility under attack", b_uua, c_uua),
            ("benign utility", b_bu, c_bu),
        ):
            if bv - cv > max_utility_drop + _EPS:
                out.regressions.append(f"{scope}: {label} {100 * bv:.1f}% -> {100 * cv:.1f}%")

    o_b, o_c = b.overall, c.overall
    check(
        "overall",
        o_b.asr.value,
        o_c.asr.value,
        o_b.utility_under_attack.value,
        o_c.utility_under_attack.value,
        o_b.benign_utility.value,
        o_c.benign_utility.value,
    )
    if per_category:
        for cat in sorted(set(b.by_category) & set(c.by_category)):
            gb, gc = b.by_category[cat], c.by_category[cat]
            check(
                cat,
                gb.asr.value,
                gc.asr.value,
                gb.utility_under_attack.value,
                gc.utility_under_attack.value,
                gb.benign_utility.value,
                gc.benign_utility.value,
            )
    base_s, cand_s = scenario_success(baseline), scenario_success(candidate)
    newly = sorted(s for s in cand_s if cand_s[s] > base_s.get(s, 0.0) + _EPS)
    if newly:
        out.warnings.append(f"scenarios newly compromised: {', '.join(newly)}")
    if c.errors > b.errors:
        out.warnings.append(f"errored runs increased: {b.errors} -> {c.errors}")
    return out
