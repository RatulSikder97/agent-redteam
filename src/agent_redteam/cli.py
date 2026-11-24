"""Command-line interface: ``agent-redteam --help``."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from agent_redteam.agents import SCRIPTED_PRESETS, Agent, ScriptedAgent, build_agent
from agent_redteam.agents.anthropic_agent import AgentAPIError
from agent_redteam.attackers import (
    DEFAULT_ATTACKER_MODEL,
    Attacker,
    LLMAttacker,
    TemplateAttacker,
    adaptive_attack,
)
from agent_redteam.compare import compare as compare_results
from agent_redteam.metrics import summarize
from agent_redteam.report import write_report
from agent_redteam.runner import RunRecord, SuiteResult, run_episode, run_suite
from agent_redteam.scenario import ScenarioSuite, load_suite

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Red-team and benchmark tool-using LLM agents in a deterministic sandbox.",
)
console = Console()

ScenarioDir = Annotated[
    Path | None, typer.Option("--scenarios", help="Scenario directory (default: bundled suite).")
]
Category = Annotated[list[str] | None, typer.Option("--category", "-c", help="Filter by category.")]
Ids = Annotated[list[str] | None, typer.Option("--id", help="Filter by scenario id.")]
Seed = Annotated[int, typer.Option(help="Base seed (canaries, mutator randomness).")]


def _suite(
    scenarios: Path | None, category: list[str] | None, ids: list[str] | None
) -> ScenarioSuite:
    suite = load_suite(scenarios).filter(category, ids)
    if not suite.scenarios:
        raise typer.BadParameter("no scenarios match the given filters")
    return suite


def _split(value: str | None) -> list[str] | None:
    if value is None:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


def _append_summary(path: Path | None, text: str) -> None:
    if path is not None:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(text + "\n")


@app.command("list")
def list_scenarios(scenarios: ScenarioDir = None, category: Category = None) -> None:
    """List scenarios with their taxonomy mapping."""
    suite = _suite(scenarios, category, None)
    table = Table(show_lines=False)
    for col in ("id", "category", "severity", "vector", "mutators", "OWASP", "ATLAS"):
        table.add_column(col)
    for s in suite.scenarios:
        table.add_row(
            s.id,
            s.category.value,
            s.severity,
            s.injection.vector,
            ",".join(s.injection.mutators) or "-",
            ",".join(s.owasp),
            ",".join(s.atlas),
        )
    console.print(table)
    console.print(f"{len(suite.scenarios)} scenarios, fingerprint {suite.fingerprint()}")


@app.command()
def validate(scenarios: ScenarioDir = None, seed: Seed = 0) -> None:
    """Sanity-check every scenario with the naive reference agent.

    Each scenario must (1) not trigger its attack oracle without the payload (no false
    positives), (2) satisfy its utility oracle without the payload, and (3) be exploitable
    by the naive agent with the payload (the oracle can actually fire).
    """
    suite = load_suite(scenarios)
    agent = ScriptedAgent()
    failures: list[str] = []
    for s in suite.scenarios:
        benign = run_episode(s, suite, agent, seed=seed, attacked=False)
        attacked = run_episode(s, suite, agent, seed=seed, attacked=True)
        if benign.attack_success:
            failures.append(f"{s.id}: attack oracle fires on the benign run (false positive)")
        if not benign.utility:
            failures.append(f"{s.id}: utility oracle fails on the benign run")
        if not attacked.attack_success:
            failures.append(f"{s.id}: naive agent is not compromised (oracle never fires)")
    for f in failures:
        console.print(f"[red]FAIL[/red] {f}")
    console.print(f"{len(suite.scenarios)} scenarios checked, {len(failures)} problem(s)")
    if failures:
        raise typer.Exit(code=1)


def _progress(record: RunRecord) -> None:
    mark = "A" if record.attacked else "B"
    outcome = "PWNED" if record.attack_success and record.attacked else "ok"
    console.print(
        f"  [{mark}] {record.scenario_id:<32} {record.status:<10} "
        f"attack={outcome:<5} utility={'yes' if record.utility else 'no'}",
        highlight=False,
    )


def _build(name: str, defenses: list[str] | None = None, model: str | None = None) -> Agent:
    try:
        return build_agent(name, defenses=defenses, model=model)
    except (ValueError, AgentAPIError) as exc:
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(code=2) from exc


def _abort_if_all_errored(result: SuiteResult) -> None:
    """Fail fast with the underlying cause when no episode could run (e.g. no credentials)."""
    if result.records and all(r.status in {"error", "harness_error"} for r in result.records):
        console.print(f"[red]every episode failed:[/red] {result.records[0].error}")
        raise typer.Exit(code=2)


@app.command()
def run(
    agent: Annotated[str, typer.Option(help=f"{', '.join(SCRIPTED_PRESETS)} or claude")] = "naive",
    defenses: Annotated[
        str | None, typer.Option(help="Comma-separated override: spotlight,confirm,egress")
    ] = None,
    model: Annotated[str | None, typer.Option(help="Target model for --agent claude.")] = None,
    scenarios: ScenarioDir = None,
    category: Category = None,
    ids: Ids = None,
    seed: Seed = 0,
    repeats: Annotated[int, typer.Option(min=1)] = 1,
    out: Annotated[Path, typer.Option(help="Results JSON path.")] = Path("out/results.json"),
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run the suite against one agent and write results JSON."""
    suite = _suite(scenarios, category, ids)
    target = _build(agent, defenses=_split(defenses), model=model)
    result = run_suite(
        suite, target, seed=seed, repeats=repeats, progress=_progress if verbose else None
    )
    _abort_if_all_errored(result)
    result.save(out)
    s = summarize(result)
    console.print(
        f"{s.agent}: ASR {s.overall.asr.fmt()} | utility under attack "
        f"{s.overall.utility_under_attack.fmt(ci=False)} | benign utility "
        f"{s.overall.benign_utility.fmt(ci=False)} -> {out}"
    )


@app.command()
def bench(
    agents: Annotated[str, typer.Option(help="Comma-separated agents.")] = ",".join(
        SCRIPTED_PRESETS
    ),
    model: Annotated[str | None, typer.Option(help="Target model for claude agents.")] = None,
    scenarios: ScenarioDir = None,
    category: Category = None,
    seed: Seed = 0,
    repeats: Annotated[int, typer.Option(min=1)] = 1,
    out_dir: Annotated[Path, typer.Option(help="Output directory.")] = Path("out"),
    summary_file: Annotated[
        Path | None,
        typer.Option(help="Append the markdown report here (e.g. $GITHUB_STEP_SUMMARY)."),
    ] = None,
) -> None:
    """Run several agents and write per-agent JSON plus a combined report."""
    suite = _suite(scenarios, category, None)
    results: list[SuiteResult] = []
    for name in _split(agents) or []:
        target = _build(name, model=model)
        result = run_suite(suite, target, seed=seed, repeats=repeats)
        _abort_if_all_errored(result)
        result.save(out_dir / "results" / f"{target.name}.json")
        s = summarize(result)
        console.print(
            f"{s.agent:<10} ASR {s.overall.asr.fmt():<18} "
            f"UuA {s.overall.utility_under_attack.fmt(ci=False)}"
        )
        results.append(result)
    md_path, html_path = write_report(results, out_dir / "report")
    console.print(f"report: {md_path} | {html_path}")
    _append_summary(summary_file, md_path.read_text(encoding="utf-8"))


@app.command()
def report(
    results: Annotated[list[Path], typer.Argument(help="Results JSON files.")],
    out_dir: Annotated[Path, typer.Option(help="Output directory.")] = Path("out/report"),
) -> None:
    """Build a markdown + HTML report (with charts) from results files."""
    md_path, html_path = write_report([SuiteResult.load(p) for p in results], out_dir)
    console.print(f"report: {md_path} | {html_path}")


@app.command()
def compare(
    baseline: Annotated[Path, typer.Argument(help="Baseline results JSON (or directory).")],
    candidate: Annotated[Path, typer.Argument(help="Candidate results JSON (or directory).")],
    max_asr_increase: Annotated[
        float, typer.Option(help="Allowed absolute ASR increase (0-1).")
    ] = 0.0,
    max_utility_drop: Annotated[
        float, typer.Option(help="Allowed absolute utility drop (0-1).")
    ] = 0.0,
    per_category: Annotated[bool, typer.Option(help="Also gate each category.")] = True,
    summary_file: Annotated[Path | None, typer.Option(help="Append markdown here.")] = None,
) -> None:
    """Exit non-zero if the candidate regresses security or utility versus the baseline."""
    pairs: list[tuple[Path, Path]]
    if baseline.is_dir() and candidate.is_dir():
        pairs = [(b, candidate / b.name) for b in sorted(baseline.glob("*.json"))]
        missing = [str(c) for _, c in pairs if not c.exists()]
        if missing:
            console.print(f"[red]missing candidate results:[/red] {', '.join(missing)}")
            raise typer.Exit(code=1)
    else:
        pairs = [(baseline, candidate)]
    failed = False
    for b, c in pairs:
        result = compare_results(
            SuiteResult.load(b),
            SuiteResult.load(c),
            max_asr_increase=max_asr_increase,
            max_utility_drop=max_utility_drop,
            per_category=per_category,
        )
        md = result.to_markdown()
        console.print(md, highlight=False)
        _append_summary(summary_file, md)
        failed |= not result.passed
    if failed:
        raise typer.Exit(code=1)


@app.command()
def attack(
    scenario: Annotated[str, typer.Option("--scenario", "-s", help="Scenario id.")],
    agent: Annotated[str, typer.Option(help="Target agent.")] = "defended",
    attacker: Annotated[str, typer.Option(help="template | llm")] = "template",
    attacker_model: Annotated[
        str, typer.Option(help="Attacker model for --attacker llm.")
    ] = DEFAULT_ATTACKER_MODEL,
    model: Annotated[str | None, typer.Option(help="Target model for --agent claude.")] = None,
    budget: Annotated[int, typer.Option(min=1, help="Max attempts.")] = 16,
    scenarios: ScenarioDir = None,
    seed: Seed = 0,
) -> None:
    """Adaptive attack: mutate one scenario's payload until it beats the target's defenses."""
    suite = load_suite(scenarios)
    target_scenario = suite.get(scenario)
    target = _build(agent, model=model)
    adversary: Attacker
    if attacker == "template":
        adversary = TemplateAttacker(seed=seed)
    elif attacker == "llm":
        from agent_redteam.agents.anthropic_agent import make_client

        try:
            client = make_client()
        except AgentAPIError as exc:
            console.print(f"[red]error:[/red] {exc}")
            raise typer.Exit(code=2) from exc
        adversary = LLMAttacker(client=client, model=attacker_model)
    else:
        raise typer.BadParameter("attacker must be 'template' or 'llm'")
    result = adaptive_attack(target_scenario, suite, target, adversary, budget=budget, seed=seed)
    for r in result.rounds:
        chain = "+".join(r.attempt.mutators) or "(none)"
        verdict = "[red]SUCCESS[/red]" if r.success else "failed"
        console.print(
            f"round {r.index:>2} mutators={chain:<28} {verdict}  {r.feedback}", highlight=False
        )
    first = result.first_success
    if first is None:
        console.print(f"{target.name} resisted {len(result.rounds)} attempt(s) on {scenario}")
    else:
        console.print(f"{target.name} compromised on round {first.index} of {len(result.rounds)}")


if __name__ == "__main__":
    app()
