"""Markdown + self-contained HTML reports with matplotlib charts."""

from __future__ import annotations

import base64
import html
from collections.abc import Callable, Sequence
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.axes import Axes

from agent_redteam.metrics import Summary, scenario_success, summarize
from agent_redteam.runner import SuiteResult

# Colorblind-safe (Okabe-Ito derived) series colors.
PALETTE = ["#D55E00", "#0072B2", "#009E73", "#CC79A7", "#E69F00", "#56B4E9", "#999999"]
INK = "#222222"
GRID = "#DDDDDD"


def _style(ax: Axes) -> None:
    ax.spines[["top", "right"]].set_visible(False)
    ax.spines[["left", "bottom"]].set_color("#888888")
    ax.tick_params(colors=INK, labelsize=8)
    ax.yaxis.grid(True, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)


def chart_asr_by_category(summaries: Sequence[Summary], path: Path) -> None:
    cats = sorted({c for s in summaries for c in s.by_category})
    width = 0.8 / max(len(summaries), 1)
    fig, ax = plt.subplots(figsize=(10, 4.2), dpi=150)
    for i, s in enumerate(summaries):
        xs = [j + (i - (len(summaries) - 1) / 2) * width for j in range(len(cats))]
        ys = [100 * s.by_category[c].asr.value if c in s.by_category else 0.0 for c in cats]
        ax.bar(xs, ys, width=width * 0.92, label=s.agent, color=PALETTE[i % len(PALETTE)])
    ax.set_xticks(range(len(cats)))
    ax.set_xticklabels([c.replace("_", "\n") for c in cats], fontsize=8)
    ax.set_ylabel("attack success rate (%)", fontsize=9, color=INK)
    ax.set_ylim(0, 105)
    ax.set_title(
        "Attack success rate by category (lower is better)", fontsize=10, color=INK, loc="left"
    )
    _style(ax)
    ax.legend(
        frameon=False,
        fontsize=8,
        ncol=len(summaries),
        loc="upper center",
        bbox_to_anchor=(0.5, -0.2),
    )
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def chart_security_utility(summaries: Sequence[Summary], path: Path) -> None:
    fig, ax = plt.subplots(figsize=(6, 4.2), dpi=150)
    for i, s in enumerate(summaries):
        x = 100 * s.overall.asr.value
        y = 100 * s.overall.utility_under_attack.value
        lo, hi = s.overall.asr.ci
        ax.errorbar(
            x,
            y,
            xerr=[[x - 100 * lo], [100 * hi - x]],
            fmt="o",
            color=PALETTE[i % len(PALETTE)],
            ecolor=PALETTE[i % len(PALETTE)],
            elinewidth=1,
            capsize=3,
            markersize=7,
        )
        ax.annotate(
            s.agent,
            (x, y),
            textcoords="offset points",
            xytext=(6, 8 if i % 2 == 0 else -14),
            fontsize=8,
            color=INK,
        )
    ax.set_xlabel("attack success rate (%) with 95% CI", fontsize=9, color=INK)
    ax.set_ylabel("utility under attack (%)", fontsize=9, color=INK)
    ax.set_xlim(-5, 105)
    lowest = min((100 * s.overall.utility_under_attack.value for s in summaries), default=0.0)
    ax.set_ylim(max(-5.0, lowest - 25), 105)
    ax.set_title("Security vs. utility (best: top-left)", fontsize=10, color=INK, loc="left")
    _style(ax)
    ax.xaxis.grid(True, color=GRID, linewidth=0.6)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def chart_scenario_heatmap(results: Sequence[SuiteResult], path: Path) -> None:
    per_agent = [scenario_success(r) for r in results]
    scenarios = sorted({s for d in per_agent for s in d})
    grid = [[d.get(s, float("nan")) for d in per_agent] for s in scenarios]
    fig, ax = plt.subplots(figsize=(1.2 * len(results) + 3.5, 0.2 * len(scenarios) + 1.2), dpi=150)
    ax.imshow(grid, cmap="Reds", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(results)))
    ax.set_xticklabels([r.meta.agent for r in results], fontsize=8, rotation=30, ha="right")
    ax.set_yticks(range(len(scenarios)))
    ax.set_yticklabels(scenarios, fontsize=6)
    ax.set_title(
        "Per-scenario compromise (dark = attack succeeded)", fontsize=10, color=INK, loc="left"
    )
    for spine in ax.spines.values():
        spine.set_visible(False)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def _headline_table(summaries: Sequence[Summary]) -> list[str]:
    lines = [
        "| agent | defenses | ASR [95% CI] | utility under attack | benign utility "
        "| denied | blocked | flagged |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for s in summaries:
        lines.append(
            f"| {s.agent} | {'+'.join(s.defenses) or 'none'} | {s.overall.asr.fmt()} | "
            f"{s.overall.utility_under_attack.fmt(ci=False)} | "
            f"{s.overall.benign_utility.fmt(ci=False)} | "
            f"{s.denied_calls} | {s.blocked_calls} | {s.flagged_outputs} |"
        )
    return lines


def _category_table(summaries: Sequence[Summary]) -> list[str]:
    cats = sorted({c for s in summaries for c in s.by_category})
    lines = [
        "| category | n | " + " | ".join(s.agent for s in summaries) + " |",
        "|---|---:|" + "---:|" * len(summaries),
    ]
    for c in cats:
        n = max((s.by_category[c].scenarios for s in summaries if c in s.by_category), default=0)
        cells = [
            s.by_category[c].asr.fmt(ci=False) if c in s.by_category else "n/a" for s in summaries
        ]
        lines.append(f"| {c} | {n} | " + " | ".join(cells) + " |")
    return lines


def build_markdown(results: Sequence[SuiteResult], image_prefix: str = "") -> str:
    summaries = [summarize(r) for r in results]
    meta = results[0].meta
    lines = [
        "# agent-redteam benchmark report",
        "",
        f"Scenarios: {meta.scenario_count} | suite fingerprint `{meta.suite_fingerprint}` | "
        f"seed {meta.seed} | repeats {meta.repeats} | harness v{meta.harness_version}",
        "",
        "## Headline",
        "",
        *_headline_table(summaries),
        "",
        "ASR = attacked runs where the attack oracle fired. Utility under attack = attacked runs "
        "where the user's task still completed. Benign utility = the same task with the payload "
        "removed. denied/blocked/flagged count tool calls stopped by the confirmation policy, "
        "stopped by egress DLP, and tool outputs flagged by the injection detector.",
        "",
        "## Attack success rate by category",
        "",
        *_category_table(summaries),
        "",
        f"![ASR by category]({image_prefix}asr_by_category.png)",
        "",
        f"![Security vs utility]({image_prefix}security_utility.png)",
        "",
        "## Residual risk",
        "",
    ]
    for s in summaries:
        if s.defenses:
            listed = ", ".join(f"`{c}`" for c in s.compromised) or "none"
            lines.append(f"- **{s.agent}** still compromised by: {listed}")
    lines += [
        "",
        f"![Per-scenario heatmap]({image_prefix}scenario_heatmap.png)",
        "",
    ]
    for s in summaries:
        if s.errors or s.refusals or s.benign_false_positive.k:
            lines.append(
                f"- {s.agent}: {s.errors} errored runs, {s.refusals} refusals, "
                f"{s.benign_false_positive.k} benign runs where the attack oracle fired"
            )
        if s.usage:
            lines.append(f"- {s.agent} token usage: {s.usage}")
    return "\n".join(lines).rstrip() + "\n"


def _md_to_html(md: str, images: dict[str, str]) -> str:
    """Minimal renderer for the subset of markdown build_markdown emits."""
    out: list[str] = []
    in_table = False
    for line in md.splitlines():
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(set(c) <= set("-:") for c in cells):
                continue
            tag = "th" if not in_table else "td"
            if not in_table:
                out.append("<table>")
                in_table = True
            out.append("<tr>" + "".join(f"<{tag}>{_inline(c)}</{tag}>" for c in cells) + "</tr>")
            continue
        if in_table:
            out.append("</table>")
            in_table = False
        if line.startswith("![") and "](" in line:
            src = line.split("](", 1)[1].rstrip(")")
            alt = line[2 : line.index("]")]
            data = images.get(Path(src).name, src)
            out.append(f'<figure><img alt="{html.escape(alt)}" src="{data}"></figure>')
        elif line.startswith("# "):
            out.append(f"<h1>{_inline(line[2:])}</h1>")
        elif line.startswith("## "):
            out.append(f"<h2>{_inline(line[3:])}</h2>")
        elif line.startswith("- "):
            out.append(f"<p class='item'>{_inline(line[2:])}</p>")
        elif line.strip():
            out.append(f"<p>{_inline(line)}</p>")
    if in_table:
        out.append("</table>")
    return "\n".join(out)


def _inline(text: str) -> str:
    escaped = html.escape(text)
    parts = escaped.split("`")
    escaped = "".join(f"<code>{p}</code>" if i % 2 else p for i, p in enumerate(parts))
    parts = escaped.split("**")
    return "".join(f"<strong>{p}</strong>" if i % 2 else p for i, p in enumerate(parts))


HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agent-redteam report</title>
<style>
:root {{ --ink:#1d1d1f; --muted:#5f6368; --line:#e3e3e3; --bg:#ffffff; }}
body {{ font: 14px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif; color: var(--ink);
       background: var(--bg); max-width: 1040px; margin: 2rem auto; padding: 0 16px; }}
h1 {{ font-size: 1.6rem; }} h2 {{ font-size: 1.15rem; margin-top: 2rem; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13px;
         overflow-x: auto; display: block; }}
th, td {{ border-bottom: 1px solid var(--line); padding: 6px 10px;
          text-align: right; white-space: nowrap; }}
th:first-child, td:first-child {{ text-align: left; }}
code {{ background: #f4f4f4; padding: 1px 4px; border-radius: 3px; }}
img {{ max-width: 100%; }} figure {{ margin: 1rem 0; }} .item {{ margin: .2rem 0; }}
p {{ color: var(--ink); }}
</style></head><body>
{body}
</body></html>
"""


def write_report(results: Sequence[SuiteResult], out_dir: Path) -> tuple[Path, Path]:
    """Write report.md, report.html and the chart PNGs into ``out_dir``."""
    if not results:
        raise ValueError("no results to report")
    out_dir.mkdir(parents=True, exist_ok=True)
    summaries = [summarize(r) for r in results]
    charts: dict[str, Callable[[Path], None]] = {
        "asr_by_category.png": lambda p: chart_asr_by_category(summaries, p),
        "security_utility.png": lambda p: chart_security_utility(summaries, p),
        "scenario_heatmap.png": lambda p: chart_scenario_heatmap(results, p),
    }
    images: dict[str, str] = {}
    for name, draw in charts.items():
        path = out_dir / name
        draw(path)
        images[name] = "data:image/png;base64," + base64.b64encode(path.read_bytes()).decode()
    md = build_markdown(results)
    md_path = out_dir / "report.md"
    md_path.write_text(md, encoding="utf-8")
    html_path = out_dir / "report.html"
    html_path.write_text(HTML_TEMPLATE.format(body=_md_to_html(md, images)), encoding="utf-8")
    return md_path, html_path
