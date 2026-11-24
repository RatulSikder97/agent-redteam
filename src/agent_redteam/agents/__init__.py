"""Agent adapters.

``build_agent`` resolves the CLI's ``--agent`` names:

* scripted presets: ``naive``, ``spotlight``, ``confirm``, ``egress``, ``defended``
* ``claude`` - the Anthropic Messages API agent (needs credentials)

Custom adapters implement :class:`agent_redteam.agents.base.Agent`.
"""

from __future__ import annotations

from collections.abc import Sequence

from agent_redteam.agents.base import Agent, AgentOutput, Episode, PlanStep, ToolExecutor
from agent_redteam.agents.scripted import ScriptedAgent
from agent_redteam.defenses import PRESETS, DefenseConfig

SCRIPTED_PRESETS = tuple(PRESETS)

__all__ = [
    "SCRIPTED_PRESETS",
    "Agent",
    "AgentOutput",
    "Episode",
    "PlanStep",
    "ScriptedAgent",
    "ToolExecutor",
    "build_agent",
]


def build_agent(
    name: str,
    *,
    defenses: Sequence[str] | None = None,
    model: str | None = None,
) -> Agent:
    """Build an agent by name. ``defenses`` overrides the preset's defense set."""
    if name in PRESETS:
        config = (
            DefenseConfig.from_names(defenses)
            if defenses is not None
            else DefenseConfig.preset(name)
        )
        return ScriptedAgent(name=name, defenses=config)
    if name == "claude":
        from agent_redteam.agents.anthropic_agent import (
            DEFAULT_TARGET_MODEL,
            ClaudeAgent,
            make_client,
        )

        config = DefenseConfig.from_names(defenses or [])
        label = "claude" if not config.names() else f"claude+{config.label}"
        return ClaudeAgent(
            client=make_client(),
            model_id=model or DEFAULT_TARGET_MODEL,
            defenses=config,
            name=label,
        )
    raise ValueError(f"unknown agent '{name}' (known: {[*SCRIPTED_PRESETS, 'claude']})")
