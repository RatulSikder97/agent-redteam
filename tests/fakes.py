"""Offline stand-ins for the Anthropic client (no network, no credentials)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, cast

import anthropic
from anthropic.types import Message


def message(
    content: Sequence[dict[str, Any]], stop_reason: str = "end_turn", **extra: Any
) -> Message:
    return Message.model_validate(
        {
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "model": "claude-test",
            "content": list(content),
            "stop_reason": stop_reason,
            "usage": {"input_tokens": 10, "output_tokens": 5},
            **extra,
        }
    )


def text(t: str) -> dict[str, Any]:
    return {"type": "text", "text": t}


def tool_use(name: str, args: dict[str, Any], id_: str = "tu_1") -> dict[str, Any]:
    return {"type": "tool_use", "id": id_, "name": name, "input": args}


class _Messages:
    def __init__(self, script: list[Message | Exception]) -> None:
        self.script = script
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Message:
        if "messages" in kwargs:
            kwargs = {
                **kwargs,
                "messages": list(kwargs["messages"]),
            }  # snapshot: the agent mutates its list
        self.calls.append(kwargs)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class FakeClient:
    def __init__(self, script: list[Message | Exception]) -> None:
        self.messages = _Messages(script)

    def as_client(self) -> anthropic.Anthropic:
        return cast(anthropic.Anthropic, self)
