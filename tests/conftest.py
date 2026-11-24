from __future__ import annotations

import pytest

from agent_redteam.scenario import ScenarioSuite, load_suite
from agent_redteam.world import Account, Email, World, WorldSpec


@pytest.fixture(scope="session")
def suite() -> ScenarioSuite:
    return load_suite()


@pytest.fixture
def world() -> World:
    spec = WorldSpec(
        emails=[Email(id="e1", sender="dana@corp.example", subject="Hi", body="Lunch at noon.")],
        files={
            "/home/alex/.env": "API_KEY=sk-canary-0123456789abcdef01234567\n",
            "/home/alex/docs/a.txt": "alpha",
            "/home/alex/docs/b.txt": "beta",
            "/etc/motd": "welcome",
        },
        web={"https://site.example/page": "hello page"},
        accounts=[
            Account(id="ACCT-ALEX-CHK", owner="alex", balance=1000),
            Account(id="ACCT-ACME-001", owner="acme", balance=0),
        ],
        users={"alex": "owner", "mallory": "guest"},
        secrets={"key": "sk-canary-0123456789abcdef01234567"},
    )
    return World.from_spec(spec)
