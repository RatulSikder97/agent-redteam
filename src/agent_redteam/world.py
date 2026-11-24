"""Deterministic, in-process simulated tool world.

A :class:`WorldSpec` is the declarative (YAML-friendly) initial state of a sandbox. A
:class:`World` is the mutable runtime copy that tools act on. Every side effect an attack
could aim for (money moving, data leaving, files disappearing, roles changing) is recorded
explicitly so that success oracles can be pure functions of the final state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

INTERNAL_DOMAIN = "corp.example"


class Email(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    sender: str
    to: str = "alex@corp.example"
    subject: str
    body: str
    unread: bool = True


class Account(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    owner: str
    balance: float = 0.0


class Transaction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account: str
    counterparty: str
    amount: float
    memo: str = ""


class WorldSpec(BaseModel):
    """Declarative initial state of the sandbox."""

    model_config = ConfigDict(extra="forbid")

    user: str = "alex"
    user_email: str = "alex@corp.example"
    internal_domain: str = INTERNAL_DOMAIN
    emails: list[Email] = Field(default_factory=list)
    files: dict[str, str] = Field(default_factory=dict)
    web: dict[str, str] = Field(default_factory=dict)
    accounts: list[Account] = Field(default_factory=list)
    transactions: list[Transaction] = Field(default_factory=list)
    users: dict[str, str] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)

    def merged_over(self, base: WorldSpec) -> WorldSpec:
        """Layer this spec on top of ``base``.

        Mappings are merged key-wise (this spec wins), emails and accounts are merged by id,
        transactions are concatenated. Scalar identity fields come from ``base`` unless this
        spec overrides them explicitly.
        """
        emails = {e.id: e for e in base.emails}
        emails.update({e.id: e for e in self.emails})
        accounts = {a.id: a for a in base.accounts}
        accounts.update({a.id: a for a in self.accounts})
        explicit = self.model_fields_set
        return WorldSpec(
            user=self.user if "user" in explicit else base.user,
            user_email=self.user_email if "user_email" in explicit else base.user_email,
            internal_domain=(
                self.internal_domain if "internal_domain" in explicit else base.internal_domain
            ),
            emails=list(emails.values()),
            files={**base.files, **self.files},
            web={**base.web, **self.web},
            accounts=list(accounts.values()),
            transactions=[*base.transactions, *self.transactions],
            users={**base.users, **self.users},
            secrets={**base.secrets, **self.secrets},
        )


EgressChannel = Literal["fetch", "email", "shell", "response_image", "response_link"]


@dataclass(frozen=True)
class EgressEvent:
    """Data leaving the trust boundary: a network request, external email, or rendered URL."""

    channel: EgressChannel
    destination: str
    payload: str


@dataclass(frozen=True)
class SentEmail:
    to: str
    subject: str
    body: str


@dataclass(frozen=True)
class RoleChange:
    username: str
    old_role: str | None
    new_role: str


@dataclass
class World:
    """Mutable runtime state. Build with :meth:`from_spec`; never share between runs."""

    spec: WorldSpec
    emails: dict[str, Email]
    files: dict[str, str]
    web: dict[str, str]
    accounts: dict[str, Account]
    transactions: list[Transaction]
    users: dict[str, str]
    deleted: list[str] = field(default_factory=list)
    sent: list[SentEmail] = field(default_factory=list)
    fetches: list[str] = field(default_factory=list)
    shell_log: list[str] = field(default_factory=list)
    role_changes: list[RoleChange] = field(default_factory=list)
    egress: list[EgressEvent] = field(default_factory=list)

    @classmethod
    def from_spec(cls, spec: WorldSpec) -> World:
        snapshot = spec.model_copy(deep=True)
        return cls(
            spec=snapshot,
            emails={e.id: e.model_copy() for e in snapshot.emails},
            files=dict(snapshot.files),
            web=dict(snapshot.web),
            accounts={a.id: a.model_copy() for a in snapshot.accounts},
            transactions=[t.model_copy() for t in snapshot.transactions],
            users=dict(snapshot.users),
        )

    def is_external_address(self, address: str) -> bool:
        domain = address.rsplit("@", 1)[-1].strip().lower()
        return domain != self.spec.internal_domain.lower()

    def user_accounts(self) -> list[Account]:
        return [a for a in self.accounts.values() if a.owner == self.spec.user]
