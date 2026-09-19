"""Model and prompt registry with lifecycle rules and an audit trail.

Governance controls implemented here:

* models move ``proposed -> approved -> deprecated`` (or ``blocked``);
* prompt versions move ``draft -> in_review -> approved -> deprecated``;
* the approver must differ from the model's owner or the prompt's author (separation of duties);
* every change is written to an append-only audit log.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from collections.abc import Callable
from datetime import date, datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

from opscenter.db import Database
from opscenter.errors import RegistryError
from opscenter.models import NAME_PATTERN
from opscenter.store import from_epoch, to_epoch

ModelStatus = Literal["proposed", "approved", "deprecated", "blocked"]
PromptStatus = Literal["draft", "in_review", "approved", "deprecated"]

_MODEL_TRANSITIONS: dict[str, set[str]] = {
    "proposed": {"approved", "blocked"},
    "approved": {"deprecated", "blocked"},
    "deprecated": {"blocked"},
    "blocked": {"proposed"},
}
_PROMPT_TRANSITIONS: dict[str, set[str]] = {
    "draft": {"in_review"},
    "in_review": {"draft", "approved"},
    "approved": {"deprecated"},
    "deprecated": set(),
}
_VERSION = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
_NAME = re.compile(NAME_PATTERN)


class ModelEntry(BaseModel):
    """A model that applications may (or may not) use."""

    name: str
    provider: str = ""
    status: ModelStatus = "proposed"
    owner: str = ""
    review_due: date | None = None
    notes: str = ""


class PromptVersion(BaseModel):
    """One version of a prompt template. Only a hash of its content is stored."""

    prompt_id: str
    version: str
    status: PromptStatus = "draft"
    content_hash: str
    author: str
    approved_by: str | None = None
    created_at: datetime


class AuditEntry(BaseModel):
    """One row of the audit log."""

    id: int
    timestamp: datetime
    actor: str
    action: str
    subject: str
    detail: str


def content_hash(content: str) -> str:
    """Stable short hash used to pin a prompt version to its text."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


class Registry:
    """CRUD and lifecycle operations over models and prompt versions."""

    def __init__(self, db: Database, clock: Callable[[], datetime] | None = None) -> None:
        self._db = db
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    # -- audit ---------------------------------------------------------------------------------

    def _audit(self, actor: str, action: str, subject: str, detail: str = "") -> None:
        self._db.conn.execute(
            "INSERT INTO audit_log (ts, actor, action, subject, detail) VALUES (?,?,?,?,?)",
            (to_epoch(self._clock()), actor, action, subject, detail),
        )

    def audit_log(self, limit: int = 100) -> list[AuditEntry]:
        """Most recent audit entries, newest first."""
        rows = self._db.conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [
            AuditEntry(
                id=r["id"],
                timestamp=from_epoch(r["ts"]),
                actor=r["actor"],
                action=r["action"],
                subject=r["subject"],
                detail=r["detail"],
            )
            for r in rows
        ]

    # -- models --------------------------------------------------------------------------------

    def register_model(
        self,
        name: str,
        *,
        actor: str,
        provider: str = "",
        owner: str = "",
        review_due: date | None = None,
        notes: str = "",
        status: ModelStatus = "proposed",
    ) -> ModelEntry:
        """Add a model. New models start as ``proposed`` unless imported with a status."""
        if not _NAME.match(name):
            raise RegistryError(f"invalid model name: {name!r}")
        if self.get_model(name) is not None:
            raise RegistryError(f"model {name} is already registered")
        with self._db.transaction() as conn:
            conn.execute(
                "INSERT INTO models VALUES (?,?,?,?,?,?)",
                (
                    name,
                    provider,
                    status,
                    owner,
                    review_due.isoformat() if review_due else None,
                    notes,
                ),
            )
            self._audit(actor, "model.register", name, f"status={status} owner={owner}")
        return ModelEntry(
            name=name,
            provider=provider,
            status=status,
            owner=owner,
            review_due=review_due,
            notes=notes,
        )

    def get_model(self, name: str) -> ModelEntry | None:
        """The registry entry for ``name`` or ``None``."""
        row = self._db.conn.execute("SELECT * FROM models WHERE name = ?", (name,)).fetchone()
        return self._model(row) if row else None

    @staticmethod
    def _model(row: sqlite3.Row) -> ModelEntry:
        r = row
        return ModelEntry(
            name=r["name"],
            provider=r["provider"],
            status=r["status"],
            owner=r["owner"],
            review_due=date.fromisoformat(r["review_due"]) if r["review_due"] else None,
            notes=r["notes"],
        )

    def models(self) -> list[ModelEntry]:
        """All registered models, by name."""
        rows = self._db.conn.execute("SELECT * FROM models ORDER BY name").fetchall()
        return [self._model(r) for r in rows]

    def set_model_status(self, name: str, status: ModelStatus, *, actor: str) -> ModelEntry:
        """Move a model to ``status`` if the transition is allowed."""
        entry = self.get_model(name)
        if entry is None:
            raise RegistryError(f"model {name} is not registered")
        if status not in _MODEL_TRANSITIONS[entry.status]:
            raise RegistryError(f"cannot move model {name} from {entry.status} to {status}")
        if status == "approved" and entry.owner and actor == entry.owner:
            raise RegistryError("a model cannot be approved by its owner")
        with self._db.transaction() as conn:
            conn.execute("UPDATE models SET status = ? WHERE name = ?", (status, name))
            self._audit(actor, "model.status", name, f"{entry.status} -> {status}")
        return entry.model_copy(update={"status": status})

    # -- prompts -------------------------------------------------------------------------------

    def register_prompt(
        self,
        prompt_id: str,
        version: str,
        *,
        content: str,
        author: str,
        status: PromptStatus = "draft",
    ) -> PromptVersion:
        """Add a prompt version, storing only the hash of its content."""
        if not _NAME.match(prompt_id) or not _VERSION.match(version):
            raise RegistryError("invalid prompt id or version")
        if self.get_prompt(prompt_id, version) is not None:
            raise RegistryError(f"prompt {prompt_id}@{version} already exists")
        now = self._clock()
        digest = content_hash(content)
        with self._db.transaction() as conn:
            conn.execute(
                "INSERT INTO prompt_versions VALUES (?,?,?,?,?,?,?)",
                (prompt_id, version, status, digest, author, None, to_epoch(now)),
            )
            self._audit(author, "prompt.register", f"{prompt_id}@{version}", f"hash={digest}")
        return PromptVersion(
            prompt_id=prompt_id,
            version=version,
            status=status,
            content_hash=digest,
            author=author,
            created_at=now,
        )

    @staticmethod
    def _prompt(row: sqlite3.Row) -> PromptVersion:
        r = row
        return PromptVersion(
            prompt_id=r["prompt_id"],
            version=r["version"],
            status=r["status"],
            content_hash=r["content_hash"],
            author=r["author"],
            approved_by=r["approved_by"],
            created_at=from_epoch(r["created_at"]),
        )

    def get_prompt(self, prompt_id: str, version: str) -> PromptVersion | None:
        """The prompt version or ``None``."""
        row = self._db.conn.execute(
            "SELECT * FROM prompt_versions WHERE prompt_id = ? AND version = ?",
            (prompt_id, version),
        ).fetchone()
        return self._prompt(row) if row else None

    def prompts(self) -> list[PromptVersion]:
        """All prompt versions."""
        rows = self._db.conn.execute(
            "SELECT * FROM prompt_versions ORDER BY prompt_id, version"
        ).fetchall()
        return [self._prompt(r) for r in rows]

    def transition_prompt(
        self, prompt_id: str, version: str, status: PromptStatus, *, actor: str
    ) -> PromptVersion:
        """Move a prompt version through review. Approval requires someone other than the author."""
        entry = self.get_prompt(prompt_id, version)
        if entry is None:
            raise RegistryError(f"prompt {prompt_id}@{version} does not exist")
        if status not in _PROMPT_TRANSITIONS[entry.status]:
            raise RegistryError(
                f"cannot move prompt {prompt_id}@{version} from {entry.status} to {status}"
            )
        if status == "approved" and actor == entry.author:
            raise RegistryError("a prompt cannot be approved by its author")
        approver = actor if status == "approved" else entry.approved_by
        with self._db.transaction() as conn:
            conn.execute(
                "UPDATE prompt_versions SET status = ?, approved_by = ? WHERE prompt_id = ? AND version = ?",
                (status, approver, prompt_id, version),
            )
            self._audit(
                actor, "prompt.status", f"{prompt_id}@{version}", f"{entry.status} -> {status}"
            )
        return entry.model_copy(update={"status": status, "approved_by": approver})

    def verify_prompt(self, prompt_id: str, version: str, content: str) -> bool:
        """True if ``content`` matches the registered hash for this version."""
        entry = self.get_prompt(prompt_id, version)
        return entry is not None and entry.content_hash == content_hash(content)


class ImportedModel(BaseModel):
    """A model entry in an import file."""

    name: str
    provider: str = ""
    status: ModelStatus = "approved"
    owner: str = ""
    review_due: date | None = None


class ImportedPrompt(BaseModel):
    """A prompt entry in an import file."""

    prompt_id: str
    version: str
    status: PromptStatus = "approved"
    author: str = "import"
    content: str = Field(default="", max_length=200_000)


def import_entries(
    registry: Registry, models: list[ImportedModel], prompts: list[ImportedPrompt]
) -> tuple[int, int]:
    """Load entries with explicit statuses (bootstrap or migration). Existing entries are skipped.

    Imports are recorded in the audit log with the actor ``import``. Returns the number of models
    and prompts added.
    """
    added_models = added_prompts = 0
    for m in models:
        if registry.get_model(m.name) is None:
            registry.register_model(
                m.name,
                actor="import",
                provider=m.provider,
                owner=m.owner,
                review_due=m.review_due,
                status=m.status,
            )
            added_models += 1
    for p in prompts:
        if registry.get_prompt(p.prompt_id, p.version) is None:
            registry.register_prompt(
                p.prompt_id, p.version, content=p.content, author=p.author, status=p.status
            )
            added_prompts += 1
    return added_models, added_prompts
