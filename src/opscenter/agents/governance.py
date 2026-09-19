"""Governance agent: production usage of unapproved, deprecated or blocked models and prompts."""

from __future__ import annotations

from collections import Counter
from typing import Any

from opscenter.agents.base import AnalysisContext, make_alert
from opscenter.models import AgentResult, Alert, Severity

_MODEL_SEVERITY = {
    "proposed": Severity.HIGH,
    "approved": None,
    "deprecated": Severity.MEDIUM,
    "blocked": Severity.CRITICAL,
}
_PROMPT_SEVERITY = {
    "draft": Severity.HIGH,
    "in_review": Severity.HIGH,
    "approved": None,
    "deprecated": Severity.MEDIUM,
}


class GovernanceAgent:
    """Checks production traffic against the model and prompt registry."""

    name = "governance"

    def analyze(self, ctx: AnalysisContext) -> AgentResult:
        alerts: list[Alert] = []
        prod = [e for e in ctx.events if e.environment == "prod"]
        model_calls = Counter((e.app, e.model) for e in prod)
        prompt_calls = Counter((e.app, e.prompt_id, e.prompt_version) for e in prod if e.prompt_id)
        rows: dict[str, Any] = {"models": [], "prompts": []}

        for (app, model), calls in sorted(model_calls.items()):
            entry = ctx.registry.get_model(model)
            status = entry.status if entry else "unregistered"
            rows["models"].append({"app": app, "model": model, "status": status, "calls": calls})
            severity = Severity.HIGH if entry is None else _MODEL_SEVERITY[entry.status]
            if severity is None:
                continue
            alerts.append(
                make_alert(
                    self.name,
                    severity,
                    f"Production traffic on {status} model {model}",
                    f"{app} made {calls} production calls to {model}, which is {status}.",
                    key=f"model-{model}",
                    app=app,
                    evidence={"model": model, "status": status, "calls": calls},
                    recommendation="Register and approve the model, or move traffic to an approved one."
                    if entry is None or entry.status == "proposed"
                    else "Move traffic to an approved model.",
                )
            )

        for (app, prompt_id, version), calls in sorted(
            prompt_calls.items(), key=lambda kv: (kv[0][0], str(kv[0][1]), str(kv[0][2]))
        ):
            assert prompt_id is not None
            entry_p = ctx.registry.get_prompt(prompt_id, version or "")
            prompt_status = entry_p.status if entry_p else "unregistered"
            rows["prompts"].append(
                {
                    "app": app,
                    "prompt": f"{prompt_id}@{version}",
                    "status": prompt_status,
                    "calls": calls,
                }
            )
            prompt_severity = (
                Severity.MEDIUM if entry_p is None else _PROMPT_SEVERITY[entry_p.status]
            )
            if prompt_severity is None:
                continue
            alerts.append(
                make_alert(
                    self.name,
                    prompt_severity,
                    f"Production uses {prompt_status} prompt {prompt_id}@{version}",
                    f"{app} made {calls} production calls with prompt {prompt_id}@{version}, which is {prompt_status}.",
                    key=f"prompt-{prompt_id}-{version}",
                    app=app,
                    evidence={
                        "prompt": f"{prompt_id}@{version}",
                        "status": prompt_status,
                        "calls": calls,
                    },
                    recommendation="Complete review and approval before serving production traffic.",
                )
            )

        for entry_m in ctx.registry.models():
            if entry_m.review_due and entry_m.review_due < ctx.now.date():
                alerts.append(
                    make_alert(
                        self.name,
                        Severity.LOW,
                        f"Model review overdue: {entry_m.name}",
                        f"The scheduled review of {entry_m.name} was due {entry_m.review_due.isoformat()}.",
                        key=f"review-{entry_m.name}",
                        evidence={"owner": entry_m.owner, "due": entry_m.review_due.isoformat()},
                        recommendation="Re-run the security and quality review and update the due date.",
                    )
                )
        return AgentResult(name=self.name, alerts=alerts, metrics=rows)
