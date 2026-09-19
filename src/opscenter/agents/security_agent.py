"""Security agent: PII and credential leakage, injection attempts and repeat offenders."""

from __future__ import annotations

from collections import Counter
from typing import Any

from opscenter.agents.base import AnalysisContext, by_app, make_alert
from opscenter.models import AgentResult, Alert, Severity


class SecurityAgent:
    """Raises alerts from the security signals derived at ingestion."""

    name = "security"

    def analyze(self, ctx: AnalysisContext) -> AgentResult:
        t = ctx.thresholds
        alerts: list[Alert] = []
        rows: dict[str, Any] = {}

        for app, events in by_app(ctx.events).items():
            n = len(events)
            pii_out = sum(1 for e in events if e.signals.pii_out > 0)
            pii_in = sum(1 for e in events if e.signals.pii_in > 0)
            secrets_out = sum(1 for e in events if e.signals.secrets_out > 0)
            injected = [e for e in events if e.signals.injection]
            blocked = sum(1 for e in events if e.status == "blocked")
            rows[app] = {
                "requests": n,
                "pii_in": pii_in,
                "pii_out": pii_out,
                "secrets_out": secrets_out,
                "injection_attempts": len(injected),
                "blocked": blocked,
            }

            if secrets_out:
                alerts.append(
                    make_alert(
                        self.name,
                        Severity.CRITICAL,
                        "Credential-shaped data in model output",
                        f"{secrets_out} {app} responses contain what looks like a credential.",
                        key="secrets-out",
                        app=app,
                        evidence={"events": secrets_out},
                        recommendation="Rotate any exposed credential, find where the model saw it, and add "
                        "output filtering.",
                    )
                )
            if pii_out:
                rate = pii_out / n
                alerts.append(
                    make_alert(
                        self.name,
                        Severity.HIGH if rate >= 0.01 else Severity.MEDIUM,
                        "PII in model output",
                        f"{pii_out} of {n} {app} responses ({rate:.1%}) contain personal data.",
                        key="pii-out",
                        app=app,
                        evidence={"events": pii_out, "rate": round(rate, 4)},
                        recommendation="Add output redaction and check whether retrieval or the prompt exposes "
                        "personal data unnecessarily.",
                    )
                )
            if n >= t.min_samples and injected:
                rate = len(injected) / n
                if rate >= t.injection_rate_medium:
                    severity = Severity.HIGH if rate >= t.injection_rate_high else Severity.MEDIUM
                    alerts.append(
                        make_alert(
                            self.name,
                            severity,
                            "Elevated prompt-injection attempts",
                            f"{len(injected)} of {n} {app} requests ({rate:.1%}) match injection patterns.",
                            key="injection-rate",
                            app=app,
                            evidence={"attempts": len(injected), "rate": round(rate, 4)},
                            recommendation="Confirm input filtering and least-privilege tool access are in place "
                            "and review the repeat offenders.",
                        )
                    )
            offenders = Counter(e.user_hash for e in injected if e.user_hash)
            heavy = sorted(h for h, c in offenders.items() if c >= t.repeat_offender)
            if heavy:
                alerts.append(
                    make_alert(
                        self.name,
                        Severity.MEDIUM,
                        "Repeat injection attempts from the same users",
                        f"{len(heavy)} user hashes each made at least {t.repeat_offender} injection attempts.",
                        key="repeat-offenders",
                        app=app,
                        evidence={
                            "user_hashes": heavy[:10],
                            "max_attempts": max(offenders[h] for h in heavy),
                        },
                        recommendation="Rate-limit or block these users after review.",
                    )
                )
        return AgentResult(name=self.name, alerts=alerts, metrics={"apps": rows})
