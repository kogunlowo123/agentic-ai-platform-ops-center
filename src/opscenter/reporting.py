"""Markdown and JSON rendering of the operations report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opscenter.errors import ReportError
from opscenter.models import AgentResult, OpsReport, Severity

FORMATS = ("md", "json")
_FILES = {"md": "ops-report.md", "json": "ops-report.json"}
_NOTICE = (
    "Findings are computed from the telemetry your applications reported. Thresholds are defaults to "
    "tune per application. Cost figures use the price catalog you maintain. Grounding scores are a "
    "lexical proxy for hallucination risk, and drift statistics need enough samples in both windows to "
    "be meaningful."
)


def _cell(value: Any) -> str:
    return (
        str(value).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")
    )


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    if not rows:
        return ["No data.", ""]
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return [*lines, ""]


def _result(report: OpsReport, name: str) -> AgentResult | None:
    return next((r for r in report.results if r.name == name), None)


def render_markdown(report: OpsReport) -> str:
    """Render ``report`` as a Markdown document."""
    out: list[str] = [
        "# AI platform operations report",
        "",
        f"Generated {report.generated_at.isoformat()} by opscenter {report.tool_version}. "
        f"Window {report.window_start.isoformat()} to {report.window_end.isoformat()}; baseline "
        f"{report.baseline_start.isoformat()} to {report.baseline_end.isoformat()}.",
        "",
        "## Summary",
        "",
        _cell(report.summary),
        "",
        "## Application health",
        "",
        *_table(
            ["Application", "Health", "Events", "Critical", "High", "Medium", "Low"],
            [
                [
                    h.app,
                    f"{h.score}/100",
                    h.events,
                    *(h.open_alerts.get(s, 0) for s in ("critical", "high", "medium", "low")),
                ]
                for h in report.health
            ],
        ),
        "## Alerts",
        "",
    ]
    active = [a for a in report.alerts if a.status != "resolved"]
    if not active:
        out += ["No active alerts.", ""]
    for severity in Severity:
        group = [a for a in active if a.severity is severity]
        if not group:
            continue
        out += [f"### {severity.value.capitalize()}", ""]
        for a in group:
            scope = f" ({a.app})" if a.app else ""
            state = "" if a.status == "open" else f" [{a.status}]"
            out += [f"#### {_cell(a.title)}{scope}{state}", "", _cell(a.detail), ""]
            if a.evidence:
                out += [
                    "Evidence: `"
                    + _cell(json.dumps(a.evidence, sort_keys=True, default=str))
                    + "`",
                    "",
                ]
            if a.recommendation:
                out += [f"Recommendation: {_cell(a.recommendation)}", ""]
            out += [
                f"Id `{a.fingerprint}`, seen {a.occurrences} time(s), first {a.first_seen.date().isoformat()}.",
                "",
            ]

    if obs := _result(report, "observability"):
        out += ["## Observability", ""]
        out += _table(
            ["Application", "Requests", "Error rate", "p50 ms", "p95 ms", "p99 ms"],
            [
                [k, v["requests"], f"{v['error_rate']:.2%}", v["p50_ms"], v["p95_ms"], v["p99_ms"]]
                for k, v in obs.metrics.get("apps", {}).items()
            ],
        )
    if cost := _result(report, "cost"):
        out += [
            "## Cost",
            "",
            f"Total spend in window: ${cost.metrics.get('total_usd', 0):,.2f}",
            "",
        ]
        out += _table(
            ["Application", "Spend", "Per day", "Calls"],
            [
                [k, f"${v['cost_usd']:,.2f}", f"${v['daily_usd']:,.2f}", v["calls"]]
                for k, v in cost.metrics.get("apps", {}).items()
            ],
        )
        out += _table(
            ["Model", "Calls", "Spend", "Input tokens", "Output tokens"],
            [
                [k, v["calls"], f"${v['cost_usd']:,.2f}", v["input_tokens"], v["output_tokens"]]
                for k, v in cost.metrics.get("models", {}).items()
            ],
        )
    if drift := _result(report, "drift"):
        out += ["## Drift (top features by PSI)", ""]
        out += _table(
            ["Application", "Feature", "PSI", "KS D", "KS p"],
            [
                [
                    r["app"],
                    r["feature"],
                    r["psi"],
                    r["ks_d"] if r["ks_d"] is not None else "-",
                    r["ks_p"] if r["ks_p"] is not None else "-",
                ]
                for r in drift.metrics.get("features", [])[:12]
            ],
        )
    if gov := _result(report, "governance"):
        out += ["## Governance", ""]
        out += _table(
            ["Application", "Model", "Registry status", "Calls"],
            [
                [r["app"], r["model"], r["status"], r["calls"]]
                for r in gov.metrics.get("models", [])
            ],
        )
        out += _table(
            ["Application", "Prompt", "Registry status", "Calls"],
            [
                [r["app"], r["prompt"], r["status"], r["calls"]]
                for r in gov.metrics.get("prompts", [])
            ],
        )
    if quality := _result(report, "quality"):
        out += ["## Quality", ""]
        out += _table(
            ["Application", "Samples", "Mean grounding", "Share below 0.5"],
            [
                [k, v["samples"], v["mean"], f"{v['share_below_0_5']:.1%}"]
                for k, v in quality.metrics.get("grounding", {}).items()
            ],
        )
        out += _table(
            ["Suite", "Target", "Pass rate", "Change"],
            [
                [r["suite"], r["target"], f"{r['pass_rate']:.0%}", r.get("delta", "-")]
                for r in quality.metrics.get("evals", [])
            ],
        )
    failed = [r for r in report.results if r.error]
    if failed:
        out += ["## Agent errors", ""] + [f"- {r.name}: {_cell(r.error)}" for r in failed] + [""]
    out += ["## Notice", "", _NOTICE, ""]
    return "\n".join(out)


def render(report: OpsReport, fmt: str) -> str:
    """Render ``report`` as ``md`` or ``json``."""
    if fmt == "md":
        return render_markdown(report)
    if fmt == "json":
        return report.model_dump_json(indent=2)
    raise ReportError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")


def write_reports(report: OpsReport, out_dir: Path, formats: list[str]) -> list[Path]:
    """Write each requested format into ``out_dir`` under fixed file names."""
    rendered = {fmt: render(report, fmt) for fmt in formats}
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        paths = []
        for fmt, content in rendered.items():
            path = out_dir / _FILES[fmt]
            path.write_text(content, encoding="utf-8")
            paths.append(path)
    except OSError as exc:
        raise ReportError(f"cannot write reports to {out_dir}: {exc}") from exc
    return paths
