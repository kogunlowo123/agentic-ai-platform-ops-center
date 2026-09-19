"""Command-line interface ``opsctl``.

Exit codes: 0 success, 1 open alerts at or above ``--fail-on`` (or a failing evaluation), 2 for
usage or runtime errors.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import date, datetime, timezone
from pathlib import Path

import yaml
from pydantic import ValidationError

from opscenter.config import Settings
from opscenter.container import build_llm_client, build_service
from opscenter.errors import OpscenterError
from opscenter.evals import load_suite
from opscenter.logging_setup import configure_logging
from opscenter.models import Severity
from opscenter.registry import ImportedModel, ImportedPrompt, import_entries
from opscenter.reporting import FORMATS, write_reports
from opscenter.security import redact
from opscenter.service import OpsService, parse_duration
from opscenter.simulate import simulate

_MODEL_STATUSES = ["proposed", "approved", "deprecated", "blocked"]
_PROMPT_STATUSES = ["draft", "in_review", "approved", "deprecated"]


def _parse_time(text: str) -> datetime:
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OpscenterError(f"invalid timestamp {text!r}; use ISO 8601") from exc
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="opsctl", description="AI platform operations center")
    parser.add_argument("--db", type=Path, help="database path (default: OPSCENTER_DB_PATH)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create the database")

    ingest = sub.add_parser("ingest", help="ingest JSON Lines telemetry")
    ingest.add_argument("file", type=Path)

    sim = sub.add_parser(
        "simulate", help="write synthetic telemetry with an incident on the last day"
    )
    sim.add_argument("--out", type=Path, required=True)
    sim.add_argument("--days", type=int, default=7)
    sim.add_argument("--seed", type=int, default=7)
    sim.add_argument("--per-day", type=int, default=400)
    sim.add_argument("--no-incident", action="store_true")
    sim.add_argument("--end", help="ISO timestamp the data ends at (default: now)")

    report = sub.add_parser("report", help="analyse a window and produce the operations report")
    report.add_argument("--window", default="24h")
    report.add_argument("--baseline", default="6d")
    report.add_argument("--now", help="ISO timestamp treated as the end of the window")
    report.add_argument(
        "--format", default="md,json", help=f"comma list from: {', '.join(FORMATS)}"
    )
    report.add_argument("--out", type=Path, default=Path("ops-report"))
    report.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity if s is not Severity.INFO],
        help="exit 1 when an open alert at or above this severity exists",
    )

    evals = sub.add_parser("eval", help="evaluation suites").add_subparsers(
        dest="eval_command", required=True
    )
    run = evals.add_parser("run", help="run a suite against the configured model")
    run.add_argument("suite", type=Path)
    run.add_argument("--target", help="label for this target (default: the configured model name)")
    history = evals.add_parser("history", help="show stored runs of a suite")
    history.add_argument("name")

    registry = sub.add_parser("registry", help="model and prompt registry").add_subparsers(
        dest="registry_command", required=True
    )
    registry.add_parser("list")
    registry.add_parser("audit")
    add_model = registry.add_parser("add-model")
    add_model.add_argument("name")
    add_model.add_argument("--actor", required=True)
    add_model.add_argument("--owner", default="")
    add_model.add_argument("--provider", default="")
    add_model.add_argument("--review-due", type=date.fromisoformat)
    set_model = registry.add_parser("set-model")
    set_model.add_argument("name")
    set_model.add_argument("status", choices=_MODEL_STATUSES)
    set_model.add_argument("--actor", required=True)
    add_prompt = registry.add_parser("add-prompt")
    add_prompt.add_argument("prompt_id")
    add_prompt.add_argument("version")
    add_prompt.add_argument("--file", type=Path, required=True)
    add_prompt.add_argument("--author", required=True)
    set_prompt = registry.add_parser("set-prompt")
    set_prompt.add_argument("prompt_id")
    set_prompt.add_argument("version")
    set_prompt.add_argument("status", choices=_PROMPT_STATUSES)
    set_prompt.add_argument("--actor", required=True)
    imp = registry.add_parser("import", help="bootstrap the registry from a YAML file")
    imp.add_argument("file", type=Path)

    alerts = sub.add_parser("alerts", help="alert lifecycle").add_subparsers(
        dest="alerts_command", required=True
    )
    listing = alerts.add_parser("list")
    listing.add_argument("--status", choices=["open", "acked", "resolved"])
    ack = alerts.add_parser("ack")
    ack.add_argument("fingerprint")
    ack.add_argument("--actor", required=True)
    return parser


def _cmd_report(args: argparse.Namespace, service: OpsService) -> int:
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    unknown = sorted(set(formats) - set(FORMATS))
    if unknown or not formats:
        raise OpscenterError(
            f"unknown format(s) {unknown or formats}; choose from {', '.join(FORMATS)}"
        )
    report = service.report(
        window=parse_duration(args.window),
        baseline=parse_duration(args.baseline),
        now=_parse_time(args.now) if args.now else None,
    )
    paths = write_reports(report, args.out, formats)
    print(report.summary)
    for path in paths:
        print(f"Wrote {path}")
    if args.fail_on:
        threshold = Severity(args.fail_on)
        if any(a.severity.rank >= threshold.rank for a in report.open_alerts()):
            return 1
    return 0


def _cmd_eval(args: argparse.Namespace, service: OpsService, settings: Settings) -> int:
    if args.eval_command == "history":
        runs = service.evals.history(args.name)
        for r in runs:
            print(
                f"{r.timestamp.isoformat()}  {r.target:<24} pass rate {r.pass_rate:.0%}  {'PASS' if r.passed else 'FAIL'}"
            )
        if not runs:
            print("no runs")
        return 0
    suite = load_suite(args.suite)
    client = build_llm_client(settings)
    target = args.target or (
        settings.anthropic_model
        if settings.llm_provider == "anthropic"
        else settings.openai_chat_model
    )
    run = service.run_eval(suite, client, target=target)
    print(
        f"Suite {run.suite} on {run.target}: pass rate {run.pass_rate:.0%} ({'PASS' if run.passed else 'FAIL'})"
    )
    for case in run.cases:
        if not case.passed:
            print(f"  FAIL {case.case_id}: {'; '.join(case.failures)}")
    return 0 if run.passed else 1


def _cmd_registry(args: argparse.Namespace, service: OpsService) -> int:
    reg = service.registry
    cmd = args.registry_command
    if cmd == "list":
        for m in reg.models():
            print(f"model   {m.name:<28} {m.status:<11} owner={m.owner or '-'}")
        for p in reg.prompts():
            print(
                f"prompt  {p.prompt_id}@{p.version:<20} {p.status:<11} author={p.author} approved_by={p.approved_by or '-'}"
            )
    elif cmd == "audit":
        for e in reg.audit_log():
            print(
                f"{e.timestamp.isoformat()}  {e.actor:<12} {e.action:<16} {e.subject}  {e.detail}"
            )
    elif cmd == "add-model":
        reg.register_model(
            args.name,
            actor=args.actor,
            owner=args.owner,
            provider=args.provider,
            review_due=args.review_due,
        )
        print(f"registered model {args.name} as proposed")
    elif cmd == "set-model":
        reg.set_model_status(args.name, args.status, actor=args.actor)
        print(f"model {args.name} is now {args.status}")
    elif cmd == "add-prompt":
        try:
            content = args.file.read_text(encoding="utf-8")
        except OSError as exc:
            raise OpscenterError(f"cannot read {args.file}: {exc.strerror or exc}") from exc
        entry = reg.register_prompt(
            args.prompt_id, args.version, content=content, author=args.author
        )
        print(f"registered {entry.prompt_id}@{entry.version} as draft (hash {entry.content_hash})")
    elif cmd == "set-prompt":
        reg.transition_prompt(args.prompt_id, args.version, args.status, actor=args.actor)
        print(f"{args.prompt_id}@{args.version} is now {args.status}")
    else:
        try:
            data = yaml.safe_load(args.file.read_text(encoding="utf-8")) or {}
            models = [ImportedModel.model_validate(m) for m in data.get("models", [])]
            prompts = [ImportedPrompt.model_validate(p) for p in data.get("prompts", [])]
        except (OSError, yaml.YAMLError, ValidationError, AttributeError) as exc:
            raise OpscenterError(f"cannot import {args.file}: {redact(str(exc))[:300]}") from exc
        added_models, added_prompts = import_entries(reg, models, prompts)
        print(f"imported {added_models} models and {added_prompts} prompt versions")
    return 0


def _cmd_alerts(args: argparse.Namespace, service: OpsService) -> int:
    if args.alerts_command == "ack":
        record = service.alerts.acknowledge(args.fingerprint, args.actor)
        print(f"acknowledged {record.fingerprint}: {record.title}")
        return 0
    records = service.alerts.list(args.status)
    for a in records:
        scope = a.app or "-"
        print(f"{a.fingerprint}  {a.status:<8} {a.severity.value:<8} {scope:<16} {a.title}")
    if not records:
        print("no alerts")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    args = _parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    try:
        settings = Settings()
        if args.db:
            settings = settings.model_copy(update={"db_path": args.db})
        configure_logging(settings.log_level, json_output=settings.log_json)

        if args.command == "simulate":
            end = _parse_time(args.end) if args.end else datetime.now(timezone.utc)
            events = simulate(
                end=end,
                days=args.days,
                seed=args.seed,
                per_day=args.per_day,
                incident=not args.no_incident,
            )
            args.out.parent.mkdir(parents=True, exist_ok=True)
            with args.out.open("w", encoding="utf-8") as handle:
                for event in events:
                    handle.write(event.model_dump_json(exclude_none=True) + "\n")
            print(f"wrote {len(events)} events to {args.out}")
            return 0

        service = build_service(settings)
        try:
            if args.command == "init":
                print(f"database ready at {settings.db_path}")
                return 0
            if args.command == "ingest":
                result = service.ingest_file(args.file)
                print(result.model_dump_json(indent=2))
                return 0
            if args.command == "report":
                return _cmd_report(args, service)
            if args.command == "eval":
                return _cmd_eval(args, service, settings)
            if args.command == "registry":
                return _cmd_registry(args, service)
            return _cmd_alerts(args, service)
        finally:
            service.close()
    except (OpscenterError, ValidationError) as exc:
        print(f"error: {redact(str(exc))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
