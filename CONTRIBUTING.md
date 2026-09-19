# Contributing

Thanks for helping improve this project. This guide covers the workflow and the quality bar.

## Development setup

```bash
git clone <repository-url>
cd agentic-ai-platform-ops-center
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
```

## Checks

Every change must pass the gates CI enforces:

```bash
make lint        # ruff check + ruff format --check
make typecheck   # mypy --strict
make cov         # pytest with a coverage gate of 80%
```

`make format` applies safe autofixes and formatting.

## Workflow

1. Open an issue for anything larger than a small fix so the design can be discussed first.
2. Branch from `main`: `feature/<short-name>` or `fix/<short-name>`.
3. Keep commits focused, with imperative subjects.
4. Add or update tests. Bug fixes need a regression test that fails without the fix.
5. Update `CHANGELOG.md` under **Unreleased** and any affected documentation.
6. Open a pull request describing the problem, the approach and how you verified it.

## Code standards

- Python 3.10+, fully type-annotated, `mypy --strict` clean.
- Docstrings explain behaviour, not restate names.
- Errors raised deliberately derive from `OpscenterError`.
- Never store or log raw prompts, responses or user ids. If a feature needs new information from text,
  add a derived signal in `signals.py` rather than storing the text.
- Every SQL statement uses bound parameters.
- Close database connections (`OpsService` is a context manager).
- Tests are offline and deterministic: in-memory SQLite, the simulator, `httpx.MockTransport` and
  injected clocks (see `tests/conftest.py`).

## Adding a specialist agent

1. Implement `analyze(ctx) -> AgentResult` in `agents/` with a stable `name`.
2. Build alerts with `make_alert(agent, severity, title, detail, key=..., app=..., evidence=..., recommendation=...)`.
   The key, agent and app form the fingerprint, so keep keys stable across runs.
3. Include the evidence behind the alert and a concrete recommendation.
4. Register it in `container.build_service`.
5. Test firing, not firing, minimum-sample behaviour and severity boundaries.

## Adding a signal

Compute it in `signals.derive_signals`, add a field to `Signals` with a default (stored rows are JSON),
and cover it in `tests/unit/test_stats_and_signals.py`. Update the privacy table in the architecture
document.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not file public issues for vulnerabilities.

## License

By contributing you agree that your contributions are licensed under the MIT License.
