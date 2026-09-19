# ADR 0002: Deterministic specialist agents with a failure-isolating supervisor

- Status: Accepted
- Date: 2026-09-19

## Context

Operations tooling is judged on trust. An alert that cannot be explained or reproduced is ignored, and a
monitor that fails silently is worse than none. LLM-driven analysis agents are flexible but
non-deterministic, costly per run and would send operational data to a model provider.

## Decision

Implement each specialist as a rule-based analyser with a common `analyze(ctx)` contract, and coordinate
them with a supervisor that:

- catches an agent's exception, records it and raises a high-severity alert,
- keeps that agent's existing alerts open instead of resolving them,
- deduplicates by fingerprint and keeps the highest severity,
- delivers only new or reopened urgent alerts.

## Consequences

- Every alert carries the numbers behind it, and identical input produces identical output.
- A failure in one analysis (for example malformed data breaking the drift statistics) is visible and
  does not take down the report.
- The agents cannot discover unanticipated failure modes. Model-assisted triage can be added later as a
  separate layer that reads alerts, without changing detection.
