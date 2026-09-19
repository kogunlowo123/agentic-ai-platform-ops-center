# ADR 0003: SQLite as the storage engine

- Status: Accepted
- Date: 2026-09-19

## Context

The center needs durable events, an alert lifecycle, evaluation history, a registry and an audit log,
with transactional integrity between registry changes and audit entries. Requiring a database server would
raise the barrier to trying and testing it.

## Decision

Use SQLite through the standard library. Use WAL mode, bind every parameter, create the schema on open and
keep repositories (`EventStore`, `AlertManager`, `EvalRepo`, `Registry`) thin over one `Database`. Registry
changes and their audit rows share a transaction.

## Consequences

- No infrastructure, and in-memory databases make tests fast and isolated.
- One writer at a time and no network access, so it suits a scheduled job or a single operator, not a
  shared multi-writer service.
- The repository boundaries keep a future PostgreSQL or columnar backend a contained change.
- Connections must be closed. `OpsService` is a context manager, the CLI closes it, and the test suite
  tracks and closes every connection.
