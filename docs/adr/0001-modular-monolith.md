# ADR-0001: Adopt a modular monolith with ports and adapters

- **Status:** Accepted
- **Date:** 2026-11-09

## Context

The project must run locally on macOS, on Linux, and eventually as an online service.
It requires independent knowledge, agent, validation, and execution subsystems.
Microservices would increase operational complexity before domain boundaries are validated.

## Decision

Build a modular monolith with strict dependencies and replaceable adapters. Maintain an
independent React UI and a versioned FastAPI contract. Use architecture tests to enforce
boundary direction. Split deployable services only if measured requirements demand it.

## Consequences

Local development is simple and integration tests remain deterministic. Future extraction
of asynchronous workers or a separate execution service remains possible, but is not automatic.
