# systemd-security-gate — Agent Notes

This file is for maintainers and coding agents. It describes what this project is, why it exists, the hard scope boundaries, and the engineering standards to keep it tight and reliable.

## What this is (one line)

A Go **CLI** + GitHub **container action** that makes systemd `.service` hardening an enforceable CI contract by running `systemd-analyze security` in **offline** mode and failing when a configured exposure **threshold** is exceeded (with optional JSON/SARIF reports).

## Why it exists

Hardening regressions in systemd service units are often subtle: a PR weakens sandboxing directives and everything still “works”. This project turns `systemd-analyze security` into a repo-first CI gate with good developer UX (PR summary + allowlist + SARIF).

## Scope (v1 contract)

- **Unit types:** `.service` only.
- **Source of truth:** `systemd-analyze security` output (we do not implement our own scoring).
- **Mode of analysis:** offline (`--offline=yes`) against a temporary `--root` layout built from repo files.
- **Outputs:** Markdown summary (stdout + `$GITHUB_STEP_SUMMARY` when set), optional JSON report, optional SARIF report.
- **Modes:**
  - `enforce` (default): threshold failures are build failures unless allowlisted.
  - `report`: threshold failures do **not** fail, but **analysis errors still fail**.

## Non-goals (do not expand into these)

- No generic systemd unit linter (syntax/style/formatting rules are out of scope).
- No runtime verification of running services; no daemon/agent.
- No `.socket/.timer` → `.service` mapping in v1.
- No attempt to “fix” systemd output; we only parse and present it.

## Interfaces (must stay stable)

### CLI

Primary command: `ssg scan`.

Key behavior contracts:

- Accepts one or more glob patterns (`--paths`, newline-separated supported) and optional `--exclude`.
- Produces deterministic output (stable ordering and stable paths).
- Exit code semantics:
  - `enforce`: non-zero if any non-allowlisted unit exceeds threshold, or any analysis error occurs.
  - `report`: zero if only threshold is exceeded; non-zero if any analysis error occurs.

### GitHub Action

- Container action lives at the repo root: `action.yml` + `Dockerfile`.
- Inputs in `action.yml` must remain consistent with CLI flags/behavior.
- The container should keep a **pinned** Linux distro + systemd package for reproducibility.

## Determinism & output rules

- Always sort discovered units and report entries deterministically.
- Reports must use **repo-relative paths** (no `/tmp/...` leaks).
- Do not depend on locale for parsing: subprocess env must include `LC_ALL=C` and `LANG=C`.
- Keep Markdown/SARIF/JSON outputs stable; if you change output shape, update/add tests.

## systemd JSON compatibility (important)

`systemd-analyze security --json=short` output can vary by version/distro. In particular, some fields (notably `exposure`) may be `number`, `string`, or `null`.

- Parsers must be **tolerant** (accept numeric strings and nulls).
- Never assume field types are perfectly stable across systemd versions.

## Allowlist semantics (v1)

- Units may be referenced by repo-relative path (preferred) or unit basename.
- Test identifiers must match `json_field` (preferred) or `name` from systemd JSON output.
- A threshold-failing unit is treated as **allowed** if:
  - the unit is listed in `allowUnits`, OR
  - **all** non-zero-exposure checks for that unit are listed in `allowTests`.

## Engineering standards

- Language: Go (keep dependencies minimal; stdlib-first).
- Formatting: `gofmt` is mandatory.
- Static checks: `go vet` must pass.
- Tests: prefer deterministic unit tests with a stubbed `systemd-analyze` binary; avoid requiring systemd on the host.
- Coverage: keep meaningful coverage high on core logic (parsing, allowlist, reporting, SARIF).
- Keep changes narrow: do not add “nice to have” features outside the scope section.

## CI expectations

`.github/workflows/ci.yml` must stay green. It currently verifies:

- gofmt, go vet, `go mod tidy` cleanliness
- `go test` (including race where applicable) + build
- container build + a real smoke scan inside the container

If you change CLI flags, action inputs, or Dockerfile behavior, update CI accordingly.

