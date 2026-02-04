# systemd-security-gate

CLI + GitHub Action: fail CI when **required** `systemd` `.service` units in your repo exceed a security **exposure threshold**, using `systemd-analyze security` in **offline** mode.

## What it does

- Finds `.service` files by glob(s)
- Builds a temporary `--root` layout and runs:
  - `systemd-analyze security --offline=yes --root=... --threshold=... <unit>`
  - `systemd-analyze security --offline=yes --root=... --json=short <unit>` (for reports)
- Produces:
  - Markdown summary (stdout + `$GITHUB_STEP_SUMMARY` if set)
  - Optional JSON report
  - Optional SARIF report (for GitHub Code Scanning upload)

## Requirements

- `systemd-analyze` **v250+** (offline mode + `--json=short` + `--security-policy` + `--threshold`)
- v1 scope: **only `.service` units** (no `.socket/.timer` mapping yet)

## CLI usage

Build:

```bash
go build ./cmd/ssg
```

Scan:

```bash
./ssg scan \
  --repo-root . \
  --paths 'deploy/systemd/**/*.service' \
  --threshold 6.0 \
  --policy .ci/systemd-security-policy.json \
  --allowlist .ci/ssg-allowlist.json \
  --json-report ssg.json \
  --sarif-report ssg.sarif
```

Modes:

- `--mode enforce` (default): exit non-zero if any unit fails and is not allowlisted
- `--mode report`: never fail on threshold checks (adoption mode), but still fails on analysis errors

## Allowlist format (v1)

`--allowlist <path>` points to a JSON file:

```json
{
  "allowUnits": [
    "deploy/systemd/legacy.service",
    "legacy.service"
  ],
  "allowTests": [
    { "unit": "deploy/systemd/myapp.service", "test": "PrivateNetwork" },
    { "unit": "myapp.service", "test": "ProtectSystem" }
  ]
}
```

Notes:

- `unit` may be either repo-relative path or just the unit filename.
- `test` should match `json_field` / `name` from `systemd-analyze security --json=short`.
- Current semantics: if a unit exceeds `--threshold`, it is treated as **allowed** if:
  - the unit is in `allowUnits`, or
  - **all** non-zero-exposure checks are listed in `allowTests` for that unit.

## GitHub Action usage (container action)

This repo includes an action definition under `action/`. To use it, publish it to GitHub and reference it in workflows.

Example workflow:

```yaml
name: systemd security gate
on:
  pull_request:
  push:
    branches: [ main ]

jobs:
  ssg:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: <owner>/systemd-security-gate/action@v1
        with:
          paths: |
            deploy/systemd/**/*.service
          threshold: "6.0"
          policy: .ci/systemd-security-policy.json
          allowlist: .ci/ssg-allowlist.json
          json_report: ssg.json
          sarif_report: ssg.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ssg.sarif
```

## License

TBD
