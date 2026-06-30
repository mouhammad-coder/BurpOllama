# BurpOllama CLI

The Rich terminal interface is BurpOllama's primary workflow. Normal commands
run the scanner directly and do not connect to FastAPI.

Setup installs the `burpollama` launcher under `~/.local/bin`. You can also
replace `burpollama` in every example with `python3 cli.py`.

## Scan modes

```bash
# Safe default (passive)
burpollama scan https://authorized.example

# Balanced authorized bounty workflow
burpollama scan https://authorized.example --mode bounty

# Deeper authorized workflow
burpollama scan https://authorized.example --mode deep

# Explicit scope and bounded execution
burpollama scan https://authorized.example --mode bounty \
  --scope authorized.example --concurrency 5 --rate-limit 2 \
  --max-urls 100 --time-budget 900 --yes
```

Passive mode does not run active vulnerability tests. Bounty and deep modes ask
you to confirm that you own the target or have written permission. For a
non-interactive authorized job:

```bash
burpollama scan https://authorized.example --mode bounty --yes
```

Use `--scope authorized.example` to enforce an explicit domain allowlist. The
option can be repeated.

Before scanning a program scope file, run a preflight audit:

```bash
burpollama scope-check --scope-file scope.txt --audit --target https://api.authorized.example
```

The audit prints included/excluded rule counts, target scope status, and a safe
passive scan command when the target is in scope. When `--write-manifest` is
provided, it also writes a `cli_runbook` with the scan, readiness report,
readiness gate, and ready-only history commands.

You can also normalize a saved HackerOne/Bugcrowd-style program JSON export
before scanning:

```bash
burpollama scope-check --program-json program-policy.json \
  --write-scope scope.txt \
  --write-manifest preflight.json \
  --audit --target https://api.authorized.example
```

Additional controls:

```text
--concurrency N       bounded worker concurrency (default 5)
--rate-limit N        global requests per second (default 2)
--timeout SECONDS     request timeout
--retries N           bounded retry policy
--max-urls N          maximum discovered URLs carried into scan phases
--time-budget SECONDS maximum scan runtime before partial reports are written
--ai PROVIDER         preferred configured AI provider
--model MODEL         preferred model
--output DIRECTORY    report root directory
--quiet               final summary only
--json                JSON Lines events and final result
--follow              keep following until completion (direct scans already do)
```

During a scan, the terminal displays:

- Phase transitions
- The current vulnerability class
- Tested URL counters
- Key HTTP methods and response codes
- WAF and throttle warnings
- Findings as they are discovered
- Severity totals and elapsed time
- A persistent specialist-agent status table
- Overall and per-agent progress bars
- A live findings ticker

When Cloudflare JavaScript challenges are detected, BurpOllama warns
immediately and switches that scan to passive-only mode.

## Watch a dashboard scan

```bash
burpollama watch --scan-id <scan-id>
```

This connects to `ws://127.0.0.1:8888/ws`, replays available scan logs, and
continues streaming events in real time.

The optional server is started only when requested:

```bash
burpollama serve
burpollama dashboard
```

## Reconnaissance

```bash
burpollama recon https://authorized.example
burpollama recon https://authorized.example --mode deep
```

## Benchmarks

Use benchmark mode only for local authorized labs. Check that OWASP Juice Shop
is reachable before running validation probes:

```bash
burpollama benchmark juice-shop --check
burpollama benchmark juice-shop --yes
```

## Reports

```bash
burpollama report --scan-id <scan-id>
burpollama report --scan-id <scan-id> --format hackerone
burpollama report --scan-id <scan-id> --format bugcrowd
burpollama report --scan-id <scan-id> --format readiness
burpollama report --scan-id <scan-id> --format sarif --output results.sarif
```

Available formats are `markdown`, `hackerone`, `bugcrowd`, `json`, `csv`,
`sarif`, and `readiness`. The readiness audit summarizes report-ready issues,
manual-check findings, missing report-ready artifacts, and proof blockers
before you decide what to submit.

Use `--latest` to work with the most recent stored scan:

```bash
burpollama report --latest --format readiness
burpollama report --latest --format hackerone
```

## Bug bounty readiness gate

`readiness-check` is the CLI pass/fail gate for authorized program work. It is
designed for the final step after a bounded scan:

```bash
burpollama readiness-check --latest
burpollama readiness-check --latest --require-report-ready
burpollama readiness-check --latest --json --output readiness-decision.json
```

The command exits `0` when the scan has actionable report-ready or manual-check
output and all report-ready evidence artifacts exist. It exits `3` when:

- no report-ready or manual-check findings exist
- `--require-report-ready` is used and no report-ready issue exists
- a report-ready finding references a missing evidence artifact

The JSON output contains:

```json
{
  "passed": true,
  "reason": "scan has actionable bounty output",
  "scan_id": "scan-id",
  "target": "https://authorized.example",
  "readiness": {
    "report_ready_issues": 1,
    "report_ready_findings": 1,
    "manual_check_findings": 3,
    "proof_blocked_findings": 2,
    "missing_report_ready_artifacts": 0
  }
}
```

Use the gate as a hard stop before spending time writing a report. A passing
gate means the scan produced something actionable; it does not replace program
policy review or manual validation of low-context findings.

## Operations

```bash
burpollama status
burpollama doctor
burpollama version
burpollama history
burpollama history --ready-only --limit 20
burpollama validate "IDOR on /api/users/{id}" --url https://authorized.example/api/users/1
burpollama analyze --file captured-traffic.json
```

`analyze` imports the passive analyzer directly; it does not require the server.

## Local persistence

Standalone scans and reports are stored in `~/.burpollama/scans.db`. The
`history` and `report` commands read that database directly.

Every completed or interrupted scan also writes a report bundle under
`reports/<scan-id>/` unless `--output` selects another directory.

`--api` applies only to dashboard-oriented commands such as `watch`:

```bash
burpollama --api http://127.0.0.1:9000 watch --scan-id <scan-id>
```

Only scan systems you own or have explicit written authorization to test.
