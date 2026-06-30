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
passive scan command when the target is in scope.

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
manual-check findings, and proof blockers before you decide what to submit.

## Operations

```bash
burpollama status
burpollama doctor
burpollama version
burpollama history
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
