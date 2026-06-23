# BurpOllama CLI

The Rich terminal interface is BurpOllama's primary workflow. The dashboard is
optional and remains available at `http://127.0.0.1:8888/ui`.

## Start the backend

```bash
bash start.sh
```

Setup installs the `burpollama` launcher under `~/.local/bin`. You can also
replace `burpollama` in every example with `python3 cli.py`.

## Scan modes

```bash
# Balanced bounty workflow
burpollama scan https://authorized.example

# Passive-only workflow
burpollama scan https://authorized.example --mode passive

# Deeper authorized workflow
burpollama scan https://authorized.example --mode deep
```

The CLI asks you to confirm that you own the target or have written permission.
For a non-interactive job where authorization has already been established:

```bash
burpollama scan https://authorized.example --yes
```

During a scan, the terminal displays:

- Phase transitions
- The current vulnerability class
- Tested URL counters
- Key HTTP methods and response codes
- WAF and throttle warnings
- Findings as they are discovered
- Severity totals and elapsed time

When Cloudflare JavaScript challenges are detected, BurpOllama warns
immediately and switches that scan to passive-only mode.

## Watch a dashboard scan

```bash
burpollama watch --scan-id <scan-id>
```

This connects to `ws://127.0.0.1:8888/ws`, replays available scan logs, and
continues streaming events in real time.

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
burpollama report --scan-id <scan-id> --format sarif --output results.sarif
```

Available formats are `markdown`, `hackerone`, `bugcrowd`, `json`, `csv`, and
`sarif`.

## Operations

```bash
burpollama status
burpollama history
burpollama validate "IDOR on /api/users/{id}" --url https://authorized.example/api/users/1
burpollama analyze --file captured-traffic.json
```

`analyze` sends exported Burp request/response JSON to the local passive
analysis endpoint.

## Remote or alternate backend

The default API is `http://127.0.0.1:8888`. Override it before the command:

```bash
burpollama --api http://127.0.0.1:9000 status
```

Only scan systems you own or have explicit written authorization to test.
