# BurpOllama CLI

The CLI is the primary BurpOllama workflow. It runs scans directly, streams progress, and ends with final findings tables. It does not require FastAPI or the dashboard.

## Scan

```bash
# Passive default
burpollama scan https://authorized.example --yes

# Balanced authorized bounty mode
burpollama scan https://authorized.example --mode bounty --yes

# Deep authorized mode
burpollama scan https://authorized.example --mode deep --yes

# Explicit scope and bounded execution
burpollama scan https://authorized.example --mode bounty --yes \
  --scope authorized.example \
  --concurrency 5 --rate-limit 2 \
  --max-urls 100 --time-budget 900 \
  --output scans/authorized-program
```

Passive mode avoids active vulnerability tests. Bounty and deep modes require confirmation that you own the target or have written permission. Use `--yes` only for authorized targets.

## AI Autopilot Goals

## Command Examples

Preflight:

```bash
burpollama preflight https://target.com --program program.yml
```

Passive bounty scan:

```bash
burpollama ai-autopilot https://target.com --program program.yml --goal bounty-hunt --mode passive --multi-agent --final-output terminal
```

Dry run:

```bash
burpollama ai-autopilot https://target.com --program program.yml --goal bounty-hunt --dry-run-plan
```

Burp analysis:

```bash
burpollama burp import burp-history.xml --program program.yml
burpollama ai-autopilot --from-burp latest --goal burp-import-analysis --final-output terminal
```

Access control:

```bash
burpollama ai-autopilot https://target.com --program program.yml --goal access-control --auth-profile userA.json --auth-profile userB.json --final-output terminal
```

Latest findings:

```bash
burpollama findings --latest
burpollama findings --latest --json
burpollama findings --latest --show-all
```

Recommended first command:

```bash
burpollama preflight https://target.com --program program.yml
```

Recommended passive bounty workflow:

```bash
burpollama ai-autopilot https://target.com \
  --program program.yml \
  --goal bounty-hunt \
  --mode passive \
  --multi-agent \
  --final-output terminal
```

Dry-run the plan without sending scan requests:

```bash
burpollama ai-autopilot https://target.com \
  --program program.yml \
  --goal bounty-hunt \
  --dry-run-plan
```

Supported goals:

```text
recon
bounty-hunt
access-control
api-hunt
passive-analysis
manual-check
burp-import-analysis
```

`recon` only discovers attack surface safely. `bounty-hunt` runs the full safe multi-agent bounty workflow. `access-control` focuses on IDOR/BOLA/BFLA and role/object ownership candidates. `api-hunt` focuses API, object IDs, GraphQL, auth-required endpoints, excessive data exposure, mass assignment, and CORS with impact. `passive-analysis` avoids active checks. `manual-check` focuses human-verification items. `burp-import-analysis` analyzes imported Burp traffic passively.

Final output modes:

```text
--final-output chat      print final result directly for chat/Codex style output
--final-output terminal  print final result directly for CLI display
--final-output json      print machine-readable JSON to stdout
```

The default is `terminal`. Final results are always printed directly; users do not need to open `findings.json` to see the Great Findings and Needs Manual Check tables.

Recommended access-control workflow:

```bash
burpollama ai-autopilot https://target.com \
  --program program.yml \
  --goal access-control \
  --auth-profile userA.json \
  --auth-profile userB.json \
  --final-output terminal
```

Recommended Burp workflow:

```bash
burpollama burp import burp-history.xml --program program.yml
burpollama ai-autopilot --from-burp latest \
  --goal burp-import-analysis \
  --final-output terminal
```

If no `program.yml` is provided, non-interactive use requires `--yes --scope target.com`. Scope is still enforced.

## Program Profile

Example `program.yml`:

```yaml
program: example
platform: hackerone
scanner_allowed: true
automated_testing_allowed: true
in_scope:
  - example.com
  - api.example.com
out_of_scope:
  - staging.example.com
forbidden_tests:
  - dos
  - brute_force
  - spam
  - social_engineering
  - destructive_actions
allowed_modes:
  - passive
  - bounty
max_rps: 2
max_concurrency: 5
auth_testing_allowed: true
upload_testing_allowed: false
graphql_introspection_allowed: false
oob_testing_allowed: false
cloud_ai_allowed: false
notes: "Follow program rules strictly."
```

If `scanner_allowed` or `automated_testing_allowed` is false, active scanning is disabled. If scanner permission is missing, BurpOllama warns:

```text
Automated scanner permission is unknown. Running conservative passive checks only.
```

Common scan controls:

```text
--scope DOMAIN        in-scope domain; repeat for multiple domains
--scope-file FILE     text scope file with includes and ! exclusions
--concurrency N       bounded worker concurrency
--rate-limit N        global requests per second across agents
--timeout SECONDS     request timeout
--retries N           bounded retry count
--max-urls N          maximum discovered URLs carried into scan phases
--time-budget SECONDS maximum runtime before partial findings are written
--ai                  enable configured AI agents
--no-ai               disable AI agents
--ai-provider NAME    provider override
--model MODEL         model override
--output DIRECTORY    scan artifact root; default is scans
--quiet               final output only
--json                JSON event stream and final result
--no-external-tools   skip optional Katana, Nuclei, TruffleHog, and Gitleaks
--oob-server URL      explicit authorized OOB callback URL
```

## Final Findings

Use `findings` to review stored scan results:

```bash
burpollama findings --latest
burpollama findings --latest --show-info
burpollama findings --latest --show-rejected
burpollama findings --latest --show-all
burpollama findings --latest --json
burpollama findings --latest --min-rate high
burpollama findings --latest --min-confidence 80
burpollama findings --scan-id <scan-id>
```

Default output shows only:

- `Great Finding`
- `Needs Manual Check`

Hidden by default:

- `Informational`
- `Rejected`

`--json` prints stable JSON with `scan_id`, `target`, filtered `findings`, and status counts.

## Finding Statuses

| Status | CLI behavior |
|---|---|
| `Great Finding` | Printed in the Great Findings table. Requires high confidence, clear impact, complete evidence, and in-scope target. |
| `Needs Manual Check` | Printed in the Needs Manual Check table. Includes observed evidence, missing proof, and exact manual step. |
| `Informational` | Hidden by default. Use `--show-info` or `--show-all`. |
| `Rejected` | Hidden by default. Use `--show-rejected` or `--show-all` for debugging. |

Manual-check findings are used when a candidate needs two authorized accounts, authenticated cookies, program permission, active testing, impact confirmation, role comparison, file upload testing, GraphQL introspection permission, rate-limit testing, payment/order/workflow validation, or business logic understanding.

## Deprecated Commands

The old export command exits nonzero and prints:

```bash
This command is deprecated. Use `burpollama findings --latest` instead.
```

Use `findings` for terminal tables or JSON intended for local automation.

## Scope Preflight

```bash
burpollama scope-check --scope-file scope.txt --audit --target https://api.authorized.example
```

The audit shows included/excluded rules, target scope status, warnings, and a safe scan command when the target is in scope.

Normalize a saved program scope export:

```bash
burpollama scope-check --program-json program-policy.json \
  --write-scope scope.txt \
  --write-manifest preflight.json \
  --audit --target https://api.authorized.example
```

## Other Commands

```bash
burpollama status
burpollama doctor
burpollama version
burpollama history
burpollama history --ready-only --limit 20
burpollama validate "IDOR on /api/users/{id}" --url https://authorized.example/api/users/1
burpollama analyze --file captured-traffic.json
burpollama recon https://authorized.example --yes
```

## Local Smoke Test

Use local labs only. Do not use smoke tests against public targets.

```bash
# Start your local lab, for example OWASP Juice Shop on localhost:3000.
burpollama benchmark juice-shop --check
burpollama benchmark juice-shop --yes
burpollama findings --latest
# Stop the local lab when finished.
```

Verify the final terminal output contains Great Findings or useful Needs Manual Check opportunities before testing any authorized external program.

## Optional Dashboard

```bash
burpollama serve
burpollama dashboard
burpollama watch --scan-id <scan-id>
```

`watch` connects to the local dashboard WebSocket and replays scan events.

## Local Persistence

Standalone scan metadata is stored in `~/.burpollama/scans.db`. Internal scan artifacts are written under:

```text
scans/<scan-id>/
  findings.json
  evidence-board.json
  agent-messages.jsonl
  agent-decisions.jsonl
  agent-graph.json
  scan-log.jsonl
```

Only final findings and internal scan data are written.

## Safe Usage Notes

- Never scan systems without written authorization.
- Do not run bounty or deep mode unless the program permits active checks.
- Do not perform brute force, DoS, WAF bypass/evasion, destructive exploitation, arbitrary shell execution, or auto-submission.
- Rate-limit findings usually require manual validation because BurpOllama avoids high-volume testing.
- Upload, payment, order, workflow, GraphQL introspection, and role-comparison findings usually need manual permission and controlled test accounts.
