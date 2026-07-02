# BurpOllama

BurpOllama is a CLI-first authorized bug bounty scanner. It locks every run to explicit user-provided scope, uses safe passive defaults, and ends with a terminal summary of:

1. Great Findings
2. Needs Manual Check

It does not discover random public programs, auto-submit findings, or generate report drafts. Internal scan artifacts are written under `scans/<scan-id>/`.

## Safety

Use BurpOllama only on systems you own or where you have explicit written authorization. Respect the program scope, rate limits, and prohibited testing rules.

BurpOllama must not be used for brute force, DoS, WAF bypass, stealth/evasion, destructive exploitation, credential attacks, arbitrary shell execution, or out-of-scope scanning.

Do not submit tool-generated findings without human verification.

## Install

```bash
git clone https://github.com/your-org/BurpOllama.git
cd BurpOllama
python -m pip install --upgrade pip
python -m pip install -e .
burpollama --help
burpollama doctor
```

Supported Python versions: 3.10, 3.11, and 3.12. The CLI is tested on Windows and Linux/Kali-style environments.

## Quick Local Test

Use local targets only for smoke tests. Do not point smoke tests at public targets.

```bash
# Optional: run the benchmark target locally if you use OWASP Juice Shop.
burpollama benchmark juice-shop --check
burpollama benchmark juice-shop --yes

# Review final findings.
burpollama findings --latest
```

Expected outcome: the benchmark path prints final findings, including Great Findings and Needs Manual Check opportunities when the local lab is available. Stop the local lab when finished.

## program.yml Setup

Start from `examples/program.yml` and replace every `example.com` entry with the exact authorized program scope.

```yaml
program: example-authorized-program
scanner_allowed: true
automated_testing_allowed: true
in_scope:
  - example.com
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
```

If scanner permission is missing or unknown, BurpOllama defaults to conservative passive behavior.

## Preflight

Run preflight before scanning an authorized target:

```bash
burpollama preflight https://target.com --program program.yml
```

Preflight checks DNS resolution, scope status, scanner permission, automated testing permission, effective mode, rate limits, cloud AI permission, auth/upload/OOB permission, blocked checks, and the recommended safe command. It does not perform vulnerability testing.

## Passive Authorized Scan

Recommended first scan:

```bash
burpollama ai-autopilot https://target.com --program program.yml --goal bounty-hunt --mode passive --multi-agent --final-output terminal
```

Dry-run the plan without sending scan requests:

```bash
burpollama ai-autopilot https://target.com --program program.yml --goal bounty-hunt --dry-run-plan
```

## Burp Import Workflow

Burp imports are passive by default and do not replay requests.

```bash
burpollama burp import burp-history.xml --program program.yml
burpollama ai-autopilot --from-burp latest --goal burp-import-analysis --final-output terminal
```

## Access-Control Workflow

Use only owned, authorized test accounts.

```bash
burpollama ai-autopilot https://target.com --program program.yml --goal access-control --auth-profile userA.json --auth-profile userB.json --final-output terminal
```

Auth profiles support `name`, `base_url`, `cookies`, `headers`, `role`, and `notes`. Cookies and headers are redacted from output.

## Findings Command

```bash
burpollama findings --latest
burpollama findings --latest --json
burpollama findings --latest --show-all
```

Final output always includes stable sections such as Scan Finished, Target, Goal, Mode, Program, Scanner Permission, Great Findings, Needs Manual Check, and Best Next Safe Actions.

## Troubleshooting

- `burpollama doctor` checks Python, packages, optional AI, Ollama status, config/scans writability, external tools, and safe defaults.
- `Target is outside program.yml scope`: fix `in_scope` or the target URL before scanning.
- `Scanner permission is unknown`: use passive mode until the program explicitly allows scanners.
- No Great Findings: review Needs Manual Check, add authorized test users/cookies if allowed, and rerun within program rules.
- Rate-limit, upload, GraphQL introspection, payment/order workflow, MFA, and access-control findings often require manual verification and explicit permission.

## Development

```bash
python -m py_compile cli.py core\program_profile.py core\findings.py core\storage.py core\events.py core\scanner.py core\skills\runner.py core\skills\evidence.py core\agents\base.py core\agents\final_findings_presenter_agent.py core\benchmarks\juice_shop.py
python -m pytest
```
