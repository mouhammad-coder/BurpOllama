# Security Policy

## Authorized Use Only

BurpOllama is intended only for systems you own or where you have explicit written authorization to test. Do not use it for random public scanning, out-of-scope assets, brute force, DoS, WAF bypass, stealth/evasion, credential attacks, destructive exploitation, or auto-submission.

Always follow the current bug bounty program rules, including scope, rate limits, scanner permission, upload testing, authentication testing, GraphQL introspection, and OOB testing requirements.

## Tool-Generated Findings

Do not submit BurpOllama output without human verification. Treat Great Findings as prioritized evidence and Needs Manual Check as a safe manual validation plan, not as automatic proof that a program will accept a report.

## Reporting Vulnerabilities In BurpOllama

Report vulnerabilities in BurpOllama itself privately through GitHub Security Advisories when available. Do not open public issues containing credentials, private target details, scan evidence, or working exploitation details.

## Sensitive Data

Keep `program.yml`, auth profiles, Burp exports, `scans/`, `evidence/`, and local configuration files out of public commits unless you have explicit permission to disclose them.

## Safe Defaults

BurpOllama defaults to passive/conservative behavior when permission is missing or unknown. Preflight does not perform vulnerability testing, Burp import does not replay traffic, and final output is focused on Great Findings and Needs Manual Check rather than automatic report generation.
