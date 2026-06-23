# Proof-of-Control (Authorized Only)

Perform claiming/binding ONLY when program rules explicitly allow proof-of-control. Otherwise stop at non-destructive validation and classify as "Likely Vulnerable".

## Harmless proof token

If authorized, host a single benign text file with no active content, no scripts, no styling, no data collection:

```text
subdomain-takeover-proof
researcher: <handle>
program: <program>
timestamp: <UTC timestamp>
no user data accessed
```

## Rules

- No HTML, JS, forms, redirects, tracking, or branding — plain text only.
- Take down the proof immediately after capturing evidence.
- Record the exact claim steps, the provider, and timestamps in the evidence block.
- Never use a claimed resource to receive traffic, cookies, or credentials.
- If you are unsure whether claiming is permitted, do NOT claim.
