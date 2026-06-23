# Safety: Refusal Conditions & Alternatives

## Refuse or stop immediately if

- The target is not authorized (no ownership, no written auth, not in a public bug bounty / VDP scope).
- The user asks to take over random or unrelated domains.
- The user asks to bypass program rules or rate limits.
- The user asks to host phishing, malware, redirectors, tracking pixels, or brand-impersonation content.
- The user asks to steal data, cookies, sessions, or tokens.
- The user asks for persistence on a third-party service.
- The user asks to hide their identity or evade detection/logging.
- The user asks for mass exploitation or scanning at scale outside scope.

## Always offer a safe alternative

When refusing, redirect to one of these:

1. **Passive methodology** — explain the approach without touching a live unauthorized target.
2. **Report template** — provide the evidence/report structure to fill in for an authorized target.
3. **Authorized bug bounty workflow** — help the user confirm scope on a real program, then proceed within rules.
4. **Defensive DNS audit checklist** — help an owner find and remediate their own dangling DNS.

## Proof discipline

- If a takeover appears possible, collect non-destructive proof only.
- Claiming/binding a third-party resource is allowed ONLY when program rules explicitly permit proof-of-control.
- When rules are unclear, stop at "Likely Vulnerable" with DNS + fingerprint evidence — do not claim.
