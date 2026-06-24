# Impact Assessment

Assess realistic impact only. Do not exaggerate.

## Questions to answer

- Can an attacker host arbitrary content on a trusted subdomain?
- Is the parent domain high-trust?
- Are cookies scoped to the parent domain?
- Do CORS rules trust the subdomain?
- Does CSP include the subdomain?
- Is an OAuth redirect or SSO callback involved?
- Do password-reset links, email links, or marketing flows use this subdomain?
- Does the subdomain appear in mobile apps, JavaScript, GitHub code, docs, or old emails?
- Could it be used for phishing, malware hosting, brand impersonation, or session/cookie attacks?
- Is the affected subdomain wildcarded or isolated?

## Severity scale

| Level | Criteria |
|---|---|
| Critical | Account compromise, OAuth abuse, sensitive cookie access, SSO callback abuse |
| High | Arbitrary content on trusted subdomain with realistic phishing or token risk |
| Medium | Arbitrary content possible but no sensitive trust relationship found |
| Low | Dangling DNS with weak or unconfirmed takeover evidence |
| Informational | Misconfiguration exists but takeover not currently possible |
