# Evidence & Report Templates

## Evidence Artifact (one per reportable issue)

```text
Finding ID:
Target subdomain:
Root domain:
Program:
Scope status:
Discovery sources:
DNS evidence:
  CNAME:
  A:
  AAAA:
HTTP evidence:
  URL:
  Status:
  Title:
  Server:
  Fingerprint:
TLS evidence:
  Subject:
  Issuer:
  SAN:
Provider:
Takeover status:
False-positive checks:
Proof-of-control allowed:
Proof performed:
Risk:
Impact:
Reproduction:
Remediation:
Timestamps:
```

## Candidate Table

| Subdomain | DNS Target | Provider | HTTP Status | Fingerprint | Status | Confidence |
|---|---|---|---:|---|---|---:|

## Source Coverage Table

| Source | Used? | Results | Notes |
|---|---:|---:|---|
| crt.sh | Yes | 0 | CT logs |
| CertSpotter | Yes | 0 | CT logs |
| Censys | Yes | 0 | Hosts / certs |
| Shodan | Yes | 0 | DNS records |
| SecurityTrails | Yes | 0 | Passive DNS |
| VirusTotal | Yes | 0 | Relations |
| AlienVault OTX | Yes | 0 | Passive DNS |
| Chaos | Yes | 0 | DNS dataset |
| GitHub code search | Yes | 0 | Leaked references |
| Wayback Machine | Yes | 0 | Historical URLs |
| CommonCrawl | Yes | 0 | Historical URLs |
| Business intel | Yes | 0 | Acquisitions / brands |

## Full Report Template

Fill placeholders in angle-bracket form, e.g. the-subdomain, the-provider.

````markdown
# Subdomain Takeover on the-subdomain

## Summary

The subdomain the-subdomain appears to point to an unclaimed third-party resource on
the-provider. The DNS record is still active, but the backing service is missing or
unconfigured.

## Scope

- Program: the-program
- Asset: the-subdomain
- Scope status: In scope
- Testing type: Non-destructive validation
- Proof-of-control performed: Yes/No
- Authorization note: program rule or user confirmation

## Evidence

### DNS

```bash
dig +short CNAME the-subdomain
```

Output:

```text
cname-output
```

### HTTP

```bash
curl -i -L --max-time 10 https://the-subdomain
```

Output:

```text
short-output
```

### TLS

```bash
openssl s_client -connect the-subdomain:443 -servername the-subdomain </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

Output:

```text
certificate-output
```

## Reproduction Steps

1. Resolve the DNS record for the-subdomain.
2. Observe that it points to the-provider-target.
3. Request the subdomain over HTTPS.
4. Observe the provider-specific unclaimed-resource fingerprint.
5. Confirm it is not a false positive by checking provider behavior and known fingerprints.
6. If authorized, verify proof-of-control using a harmless proof token.

## Impact

An attacker may be able to serve arbitrary content from the-subdomain if they claim the
dangling resource on the-provider. This could allow brand impersonation, phishing,
trusted-domain abuse, and potential cookie / CORS / OAuth impact depending on the parent
domain configuration.

## Recommended Remediation

Remove the stale DNS record, or recreate and properly bind the missing resource in
the-provider. Also audit related DNS records for the same provider and add continuous
monitoring for dangling DNS records.

## Timeline / Timestamp

- Tested at: UTC timestamp
- Source discovered from: source
````
