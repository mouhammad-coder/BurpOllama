# Enrichment & Confirmation Commands

Run only against in-scope, authorized hosts. Check tool availability first:

```bash
which curl openssl dig nuclei dnsx httpx subfinder 2>/dev/null
```

## DNS resolution

```bash
dig +short CNAME sub.example.com
dig +short A    sub.example.com
dig +short AAAA sub.example.com
dig +trace      sub.example.com
```

Check multiple resolvers (catch split-horizon / stale caches):

```bash
dig @1.1.1.1 sub.example.com CNAME +short
dig @8.8.8.8 sub.example.com CNAME +short
dig @9.9.9.9 sub.example.com CNAME +short
```

If `dig` is unavailable, use Python:

```python
import dns.resolver  # pip install dnspython if missing
for rr in ("CNAME", "A", "AAAA"):
    try:
        print(rr, [r.to_text() for r in dns.resolver.resolve("sub.example.com", rr)])
    except Exception as e:
        print(rr, "->", e)
```

## HTTP probing

```bash
curl -I -L --max-time 10 https://sub.example.com           # headers + redirect chain
curl -i -L --max-time 10 https://sub.example.com           # headers + body
curl -s -L https://sub.example.com | head -n 40            # body fingerprint
curl -I -L --max-redirs 10 https://sub.example.com         # full redirect chain
curl -i    --max-time 10 http://sub.example.com            # plain HTTP variant
```

## TLS certificate

```bash
openssl s_client -connect sub.example.com:443 -servername sub.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

## Optional automated detection (only if installed + active scanning authorized)

```bash
# Resolve + probe a candidate list
dnsx  -l subdomains.all.txt -cname -a -resp -o resolved.txt
httpx -l subdomains.all.txt -title -status-code -tech-detect -o httpx.txt

# Fingerprint-based takeover detection
nuclei -l subdomains.all.txt -t http/takeovers/ -o nuclei-takeovers.txt
```

## Record for every subdomain

CNAME target · A / AAAA · HTTP status · HTTP title · Server header · body fingerprint ·
TLS subject · TLS issuer · TLS SANs · error message · redirect chain · timestamp (UTC) · discovery source.
