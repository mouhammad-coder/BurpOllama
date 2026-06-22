# External Tool Integration

BurpOllama detects optional tools and invokes them with argument arrays—never
through `shell=True`. Every execution has a timeout and bounded output.

Supported categories include:

- Recon: subfinder, httpx, katana, gau, waybackurls, dnsx
- Validation: nuclei, Dalfox
- Discovery: ffuf, Arjun, ParamSpider
- Secrets: Gitleaks, TruffleHog, Semgrep
- Takeover: Subjack, DNSReaper, nuclei takeover templates
- Cloud: cloud_enum
- WAF: wafw00f plus BurpOllama's safe differential workflow
- Web3: Slither, Mythril, Foundry

Missing tools are reported as unavailable and never make a scan fail.

