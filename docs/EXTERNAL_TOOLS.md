# External Tool Integration

BurpOllama detects optional tools and invokes them with argument arrays—never
through `shell=True`. Every execution has a timeout and bounded output.

Supported categories include:

- Recon: subfinder, httpx, katana, gau, waybackurls, dnsx, Amass, GoWitness
- Network: Naabu and bounded Nmap service discovery
- Validation: nuclei, Dalfox
- Discovery: ffuf, Gobuster, Arjun, ParamSpider
- Secrets: Gitleaks, TruffleHog, Semgrep
- Takeover: Subjack, DNSReaper, nuclei takeover templates
- Cloud: cloud_enum
- WAF: wafw00f plus BurpOllama's safe differential workflow
- TLS/CMS: testssl.sh and droopescan
- Kubernetes: Trivy and legacy kube-hunter (intensive authorization required;
  kube-hunter upstream recommends Trivy for maintained Kubernetes coverage)
- Injection: CRLFuzz candidates plus BurpOllama's built-in CRLF validation
- Web3: Slither, Mythril, Foundry

Missing tools are reported as unavailable and never make a scan fail.
All discovery workflows are checked by ScopePolicy before execution.
