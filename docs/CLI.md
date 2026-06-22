# BurpOllama CLI

The `burpollama` command is a local command center for the dashboard, scan API,
specialist agents, optional tools, technique memory, and isolated Web3 checks.

```bash
burpollama serve
burpollama status
burpollama agents
burpollama tools
burpollama scan https://authorized.example --mode BALANCED --authorized
burpollama discover parameters https://authorized.example --authorized --intensive
burpollama waf-check https://authorized.example --authorized --intensive
burpollama web3-audit contracts/
```

`--authorized` is deliberately required for network discovery and scanning.
`--intensive` is separately required for higher-volume adapters such as ffuf,
Arjun, Dalfox, and symbolic analyzers.

Scope imports are advisory:

```bash
burpollama scope-import hackerone-scope.json bugcrowd-scope.csv
```

Always compare imported data with the live program policy before testing.
