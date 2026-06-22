# Web3 and Smart-Contract Scanning

`burpollama web3-audit PATH` performs dependency-free static Solidity candidate
checks. It detects patterns such as `tx.origin` authorization, unrestricted
destruction, delegate calls, weak randomness, low-level calls, and unbounded
loops.

Results are candidates, not proven exploits. For deeper analysis install
Slither, Mythril, or Foundry and validate findings against the exact compiler,
deployment, proxy, and access-control configuration.

The Web3 scanner is isolated from the web pipeline and does not submit
transactions or interact with a chain.

