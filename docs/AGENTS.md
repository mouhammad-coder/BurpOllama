# Specialist Agents

BurpOllama exposes bounded specialist profiles:

1. Recon Agent
2. Recon Ranker
3. Credential Hunter
4. Token Auditor
5. Validator
6. Chain Builder
7. Final Findings Presenter
8. Web3 Auditor
9. Autopilot

These profiles describe responsibilities and safety requirements. They do not
grant an LLM unrestricted shell access. Network actions continue through scope
validation, request budgets, authorization checks, and auditable adapters.

The Final Findings Presenter replaces report writing. It separates Great
Findings from Needs Manual Check, hides noisy findings by default, redacts
secrets, and writes only internal scan artifacts.
