# Claude harness instructions

Use BurpOllama through its documented CLI or local API. Never scan a target
unless the user confirms ownership or written authorization. Prefer:

```bash
burpollama status
burpollama agents
burpollama scan TARGET --mode BALANCED --authorized
```

Do not bypass the authorization, scope, mutation, or intensive-testing gates.

