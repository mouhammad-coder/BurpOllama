# Burp Import Example Notes

Burp imports are passive by default. `burpollama burp import` records metadata
about a Burp XML or HAR export and does not replay requests.

Safe workflow:

```bash
burpollama burp import burp-history.xml --program examples/program.yml
burpollama ai-autopilot --from-burp latest --goal burp-import-analysis --final-output terminal
```

Before using this against a real program:

- Replace `examples/program.yml` with the real authorized program scope.
- Export only traffic you are allowed to analyze.
- Keep cookies, tokens, and private target details out of public commits.
- Use the generated Needs Manual Check steps with owned test accounts only.
