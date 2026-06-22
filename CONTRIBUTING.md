# Contributing

Contributions should preserve BurpOllama's safety boundaries:

- no network testing without explicit authorization;
- no unrestricted shell execution;
- no silent model or tool downloads;
- no state-changing requests without explicit mutation consent;
- findings must distinguish candidates from validated vulnerabilities.

Run Python syntax checks and the complete offline test suite before submitting a
pull request. New detectors need positive, negative, timeout, and false-positive
tests.

