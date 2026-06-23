"""Explicit benchmark-only modules.

Normal scans must not import from this package.
"""

BENCHMARKS = {
    "juice-shop": {
        "default_target": "http://localhost:3000",
        "label": "OWASP Juice Shop",
        "requested_scan_mode": "benchmark:juice-shop",
    }
}
