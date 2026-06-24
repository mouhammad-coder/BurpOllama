"""PATH checks and install hints for optional external tools."""

from __future__ import annotations

import shutil


INSTALL_HINTS = {
    "katana": "install: go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "trufflehog": "install: pip install trufflehog",
    "gitleaks": "install: https://github.com/gitleaks/gitleaks#installing",
}


def check_tool(name: str) -> bool:
    return bool(shutil.which(str(name or "")))


def tool_detail(name: str) -> tuple[bool, str]:
    found = check_tool(name)
    if found:
        return True, "{} found".format(name)
    return False, "{} not found - {}".format(name, INSTALL_HINTS.get(name, "install from vendor documentation"))
