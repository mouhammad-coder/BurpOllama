"""
delta_tracker.py — Passive Delta Highlighting
Tracks the URL template surface discovered by Phase 1 automated crawl.
When Mode 2 (Burp passive layer) observes a URL NOT in that surface,
flags it as "Hidden Surface Area" and triggers an on-demand micro-scan.
"""

import re
from urllib.parse import urlparse
from typing import Callable, Optional, Set

# Reuse path template logic from recon_engine
_NUMERIC_RE = re.compile(r'^\d+$')
_UUID_RE    = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)
_HEX_RE     = re.compile(r'^[0-9a-f]{16,}$', re.IGNORECASE)
_TOKEN_RE   = re.compile(r'^[A-Za-z0-9_\-]{16,}$')


def _path_template(url: str) -> str:
    """Convert URL to structural template (mirrors recon_engine._path_template)."""
    try:
        parsed   = urlparse(url)
        segments = parsed.path.split("/")
        parts    = []
        for seg in segments:
            if not seg:
                parts.append(seg)
            elif _NUMERIC_RE.match(seg):
                parts.append("{id}")
            elif _UUID_RE.match(seg):
                parts.append("{uuid}")
            elif _HEX_RE.match(seg):
                parts.append("{hash}")
            elif _TOKEN_RE.match(seg) and not seg.isalpha():
                parts.append("{token}")
            else:
                parts.append(seg)
        return "{}://{}{}".format(parsed.scheme, parsed.netloc, "/".join(parts))
    except Exception:
        return url


class DeltaTracker:
    """
    Maintains the set of URL templates discovered during automated Phase 1.
    Compares every Mode 2 (Burp) URL against that baseline.

    If a URL template was NOT seen in Phase 1:
      - Flag as "Hidden Surface Area"
      - Broadcast high-visibility alert to dashboard
      - Optionally trigger micro-scan callback
    """

    def __init__(self):
        self._mode1_templates: Set[str] = set()
        self._mode1_hosts:     Set[str] = set()
        self._delta_seen:      Set[str] = set()   # templates already alerted
        self._delta_count:     int      = 0
        self._broadcast_fn              = None
        self._microscan_fn              = None     # async callback for on-demand scan
        self._enabled:         bool     = False

    def set_broadcast(self, fn):
        self._broadcast_fn = fn

    def set_microscan(self, fn):
        """Register async callback: fn(url, template) → None"""
        self._microscan_fn = fn

    def register_mode1_surface(self, urls: list):
        """
        Called after Phase 1 completes with the full clustered URL list.
        Builds the baseline template set.
        """
        self._mode1_templates.clear()
        self._mode1_hosts.clear()
        for url in urls:
            try:
                tmpl   = _path_template(url)
                parsed = urlparse(url)
                self._mode1_templates.add(tmpl)
                self._mode1_hosts.add(parsed.netloc.lower())
            except Exception:
                pass
        self._enabled = bool(self._mode1_templates)
        print("[DeltaTracker] Baseline: {} templates across {} hosts".format(
            len(self._mode1_templates), len(self._mode1_hosts)))

    def is_new_surface(self, url: str) -> bool:
        """
        Returns True if the URL represents a template NOT seen in Phase 1.
        Only checks URLs from hosts that were in scope during Phase 1.
        """
        if not self._enabled:
            return False
        try:
            parsed = urlparse(url)
            # Only track in-scope hosts
            if parsed.netloc.lower() not in self._mode1_hosts:
                return False
            # Ignore static assets
            path = parsed.path.lower()
            if re.search(r'\.(css|js|png|jpg|gif|ico|woff|svg|ttf)$', path):
                return False
            tmpl = _path_template(url)
            return tmpl not in self._mode1_templates
        except Exception:
            return False

    async def check_and_alert(self, url: str, log: Optional[Callable] = None):
        """
        Check a Mode 2 URL. If it's new surface, broadcast alert and
        optionally trigger micro-scan. Deduplicates alerts by template.
        """
        if not self.is_new_surface(url):
            return

        tmpl = _path_template(url)

        # Deduplicate — only alert once per template
        if tmpl in self._delta_seen:
            return
        self._delta_seen.add(tmpl)
        self._delta_count += 1

        msg = "[DeltaTracker] NEW SURFACE #{}: {} (template: {})".format(
            self._delta_count, url[:80], tmpl[:60])
        if log:
            log(msg, "warning")

        # Broadcast high-visibility alert to dashboard
        if self._broadcast_fn:
            try:
                await self._broadcast_fn({
                    "type":         "hidden_surface_alert",
                    "url":          url,
                    "template":     tmpl,
                    "delta_count":  self._delta_count,
                    "message":      "Hidden Surface Area detected — not found during automated crawl",
                })
            except Exception as e:
                print("[DeltaTracker] Broadcast error: {}".format(e))

        # Trigger on-demand micro-scan if callback registered
        if self._microscan_fn:
            try:
                await self._microscan_fn(url, tmpl)
            except Exception as e:
                print("[DeltaTracker] Micro-scan error: {}".format(e))

    @property
    def delta_count(self) -> int:
        return self._delta_count

    @property
    def baseline_size(self) -> int:
        return len(self._mode1_templates)

    @property
    def stats(self) -> dict:
        return {
            "enabled":        self._enabled,
            "baseline_size":  self.baseline_size,
            "delta_count":    self._delta_count,
            "hosts_tracked":  len(self._mode1_hosts),
        }


# ── Module-level singleton ────────────────────────────────────────────────────
delta_tracker = DeltaTracker()
