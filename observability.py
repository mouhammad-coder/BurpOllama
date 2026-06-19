"""
observability.py - metrics, tracing spans, health, and coverage telemetry.
"""

from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MetricRegistry:
    counters: dict[str, float] = field(default_factory=dict)
    gauges: dict[str, float] = field(default_factory=dict)
    histograms: dict[str, list[float]] = field(default_factory=dict)
    spans: list[dict] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)

    def inc(self, name: str, value: float = 1, **labels):
        key = self._key(name, labels)
        self.counters[key] = self.counters.get(key, 0) + value

    def gauge(self, name: str, value: float, **labels):
        self.gauges[self._key(name, labels)] = value

    def observe(self, name: str, value: float, **labels):
        self.histograms.setdefault(self._key(name, labels), []).append(value)

    @contextmanager
    def span(self, name: str, **attrs):
        start = time.time()
        status = "ok"
        try:
            yield
        except Exception:
            status = "error"
            raise
        finally:
            duration = time.time() - start
            self.observe("span_duration_seconds", duration, span=name, status=status)
            self.spans.append({
                "name": name,
                "status": status,
                "duration_ms": round(duration * 1000, 2),
                "attrs": attrs,
                "ts": start,
            })
            self.spans = self.spans[-500:]

    def _key(self, name: str, labels: dict) -> str:
        if not labels:
            return name
        suffix = ",".join("{}={}".format(k, labels[k]) for k in sorted(labels))
        return "{}{{{}}}".format(name, suffix)

    def prometheus(self) -> str:
        lines = []
        for key, value in sorted(self.counters.items()):
            lines.append("{} {}".format(self._prom_key(key), value))
        for key, value in sorted(self.gauges.items()):
            lines.append("{} {}".format(self._prom_key(key), value))
        for key, values in sorted(self.histograms.items()):
            if not values:
                continue
            lines.append("{}_count {}".format(self._prom_key(key), len(values)))
            lines.append("{}_sum {}".format(self._prom_key(key), round(sum(values), 6)))
            lines.append("{}_avg {}".format(self._prom_key(key), round(sum(values) / len(values), 6)))
        return "\n".join(lines) + "\n"

    def _prom_key(self, key: str) -> str:
        if "{" not in key:
            return key.replace(".", "_").replace("-", "_")
        name, raw = key.split("{", 1)
        raw = raw.rstrip("}")
        labels = []
        for item in raw.split(","):
            if "=" not in item:
                continue
            k, v = item.split("=", 1)
            escaped = str(v).replace("\\", "\\\\").replace('"', '\\"')
            labels.append('{}="{}"'.format(k, escaped))
        return "{}{{{}}}".format(name.replace(".", "_").replace("-", "_"), ",".join(labels))

    def health(self) -> dict:
        return {
            "uptime_seconds": int(time.time() - self.started_at),
            "counters": self.counters,
            "gauges": self.gauges,
            "recent_spans": self.spans[-20:],
        }


metrics = MetricRegistry()
