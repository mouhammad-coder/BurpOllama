"""
request_fingerprint.py - HTTP fingerprinting, response dedupe, and similarity clustering.

The scanner sees the same application state through many URLs, cache variants,
tracking parameters, and Burp captures. This layer gives the rest of the system
stable fingerprints so expensive checks and AI calls can be deduplicated.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Iterable, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

try:
    import tlsh as _tlsh  # type: ignore
except Exception:  # pragma: no cover - optional native dependency
    _tlsh = None


NOISY_QUERY_KEYS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "_", "cachebuster", "cb", "ts", "t",
}

VOLATILE_HEADERS = {
    "date", "set-cookie", "cookie", "authorization", "x-request-id",
    "x-correlation-id", "cf-ray", "etag", "last-modified", "server-timing",
}


class _StructureParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tokens: list[str] = []

    def handle_starttag(self, tag, attrs):
        names = sorted(k.lower() for k, _ in attrs if k)
        self.tokens.append("{}({})".format(tag.lower(), ",".join(names[:8])))

    def handle_data(self, data):
        if data.strip():
            self.tokens.append("#text")


def _stable_json(value):
    if isinstance(value, dict):
        return {str(k): _stable_json(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_stable_json(v) for v in value[:20]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str):
            return normalize_dynamic_text(value)
        return value
    return str(value)


def normalize_dynamic_text(text: str) -> str:
    text = text or ""
    text = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "UUID", text, flags=re.I)
    text = re.sub(r"\b\d{10,13}\b", "TS", text)
    text = re.sub(r"\b\d+\b", "N", text)
    text = re.sub(r"[A-Za-z0-9+/]{32,}={0,2}", "TOKEN", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def canonical_url(url: str) -> str:
    parsed = urlparse(url or "")
    query = [
        (k, normalize_dynamic_text(v))
        for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        if k.lower() not in NOISY_QUERY_KEYS
    ]
    query.sort()
    path = re.sub(r"/\d+(?=/|$)", "/:id", parsed.path or "/")
    path = re.sub(r"/[0-9a-f]{8}-[0-9a-f-]{27,}(?=/|$)", "/:uuid", path, flags=re.I)
    return urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        path,
        "",
        urlencode(query, doseq=True),
        "",
    ))


def structural_body(body: str, content_type: str = "") -> str:
    body = body or ""
    ct = (content_type or "").lower()
    if "json" in ct or body.lstrip().startswith(("{", "[")):
        try:
            return json.dumps(_stable_json(json.loads(body)), sort_keys=True, separators=(",", ":"))
        except Exception:
            pass
    if "html" in ct or "<html" in body[:500].lower():
        parser = _StructureParser()
        try:
            parser.feed(body[:200000])
            return " ".join(parser.tokens[:5000])
        except Exception:
            return normalize_dynamic_text(re.sub(r"<[^>]+>", " TAG ", body[:200000]))
    return normalize_dynamic_text(body[:200000])


def sha256_short(value: str, size: int = 16) -> str:
    return hashlib.sha256((value or "").encode("utf-8", errors="ignore")).hexdigest()[:size]


def simhash(text: str, bits: int = 64) -> int:
    tokens = re.findall(r"[A-Za-z0-9_:/.-]{2,}", (text or "").lower())
    if not tokens:
        return 0
    vector = [0] * bits
    for token in tokens:
        digest = int(hashlib.blake2b(token.encode(), digest_size=8).hexdigest(), 16)
        weight = 2 if "/" in token or ":" in token else 1
        for i in range(bits):
            vector[i] += weight if digest & (1 << i) else -weight
    out = 0
    for i, value in enumerate(vector):
        if value >= 0:
            out |= 1 << i
    return out


def hamming_distance(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def tlsh_digest(body: str) -> str:
    data = (body or "").encode("utf-8", errors="ignore")
    if _tlsh and len(data) >= 50:
        try:
            digest = _tlsh.hash(data)
            if digest and digest != "TNULL":
                return digest
        except Exception:
            pass
    # Fallback keeps the field useful even when the native TLSH wheel is absent.
    shingles = set()
    text = normalize_dynamic_text(body).lower()
    for i in range(0, max(0, len(text) - 5)):
        shingles.add(text[i:i + 6])
    return "FALLBACK-" + sha256_short("|".join(sorted(shingles))[:50000], 32)


def headers_fingerprint(headers: str | dict | None) -> str:
    if not headers:
        return ""
    if isinstance(headers, str):
        pairs = []
        for line in headers.splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            pairs.append((k.strip().lower(), normalize_dynamic_text(v.strip())))
    else:
        pairs = [(str(k).lower(), normalize_dynamic_text(str(v))) for k, v in headers.items()]
    stable = [(k, v) for k, v in pairs if k not in VOLATILE_HEADERS]
    stable.sort()
    return sha256_short(json.dumps(stable, separators=(",", ":")), 20)


@dataclass(frozen=True)
class RequestFingerprint:
    canonical_url: str
    structural_hash: str
    simhash: str
    tlsh: str
    response_hash: str
    header_hash: str

    def as_dict(self) -> dict:
        return {
            "canonical_url": self.canonical_url,
            "structural_hash": self.structural_hash,
            "simhash": self.simhash,
            "tlsh": self.tlsh,
            "response_hash": self.response_hash,
            "header_hash": self.header_hash,
        }


def fingerprint_http(
    method: str,
    url: str,
    request_body: str = "",
    response_status: int = 0,
    response_headers: str | dict | None = None,
    response_body: str = "",
) -> RequestFingerprint:
    header_hash = headers_fingerprint(response_headers)
    content_type = ""
    if isinstance(response_headers, dict):
        content_type = str(response_headers.get("content-type") or response_headers.get("Content-Type") or "")
    elif isinstance(response_headers, str):
        m = re.search(r"(?im)^content-type:\s*(.+)$", response_headers)
        content_type = m.group(1) if m else ""
    structure = structural_body(response_body, content_type)
    response_key = "{}:{}:{}:{}:{}".format(
        (method or "GET").upper(),
        canonical_url(url),
        int(response_status or 0),
        header_hash,
        structure,
    )
    return RequestFingerprint(
        canonical_url=canonical_url(url),
        structural_hash=sha256_short(structure, 24),
        simhash="{:016x}".format(simhash(structure)),
        tlsh=tlsh_digest(response_body),
        response_hash=sha256_short(response_key, 32),
        header_hash=header_hash,
    )


class ResponseDeduplicator:
    def __init__(self, simhash_threshold: int = 4):
        self.simhash_threshold = simhash_threshold
        self._exact: dict[str, RequestFingerprint] = {}
        self._clusters: dict[str, list[RequestFingerprint]] = defaultdict(list)

    def add(self, fp: RequestFingerprint) -> tuple[bool, str]:
        if fp.response_hash in self._exact:
            return False, fp.response_hash
        sim = int(fp.simhash, 16)
        for cluster_id, members in self._clusters.items():
            if members and hamming_distance(sim, int(members[0].simhash, 16)) <= self.simhash_threshold:
                members.append(fp)
                self._exact[fp.response_hash] = fp
                return True, cluster_id
        cluster_id = "CL-" + sha256_short(fp.structural_hash + fp.simhash, 12)
        self._clusters[cluster_id].append(fp)
        self._exact[fp.response_hash] = fp
        return True, cluster_id

    def stats(self) -> dict:
        return {
            "responses_seen": len(self._exact),
            "similarity_clusters": len(self._clusters),
            "largest_cluster": max((len(v) for v in self._clusters.values()), default=0),
        }


def cluster_fingerprints(fingerprints: Iterable[RequestFingerprint], threshold: int = 4) -> list[dict]:
    deduper = ResponseDeduplicator(simhash_threshold=threshold)
    for fp in fingerprints:
        deduper.add(fp)
    clusters = []
    for cid, members in deduper._clusters.items():
        clusters.append({
            "id": cid,
            "size": len(members),
            "representative": members[0].as_dict() if members else {},
            "urls": [m.canonical_url for m in members[:25]],
        })
    return sorted(clusters, key=lambda c: c["size"], reverse=True)
