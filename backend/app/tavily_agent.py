"""Tavily threat-intel + stale-claim verification.

Verdicts: CONFIRMED | STALE_CONTRADICTED | REVOKED | UNVERIFIABLE
Freshness score (0-100) = recency(40) + corroboration(30) + consistency(30)
This is a transparent heuristic, not ground truth. Say so in the pitch.
"""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from tavily import AsyncTavilyClient

from .trace import TraceStore

TRUSTED_DOMAINS = [
    "nvd.nist.gov", "cve.org", "github.com", "cisa.gov", "osv.dev",
    "security.snyk.io", "pypi.org", "access.redhat.com", "ubuntu.com",
]
FIX_RE = re.compile(
    r"(?i)(?:fixed|patched|resolved)\s+in\s+(?:version\s+)?v?([0-9][\w.\-]*)"
    r"|upgrade\s+to\s+(?:version\s+)?v?([0-9][\w.\-]*)"
)
WITHDRAWN_RE = re.compile(r"(?i)\b(rejected|withdrawn|disputed)\b")
CVSS_RE = re.compile(r"(?i)cvss[^0-9]{0,25}(\d{1,2}\.\d)")
UNPATCHED_CLAIM_RE = re.compile(
    r"(?i)no (?:known )?(?:patch|fix)|unpatched|not (?:yet )?fixed|unfixed|no update available"
)
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def _clean_versions(raw: list[str]) -> list[str]:
    """Strip distro suffixes (5.3.1-1ubuntu0.1 -> 5.3.1), keep only dotted numeric
    versions, dedupe, and sort numerically."""
    out: set[str] = set()
    for v in raw:
        if not v:
            continue
        v = re.split(r"[-+~]", v)[0].rstrip(".")
        if re.fullmatch(r"\d+(\.\d+)+", v):
            out.add(v)
    return sorted(out, key=lambda s: [int(p) for p in s.split(".")])


@dataclass
class Evidence:
    url: str
    title: str
    snippet: str
    published: str | None
    fix_versions: list[str] = field(default_factory=list)
    withdrawn: bool = False
    cvss: float | None = None


@dataclass
class Verdict:
    cve_id: str
    claim: str
    verdict: str
    freshness_score: int
    severity_score: int | None
    severity_label: str
    fix_versions: list[str]
    sources: list[dict[str, Any]]
    degraded: bool = False
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_date(raw: str | None) -> datetime | None:
    if not raw:
        return None
    for fn in (parsedate_to_datetime, lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))):
        try:
            dt = fn(raw)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:  # noqa: BLE001
            continue
    return None


def _severity_label(cvss: float | None) -> str:
    if cvss is None:
        return "UNKNOWN"
    return ("CRITICAL" if cvss >= 9 else "HIGH" if cvss >= 7
            else "MEDIUM" if cvss >= 4 else "LOW")


class ThreatIntel:
    CACHE_TTL_S = 900

    def __init__(self, api_key: str, traces: TraceStore) -> None:
        self.client = AsyncTavilyClient(api_key=api_key)
        self.traces = traces
        self._cache: dict[tuple[str, str], tuple[float, Verdict]] = {}
        self._sem = asyncio.Semaphore(3)         # stay polite on rate limits

    async def verify_claim(self, run_id: str, cve_id: str, claim: str) -> Verdict:
        if not CVE_RE.match(cve_id):
            raise ValueError("invalid CVE id")
        key = (cve_id, claim)
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < self.CACHE_TTL_S:
            self.traces.emit(run_id, "tool_call", "tavily_cache_hit", cve_id=cve_id)
            return hit[1]

        queries = [
            f"{cve_id} fixed version patch advisory",
            f"{cve_id} CVSS severity score",
        ]
        try:
            results = await asyncio.gather(*(self._search(run_id, q) for q in queries))
        except Exception as exc:  # noqa: BLE001
            self.traces.emit(run_id, "tool_call", "tavily_failed", cve_id=cve_id, error=str(exc)[:200])
            return Verdict(cve_id, claim, "UNVERIFIABLE", 0, None, "UNKNOWN", [], [],
                           degraded=True, reasoning="Tavily unavailable; no verification performed.")

        evidence = self._extract_evidence([r for batch in results for r in batch])
        verdict = self._judge(cve_id, claim, evidence)
        self._cache[key] = (time.time(), verdict)
        self.traces.emit(
            run_id, "finding", "claim_verdict",
            cve_id=cve_id, verdict=verdict.verdict,
            freshness=verdict.freshness_score, severity=verdict.severity_label,
        )
        return verdict

    # ------------------------------------------------------------ internals
    async def _search(self, run_id: str, query: str) -> list[dict[str, Any]]:
        async with self._sem:
            t0 = time.perf_counter()
            last: Exception | None = None
            for attempt in range(2):
                try:
                    resp = await self.client.search(
                        query=query,
                        search_depth="advanced",
                        max_results=6,
                        include_domains=TRUSTED_DOMAINS,
                        include_answer=False,
                    )
                    items = resp.get("results", [])
                    self.traces.emit(
                        run_id, "tool_call", "tavily_search", query=query,
                        results=len(items), latency_ms=int((time.perf_counter() - t0) * 1000),
                    )
                    return items
                except Exception as exc:  # noqa: BLE001
                    last = exc
                    await asyncio.sleep(0.6 * (attempt + 1))
            assert last is not None
            raise last

    @staticmethod
    def _extract_evidence(items: list[dict[str, Any]]) -> list[Evidence]:
        seen, out = set(), []
        for it in items:
            url = it.get("url", "")
            if not url or url in seen:
                continue
            seen.add(url)
            text = f"{it.get('title', '')} {it.get('content', '')}"
            fixes = _clean_versions([a or b for a, b in FIX_RE.findall(text)])
            cvss_vals = [float(x) for x in CVSS_RE.findall(text) if float(x) <= 10]
            out.append(Evidence(
                url=url, title=it.get("title", "")[:120], snippet=it.get("content", "")[:280],
                published=it.get("published_date"),
                fix_versions=fixes, withdrawn=bool(WITHDRAWN_RE.search(text)),
                cvss=max(cvss_vals) if cvss_vals else None,
            ))
        return out

    @staticmethod
    def _judge(cve_id: str, claim: str, ev: list[Evidence]) -> Verdict:
        fixes = _clean_versions([v for e in ev for v in e.fix_versions])
        cvss = max((e.cvss for e in ev if e.cvss is not None), default=None)
        withdrawn = any(e.withdrawn for e in ev)
        claims_unpatched = bool(UNPATCHED_CLAIM_RE.search(claim))

        if not ev:
            verdict, consistency, why = "UNVERIFIABLE", 15, "No trusted-source evidence found."
        elif withdrawn and re.search(r"(?i)exploit|vulnerab|critical", claim):
            verdict, consistency, why = "REVOKED", 0, "Sources mark this advisory rejected/withdrawn/disputed."
        elif claims_unpatched and fixes:
            verdict, consistency, why = (
                "STALE_CONTRADICTED", 0,
                "Claim says unpatched, but trusted sources report fixes "
                f"(versions mentioned: {', '.join(fixes[:3])}; may be distro backports).",
            )
        else:
            verdict, consistency, why = "CONFIRMED", 30, "Evidence is consistent with the claim."

        dates = [d for d in (_parse_date(e.published) for e in ev) if d]
        if dates:
            age_days = (datetime.now(timezone.utc) - max(dates)).days
            recency = 40 if age_days <= 180 else 30 if age_days <= 730 else 10
        else:
            recency = 20
        corroboration = min(len({e.url.split('/')[2] for e in ev if e.url.count('/') >= 2}), 3) * 10
        score = recency + corroboration + consistency

        return Verdict(
            cve_id=cve_id, claim=claim, verdict=verdict, freshness_score=score,
            severity_score=int(cvss * 10) if cvss is not None else None,
            severity_label=_severity_label(cvss), fix_versions=fixes,
            sources=[{"url": e.url, "title": e.title, "published": e.published} for e in ev[:5]],
            reasoning=why,
        )