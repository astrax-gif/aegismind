"""Scan orchestration over an ALLOWLISTED demo lab (no live-target scanning)."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from .bifrost_client import AllRoutesFailed, BifrostClient
from .tavily_agent import ThreatIntel
from .trace import TraceStore

REVIEW_SYSTEM = (
    "You are a defensive application-security reviewer. Identify vulnerabilities in the "
    "supplied code and give remediation advice. Do NOT write exploit code. Return a concise "
    "bullet list: issue, line hint, severity, fix."
)
BRIEF_SYSTEM = (
    "You write 60-second executive security war-room briefings: ~150 words, plain spoken "
    "English, no markdown, lead with the single most urgent action."
)


async def run_scan(
    run_id: str, lab_dir: Path, bf: BifrostClient, intel: ThreatIntel,
    traces: TraceStore, runs: dict[str, dict[str, Any]],
) -> None:
    runs[run_id] = {"status": "running", "lab": lab_dir.name}
    traces.emit(run_id, "run", "started", lab=lab_dir.name)
    try:
        advisories = json.loads((lab_dir / "advisories.json").read_text())
        source = (lab_dir / "app.py").read_text()

        # 1) Private code review -> must stay local (declared + heuristic).
        review_task = asyncio.create_task(bf.chat(
            [{"role": "system", "content": REVIEW_SYSTEM},
             {"role": "user", "content": f"Review this code:\n\n{source}"}],
            run_id=run_id, purpose="private_code_review", data_class="private_code",
            max_tokens=900,
        ))

        # 2) Stale-claim verification against live web via Tavily (parallel).
        verdict_tasks = [intel.verify_claim(run_id, a["cve_id"], a["claim"]) for a in advisories]
        verdicts, review = await asyncio.gather(
            asyncio.gather(*verdict_tasks), review_task, return_exceptions=True
        )
        if isinstance(verdicts, Exception):
            raise verdicts
        review_text = (review.text if not isinstance(review, Exception)
                       else f"[code review unavailable: {type(review).__name__}]")
        if isinstance(review, AllRoutesFailed):
            traces.emit(run_id, "policy", "sensitive_call_blocked",
                        note="Local model down; cloud fallback forbidden by policy.")

        findings = [v.to_dict() for v in verdicts]
        stale = [f for f in findings if f["verdict"] == "STALE_CONTRADICTED"]

        # 3) Aggregates-only summary may use cloud. No code-derived text crosses the boundary.
        agg = "\n".join(
            f"- {f['cve_id']}: {f['verdict']}, severity {f['severity_label']}, "
            f"freshness {f['freshness_score']}/100, fixes {f['fix_versions'][:2]}"
            for f in findings
        )
        summary = await bf.chat(
            [{"role": "system", "content": "You are a concise security analyst."},
             {"role": "user", "content": f"Summarize risk in 3 sentences:\n{agg}"}],
            run_id=run_id, purpose="executive_summary", max_tokens=250,
        )

        runs[run_id].update(
            status="completed", findings=findings, stale_count=len(stale),
            code_review=review_text, summary=summary.text,
            aggregates=agg,                                  # safe input for the briefing
            spend_usd=round(bf.budget.run_spend.get(run_id, 0.0), 6),
        )
        traces.emit(run_id, "run", "completed", findings=len(findings), stale=len(stale))
    except Exception as exc:  # noqa: BLE001
        runs[run_id].update(status="failed", error=str(exc)[:300])
        traces.emit(run_id, "run", "failed", error=str(exc)[:300])


async def build_briefing(run_id: str, run: dict[str, Any], bf: BifrostClient) -> str:
    res = await bf.chat(
        [{"role": "system", "content": BRIEF_SYSTEM},
         {"role": "user", "content": f"Lab: {run['lab']}\nStale advisories: {run['stale_count']}\n"
                                     f"Findings:\n{run['aggregates']}"}],
        run_id=run_id, purpose="war_room_briefing", max_tokens=320, temperature=0.3,
    )
    return res.text