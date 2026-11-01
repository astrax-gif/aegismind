import asyncio
import json
import re
import uuid
from contextlib import asynccontextmanager
from dataclasses import asdict

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .bifrost_client import BifrostClient
from .config import get_settings
from .pipeline import build_briefing, run_scan
from .tavily_agent import ThreatIntel
from .trace import TraceStore


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    app.state.traces = TraceStore()
    app.state.bifrost = BifrostClient(s, app.state.traces)
    app.state.intel = ThreatIntel(s.tavily_api_key, app.state.traces)
    app.state.runs = {}
    app.state.tasks = set()          # keep refs so tasks aren't garbage-collected
    app.state.labs = {p.name: p for p in s.demo_dir.iterdir() if p.is_dir()} if s.demo_dir.exists() else {}
    yield
    await app.state.bifrost.aclose()


app = FastAPI(title="AegisMind AI", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware, allow_origins=["http://localhost:5173"],
    allow_methods=["*"], allow_headers=["*"],
)


class ScanRequest(BaseModel):
    lab: str = Field(min_length=1, max_length=64)


class VerifyRequest(BaseModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,7}$")
    claim: str = Field(min_length=3, max_length=500)


class ChaosRequest(BaseModel):
    cloud_failure_rate: float = Field(ge=0.0, le=1.0)


@app.get("/api/health")
async def health(request: Request):
    return {"ok": True, "labs": sorted(request.app.state.labs), "gateway": request.app.state.bifrost.metrics()}


@app.get("/api/labs")
async def labs(request: Request):
    return sorted(request.app.state.labs)


@app.post("/api/scan", status_code=202)
async def start_scan(body: ScanRequest, request: Request):
    st = request.app.state
    lab_dir = st.labs.get(body.lab)           # allowlist lookup: no user-supplied paths, no live targets
    if lab_dir is None:
        raise HTTPException(400, f"Unknown lab. Allowed: {sorted(st.labs)}")
    run_id = uuid.uuid4().hex[:12]
    task = asyncio.create_task(run_scan(run_id, lab_dir, st.bifrost, st.intel, st.traces, st.runs))
    st.tasks.add(task)
    task.add_done_callback(st.tasks.discard)
    return {"run_id": run_id}


@app.get("/api/runs/{run_id}")
async def get_run(run_id: str, request: Request):
    st = request.app.state
    run = st.runs.get(run_id)
    if not run:
        raise HTTPException(404, "run not found")
    return {**run, "trace": st.traces.history(run_id)}


@app.get("/api/runs/{run_id}/stream")
async def stream_run(run_id: str, request: Request):
    traces: TraceStore = request.app.state.traces

    async def gen():
        q = traces.subscribe(run_id)                       # subscribe BEFORE replay: no gap
        seen = -1
        try:
            for ev in traces.history(run_id):
                seen = ev["seq"]
                yield f"data: {json.dumps(ev)}\n\n"
                if traces.is_terminal(ev):
                    return
            while True:
                if await request.is_disconnected():
                    return
                try:
                    ev = asdict(await asyncio.wait_for(q.get(), timeout=15))
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                if ev["seq"] <= seen:
                    continue
                seen = ev["seq"]
                yield f"data: {json.dumps(ev)}\n\n"
                if traces.is_terminal(ev):
                    return
        finally:
            traces.unsubscribe(run_id, q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/verify")
async def verify(body: VerifyRequest, request: Request):
    st = request.app.state
    run_id = f"verify-{uuid.uuid4().hex[:8]}"
    v = await st.intel.verify_claim(run_id, body.cve_id, body.claim)
    return {"run_id": run_id, **v.to_dict()}


@app.get("/api/briefing/{run_id}")
async def briefing(run_id: str, request: Request):
    st = request.app.state
    run = st.runs.get(run_id)
    if not run or run.get("status") != "completed":
        raise HTTPException(409, "run not completed")
    script = run.get("briefing_script") or await build_briefing(run_id, run, st.bifrost)
    run["briefing_script"] = script
    # audio_url is filled in Step 3 (voice.py: smallest.ai / Omnidimension, with browser TTS fallback)
    return {"run_id": run_id, "script": script, "word_count": len(script.split()), "audio_url": None}


@app.get("/api/metrics")
async def metrics(request: Request):
    return request.app.state.bifrost.metrics()


@app.post("/api/chaos")
async def chaos(body: ChaosRequest, request: Request):
    request.app.state.bifrost.chaos_cloud_failure_rate = body.cloud_failure_rate
    return {"chaos_cloud_failure_rate": body.cloud_failure_rate}