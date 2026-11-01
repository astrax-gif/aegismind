"""Bifrost gateway wrapper.

Responsibilities
  * Zero-trust routing: sensitive payloads -> LOCAL only (fail closed).
  * Cloud route through Bifrost with provider-level `fallbacks`.
  * Route-level failover (cloud -> local) for NON-sensitive traffic.
  * Circuit breaker per route, per-run + global budget enforcement.
  * Full telemetry (never logs prompt content).

ASSUMPTIONS to verify against current Bifrost docs:
  POST {base}/openai/v1/chat/completions, model = "provider/model",
  `fallbacks` list in body, `x-bf-vk` virtual-key header.
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx

from .config import Settings
from .sensitivity import DataClass, classify
from .trace import TraceStore

# USD per 1M tokens (input, output). Approximate -- Bifrost's dashboard is the
# source of truth; this powers the live UI estimate only.
PRICE_TABLE: dict[str, tuple[float, float]] = {
    "openai/gpt-4o-mini": (0.15, 0.60),
    "anthropic/claude-3-5-haiku-latest": (0.80, 4.00),
}
DEFAULT_PRICE = (1.00, 3.00)


class Route(str, Enum):
    CLOUD = "cloud"
    LOCAL = "local"


class PolicyViolation(RuntimeError):
    """Raised when a request would break the zero-trust policy."""


class BudgetExceeded(RuntimeError):
    pass


class AllRoutesFailed(RuntimeError):
    pass


@dataclass
class ChatResult:
    text: str
    route: Route
    model: str
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    latency_ms: int
    failover_used: bool
    attempts: list[dict[str, Any]] = field(default_factory=list)


class CircuitBreaker:
    def __init__(self, threshold: int, cooldown_s: float) -> None:
        self.threshold, self.cooldown_s = threshold, cooldown_s
        self.failures = 0
        self.opened_at: float | None = None

    @property
    def state(self) -> str:
        if self.opened_at is None:
            return "closed"
        return "half_open" if time.monotonic() - self.opened_at >= self.cooldown_s else "open"

    def allow(self) -> bool:
        return self.state != "open"

    def success(self) -> None:
        self.failures, self.opened_at = 0, None

    def failure(self) -> None:
        self.failures += 1
        if self.failures >= self.threshold or self.state == "half_open":
            self.opened_at = time.monotonic()


class BudgetTracker:
    def __init__(self, per_run: float, global_cap: float) -> None:
        self.per_run, self.global_cap = per_run, global_cap
        self.run_spend: dict[str, float] = {}
        self.total = 0.0

    def exhausted(self, run_id: str) -> bool:
        return self.run_spend.get(run_id, 0.0) >= self.per_run or self.total >= self.global_cap

    def add(self, run_id: str, usd: float) -> None:
        self.run_spend[run_id] = self.run_spend.get(run_id, 0.0) + usd
        self.total += usd


class BifrostClient:
    def __init__(self, settings: Settings, traces: TraceStore) -> None:
        self.s, self.traces = settings, traces
        headers = {"Content-Type": "application/json"}
        if settings.bifrost_virtual_key:
            headers["x-bf-vk"] = settings.bifrost_virtual_key
        self._http = httpx.AsyncClient(
            base_url=settings.bifrost_base_url.rstrip("/"),
            headers=headers,
            timeout=settings.request_timeout_s,
        )
        self.breakers = {
            r: CircuitBreaker(settings.breaker_failure_threshold, settings.breaker_cooldown_s)
            for r in Route
        }
        self.budget = BudgetTracker(settings.run_budget_usd, settings.global_budget_usd)
        self.chaos_cloud_failure_rate = settings.chaos_cloud_failure_rate
        self.route_counts = {r.value: 0 for r in Route}
        self.tokens = {"prompt": 0, "completion": 0}
        self.failovers = 0

    async def aclose(self) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------ API
    async def chat(
        self,
        messages: list[dict[str, str]],
        *,
        run_id: str,
        purpose: str,
        data_class: DataClass = "public",
        max_tokens: int = 700,
        temperature: float = 0.2,
    ) -> ChatResult:
        joined = "\n".join(m["content"] for m in messages)
        sens = classify(joined, data_class)

        if sens.sensitive:
            candidates = [Route.LOCAL]               # fail closed: never cloud
            self.traces.emit(
                run_id, "policy", "route_locked_local",
                purpose=purpose, reasons=list(sens.reasons),
            )
        else:
            candidates = [Route.CLOUD, Route.LOCAL]

        attempts: list[dict[str, Any]] = []
        for idx, route in enumerate(candidates):
            skip = self._skip_reason(route, run_id)
            if skip:
                attempts.append({"route": route.value, "skipped": skip})
                self.traces.emit(run_id, "policy", "route_skipped",
                                 route=route.value, reason=skip, purpose=purpose)
                continue
            try:
                result = await self._call_with_retry(
                    route, messages, max_tokens, temperature, run_id, purpose
                )
            except Exception as exc:  # noqa: BLE001 - recorded, then fail over
                self.breakers[route].failure()
                attempts.append({"route": route.value, "error": type(exc).__name__})
                self.traces.emit(run_id, "policy", "route_failed",
                                 route=route.value, error=str(exc)[:200], purpose=purpose)
                continue

            self.breakers[route].success()
            result.failover_used = idx > 0 or any("skipped" in a or "error" in a for a in attempts)
            result.attempts = attempts
            if result.failover_used:
                self.failovers += 1
            self._record(run_id, purpose, result, sens.reasons)
            return result

        raise AllRoutesFailed(
            f"No route available for '{purpose}'"
            + (" (sensitive: cloud fallback forbidden)" if sens.sensitive else "")
            + f": {attempts}"
        )

    def metrics(self) -> dict[str, Any]:
        return {
            "routes": self.route_counts,
            "tokens": self.tokens,
            "failovers": self.failovers,
            "spend_usd": round(self.budget.total, 6),
            "global_budget_usd": self.budget.global_cap,
            "breakers": {r.value: b.state for r, b in self.breakers.items()},
            "chaos_cloud_failure_rate": self.chaos_cloud_failure_rate,
        }

    # ------------------------------------------------------------- internals
    def _skip_reason(self, route: Route, run_id: str) -> str | None:
        if not self.breakers[route].allow():
            return "circuit_open"
        if route is Route.CLOUD and self.budget.exhausted(run_id):
            return "budget_exhausted"
        return None

    async def _call_with_retry(self, route, messages, max_tokens, temperature, run_id, purpose):
        last: Exception | None = None
        for attempt in range(self.s.max_retries + 1):
            try:
                return await self._call(route, messages, max_tokens, temperature)
            except httpx.HTTPStatusError as exc:
                last = exc
                if exc.response.status_code not in (429, 500, 502, 503, 504):
                    raise
            except (httpx.TransportError, httpx.TimeoutException) as exc:
                last = exc
            await asyncio.sleep(0.4 * (2 ** attempt) + random.random() * 0.2)
        assert last is not None
        raise last

    async def _call(self, route: Route, messages, max_tokens, temperature) -> ChatResult:
        if route is Route.CLOUD and random.random() < self.chaos_cloud_failure_rate:
            raise httpx.ConnectError("chaos: simulated cloud outage")

        model = self.s.cloud_model if route is Route.CLOUD else self.s.local_model
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if route is Route.CLOUD and self.s.cloud_fallbacks:
            body["fallbacks"] = self.s.cloud_fallbacks      # provider-level failover in Bifrost

        t0 = time.perf_counter()
        resp = await self._http.post("/openai/v1/chat/completions", json=body)
        resp.raise_for_status()
        data = resp.json()
        latency_ms = int((time.perf_counter() - t0) * 1000)

        text = data["choices"][0]["message"]["content"] or ""
        usage = data.get("usage") or {}
        pt, ct = int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0))
        served_model = data.get("model", model)

        if route is Route.LOCAL:
            cost = 0.0
        else:
            pin, pout = PRICE_TABLE.get(model, DEFAULT_PRICE)
            cost = (pt * pin + ct * pout) / 1_000_000

        return ChatResult(text, route, served_model, pt, ct, cost, latency_ms, False)

    def _record(self, run_id, purpose, r: ChatResult, reasons) -> None:
        self.budget.add(run_id, r.cost_usd)
        self.route_counts[r.route.value] += 1
        self.tokens["prompt"] += r.prompt_tokens
        self.tokens["completion"] += r.completion_tokens
        self.traces.emit(
            run_id, "llm_call", purpose,
            route=r.route.value, model=r.model,
            prompt_tokens=r.prompt_tokens, completion_tokens=r.completion_tokens,
            cost_usd=round(r.cost_usd, 6), latency_ms=r.latency_ms,
            failover=r.failover_used, sensitivity=list(reasons),   # reasons only, never content
            run_spend_usd=round(self.budget.run_spend.get(run_id, 0.0), 6),
        )