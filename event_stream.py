"""
event_stream.py
---------------
Lightweight stream processor.

Receives events from RealtimeSimulator → calls detection pipeline
directly (NO HTTP round-trip) → stores results in a bounded in-memory
queue → exposes results via Server-Sent Events (SSE) to the dashboard.

Flow:
  RealtimeSimulator
      └─► event_stream.process(txn)
              ├─► InferenceEngine.analyze(txn)   [direct call]
              ├─► DecisionEngine.decide(result)
              ├─► kg.flag_nodes(...)
              ├─► regenerate_visualizations(kg)
              └─► _result_queue.append(event)     [for SSE]
"""
from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from typing import Optional

from logger import get_logger

logger = get_logger(__name__)

# Bounded result queue — keeps last N events in memory
_QUEUE_MAXLEN = 200
_result_queue: deque[dict] = deque(maxlen=_QUEUE_MAXLEN)

# Stats counters
_stats: dict[str, int] = {
    "total_processed": 0,
    "total_fraud":     0,
    "total_suspicious":0,
    "total_safe":      0,
}


class EventStream:
    """
    Connects the simulator to the existing detection pipeline.
    One instance is created at startup and shared across the app.

    Args:
        inference_engine:  Existing InferenceEngine instance.
        decision_engine:   Existing DecisionEngine instance.
        kg:                The live KnowledgeGraph instance.
        output_dir:        Where visualizer saves PNG/HTML.
        viz_every:         Regenerate visualisation every N events (perf control).
    """

    def __init__(
        self,
        inference_engine,   # InferenceEngine — avoid circular import
        decision_engine,    # DecisionEngine
        kg,                 # KnowledgeGraph
        output_dir: str,
        viz_every: int = 5,
    ) -> None:
        self._inf        = inference_engine
        self._dec        = decision_engine
        self._kg         = kg
        self._output_dir = output_dir
        self._viz_every  = max(1, viz_every)
        self._since_viz  = 0
        self._lock       = __import__("threading").Lock()

        # Import here to avoid circular imports at module level
        from visualizer import regenerate_visualizations
        self._regen = regenerate_visualizations

    # ── main entry point called by simulator callback ──────────────────────────

    def process(self, txn: dict) -> None:
        """
        Process one transaction event from the simulator.
        Called from the simulator's background thread — must be thread-safe.
        """
        with self._lock:
            try:
                self._run_pipeline(txn)
            except Exception as exc:
                logger.error(f"EventStream.process error: {exc}")

    # ── internal ───────────────────────────────────────────────────────────────

    def _run_pipeline(self, txn: dict) -> None:
        t0  = time.perf_counter()

        # 1. Inference (adds txn to graph internally)
        inf = self._inf.analyze(txn)

        # 2. Decision
        dec = self._dec.decide(inf)

        # 3. Update stats
        _stats["total_processed"] += 1
        label = dec.label
        if label == "Fraud":
            _stats["total_fraud"]      += 1
        elif label == "Suspicious":
            _stats["total_suspicious"] += 1
        else:
            _stats["total_safe"]       += 1

        # 4. Conditionally regenerate visualisation (expensive — throttled)
        self._since_viz += 1
        if self._since_viz >= self._viz_every:
            self._regen(
                self._kg,
                output_dir=self._output_dir,
                focus_node=txn.get("Transaction ID")   # 🔥 THIS IS THE FIX
            )
            self._since_viz = 0

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

        # 5. Push to SSE queue
        event = _build_event(txn, inf, dec, elapsed_ms)
        _result_queue.append(event)

        if label != "Safe":
            logger.info(
                f"[STREAM] {txn.get('Transaction ID','?')} → "
                f"{label} score={dec.risk_score} ({elapsed_ms}ms)"
            )

    # ── configuration hot-reload ───────────────────────────────────────────────

    def set_viz_every(self, n: int) -> None:
        """Change visualisation throttle at runtime."""
        with self._lock:
            self._viz_every = max(1, n)


# ── SSE queue accessors ────────────────────────────────────────────────────────

def get_recent_events(n: int = 50) -> list[dict]:
    """Return the last n processed events (newest first)."""
    items = list(_result_queue)
    return list(reversed(items))[:n]


def get_stream_stats() -> dict:
    return dict(_stats)


def clear_queue() -> None:
    _result_queue.clear()


# ── SSE async generator ────────────────────────────────────────────────────────

async def sse_event_generator(poll_interval: float = 0.5):
    """
    Async generator for FastAPI SSE endpoint.
    Yields new events as they arrive in the queue.

    Usage in app.py:
        from sse_starlette.sse import EventSourceResponse
        @app.get("/stream")
        async def stream():
            return EventSourceResponse(sse_event_generator())
    """
    last_seen = 0
    while True:
        current_len = len(_result_queue)
        if current_len > last_seen:
            new_items = list(_result_queue)[last_seen:current_len]
            for item in new_items:
                yield {
                    "event": item.get("decision", "update").lower(),
                    "data":  json.dumps(item),
                }
            last_seen = current_len
        await asyncio.sleep(poll_interval)


# ── helpers ────────────────────────────────────────────────────────────────────

def _build_event(txn: dict, inf, dec, elapsed_ms: float) -> dict:
    """Flatten inference + decision into a single SSE-safe dict."""
    return {
        "transaction_id":  inf.transaction_id,
        "customer_id":     inf.customer_id,
        "ip_address":      str(txn.get("IP Address", "")),
        "device":          str(txn.get("Device Used", "")),
        "amount":          float(txn.get("Transaction Amount", 0)),
        "timestamp":       str(txn.get("Transaction Date", "")),
        "location":        str(txn.get("Customer Location", "")),
        "pattern":         str(txn.get("_pattern", "normal")),
        "velocity_count":  int(txn.get("_velocity_count", 1)),
        "risk_score":      round(dec.risk_score, 1),
        "decision":        dec.label,
        "explanation":     dec.explanation,
        "rules_triggered": [r.rule_name for r in dec.triggered_rules],
        "elapsed_ms":      elapsed_ms,
        "graph_html_url":  "/graph",
        "graph_png_url":   "/graph/png",
    }