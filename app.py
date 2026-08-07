"""
app.py
------
FastAPI application — Knowledge Graph Cyber Threat Detection.
ADDITIONS vs original:
  • RealtimeSimulator started in lifespan (background thread)
  • EventStream wires simulator → detection pipeline directly
  • GET /stream        → Server-Sent Events feed
  • GET /stream/stats  → live counters
  • GET /stream/config → hot-change simulation speed
"""
from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from propagation_engine import RiskPropagationEngine
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from dataset_generator   import ensure_dataset
from graph_engine        import KnowledgeGraph, load_graph_from_csv
from inference_engine    import InferenceEngine
from decision_engine     import DecisionEngine, LABEL_SUSPICIOUS, LABEL_FRAUD
from visualizer          import regenerate_visualizations
from logger              import get_logger
from fraud_story_engine import FraudStoryEngine

# ── NEW IMPORTS ───────────────────────────────────────────────────────────────
from realtime_simulator  import RealtimeSimulator
from event_stream        import EventStream, get_recent_events, get_stream_stats, sse_event_generator

logger = get_logger(__name__)

# ── shared singletons ─────────────────────────────────────────────────────────
kg:        KnowledgeGraph            = KnowledgeGraph()
inf_eng:   Optional[InferenceEngine] = None
dec_eng:   Optional[DecisionEngine]  = None
simulator: Optional[RealtimeSimulator] = None   # NEW
stream:    Optional[EventStream]       = None   # NEW


@asynccontextmanager
async def lifespan(app: FastAPI):
    global kg, inf_eng, dec_eng, simulator, stream

    # 1. Dataset
    csv_path = ensure_dataset()

    # 2. Knowledge graph
    app.state.kg = load_graph_from_csv(csv_path, max_rows=300)
    kg = app.state.kg

    # 3. Seed flagged nodes from historical labels
    for node, data in kg.graph.nodes(data=True):
        if data.get("known_fraud", 0):
            kg.flag_nodes([node])

    # 4. Engines
    inf_eng = InferenceEngine(kg)
    dec_eng = DecisionEngine()

    # 5. Initial visualisation
    regenerate_visualizations(kg=kg, output_dir=BASE_DIR)

    # ── NEW: start real-time simulation ──────────────────────────────────────
    stream = EventStream(
        inference_engine=inf_eng,
        decision_engine=dec_eng,
        kg=kg,
        output_dir=BASE_DIR,
        viz_every=5,          # regenerate graph every 3 seconds
    )
    simulator = RealtimeSimulator(
        events_per_second=0.2,  # 1 transaction per second by default
        num_users=25,
    )
    # simulator.start(callback=stream.process)
    # ─────────────────────────────────────────────────────────────────────────

    logger.info(f"System ready. {kg.stats()}")
    yield

    # Shutdown
    if simulator:
        simulator.stop()
    logger.info("Shutting down.")


# ── app setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Knowledge Graph Cyber Threat Detection",
    description="Live fraud detection with real-time event simulation.",
    version="3.0.0",
    lifespan=lifespan,
)

app.add_middleware(CORSMiddleware,
                   allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class CSPFixMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;"
        )
        return response

app.add_middleware(CSPFixMiddleware)


# ── Pydantic schemas (UNCHANGED) ──────────────────────────────────────────────

class TransactionIn(BaseModel):
    model_config = {"populate_by_name": True}
    transaction_id:     str   = Field(..., json_schema_extra={"example": "TXN-99999"})
    customer_id:        str   = Field(..., json_schema_extra={"example": "CUST_1042"})
    ip_address:         str   = Field(..., json_schema_extra={"example": "192.168.1.10"})
    device_used:        str   = Field(..., json_schema_extra={"example": "mobile_4321"})
    transaction_amount: float = Field(..., json_schema_extra={"example": 4500.0})
    transaction_date:   str   = Field(..., json_schema_extra={"example": "2024-06-15 02:15:00"})
    payment_method:     str   = Field(default="credit card")
    product_category:   str   = Field(default="electronics")
    quantity:           int   = Field(default=1)
    customer_age:       int   = Field(default=30)
    customer_location:  str   = Field(default="Unknown")
    account_age_days:   int   = Field(default=365)
    transaction_hour:   int   = Field(default=12)
    is_fraudulent:      int   = Field(default=0)


class RuleOut(BaseModel):
    rule: str; triggered: bool; score_contribution: float; reason: str


class DetectOut(BaseModel):
    transaction_id: str;  customer_id: str;  risk_score: float
    decision: str;        explanation: str
    triggered_rules: list[RuleOut]
    graph_png_url: str;   graph_html_url: str
    fraud_story: Optional[str] = None
    risk_propagation: Optional[list[dict]] = None


class StatsOut(BaseModel):
    total_nodes: int; total_edges: int; customers: int
    ips: int;         devices: int;     transactions: int; flagged: int


# ── original endpoints (UNCHANGED signatures) ─────────────────────────────────

@app.get("/health", tags=["System"])
def health() -> dict:
    return {"status": "healthy", "version": "3.0.0"}


@app.get("/graph", tags=["Graph"])
def serve_graph():
    return FileResponse(os.path.join(BASE_DIR, "knowledge_graph_interactive.html"))


@app.get("/graph/png", tags=["Graph"])
def serve_graph_png():
    return FileResponse(os.path.join(BASE_DIR, "knowledge_graph.png"))


@app.get("/graph/stats", response_model=StatsOut, tags=["Graph"])
def graph_stats() -> StatsOut:
    s = kg.stats()
    return StatsOut(**s, flagged=len(kg.flagged_nodes))


@app.get("/graph/refresh", tags=["Graph"])
def graph_refresh() -> dict:
    paths = regenerate_visualizations(kg, output_dir=BASE_DIR)
    return {"status": "refreshed", "files": paths}


@app.post("/detect", response_model=DetectOut, tags=["Detection"])
def detect(txn_in: TransactionIn) -> DetectOut:
    if inf_eng is None or dec_eng is None:
        raise HTTPException(503, "Engines not initialised.")

    _kg = app.state.kg   # always use the single shared instance
    
    txn: dict = {
        "Transaction ID":     txn_in.transaction_id,
        "Customer ID":        txn_in.customer_id,
        "IP Address":         txn_in.ip_address,
        "Device Used":        txn_in.device_used,
        "Transaction Amount": txn_in.transaction_amount,
        "Transaction Date":   txn_in.transaction_date,
        "Payment Method":     txn_in.payment_method,
        "Product Category":   txn_in.product_category,
        "Quantity":           txn_in.quantity,
        "Customer Age":       txn_in.customer_age,
        "Customer Location":  txn_in.customer_location,
        "Account Age Days":   txn_in.account_age_days,
        "Transaction Hour":   txn_in.transaction_hour,
        "Is Fraudulent":      txn_in.is_fraudulent,
        
        
    }

    inf = inf_eng.analyze(txn)
    dec = dec_eng.decide(inf)
    # 🔥 Initialize story engine
    # story_engine = FraudStoryEngine(kg.graph)
    story_engine = FraudStoryEngine(_kg.graph)

    # 🔥 Extract rule names
    # triggered_rules = [r.rule_name for r in inf.triggered_rules]
    triggered_rules = [r.to_dict()["rule"] for r in inf.triggered_rules]

    # 🔥 Generate story
    fraud_story = story_engine.reconstruct_story(
        transaction_id=inf.transaction_id,
        triggered_rules=triggered_rules,
        device=txn_in.device_used,
        ip=txn_in.ip_address   
    )
    # 🔥 Risk Propagation
    prop_engine = RiskPropagationEngine(_kg.graph)

    risk_propagation = prop_engine.propagate(
        start_customer=dec.customer_id
    )
    # extract risky nodes
    risky_nodes = risk_propagation

    regenerate_visualizations(
        kg=_kg,
        output_dir=BASE_DIR,
        focus_node=txn_in.transaction_id,
        highlight_nodes=risky_nodes   # ✅ NEW
    )

    return DetectOut(
        transaction_id  = dec.transaction_id,
        customer_id     = dec.customer_id,
        risk_score      = dec.risk_score,
        decision        = dec.label,
        "final_action": dec.final_action,
        explanation     = dec.explanation,
        triggered_rules = [RuleOut(**r.to_dict()) for r in dec.triggered_rules],
        graph_png_url   = "/graph/png",
        graph_html_url  = "/graph",
        fraud_story     = fraud_story,
        risk_propagation = risk_propagation 
    )


# ── NEW endpoints ─────────────────────────────────────────────────────────────

@app.get("/stream", tags=["Realtime"])
async def stream_events():
    """
    Server-Sent Events feed — subscribe from the dashboard with:
        const es = new EventSource('/stream');
        es.onmessage = e => console.log(JSON.parse(e.data));
    """
    try:
        from sse_starlette.sse import EventSourceResponse  # type: ignore
        return EventSourceResponse(sse_event_generator(poll_interval=0.4))
    except ImportError:
        # Fallback: return latest events as plain JSON if sse_starlette missing
        return get_recent_events(50)


@app.get("/stream/events", tags=["Realtime"])
def stream_events_json(n: int = Query(default=30, le=200)) -> list[dict]:
    """Latest n processed events as JSON (polling alternative to SSE)."""
    return get_recent_events(n)


@app.get("/stream/stats", tags=["Realtime"])
def stream_stats() -> dict:
    """Live counters: total processed, fraud, suspicious, safe."""
    stats = get_stream_stats()
    stats["simulator_running"] = simulator.is_running if simulator else False
    stats["graph_nodes"]       = kg.graph.number_of_nodes()
    stats["graph_edges"]       = kg.graph.number_of_edges()
    stats["flagged_nodes"]     = len(kg.flagged_nodes)
    return stats


@app.post("/stream/config", tags=["Realtime"])
def stream_config(
    events_per_second: float = Query(default=1.0, ge=0.1, le=20.0),
    viz_every:         int   = Query(default=5,   ge=1,   le=50),
) -> dict:
    """Hot-change simulation speed and visualisation throttle."""
    if simulator:
        simulator.update_speed(events_per_second)
    if stream:
        stream.set_viz_every(viz_every)
    return {
        "events_per_second": events_per_second,
        "viz_every":         viz_every,
        "status":            "updated",
    }


@app.get("/stream/pause", tags=["Realtime"])
def stream_pause() -> dict:
    """Pause simulation (set speed to minimum)."""
    if simulator:
        simulator.update_speed(0.1)
    return {"status": "paused"}


@app.get("/stream/resume", tags=["Realtime"])
def stream_resume() -> dict:
    """Resume simulation at default speed."""
    if simulator:
        simulator.update_speed(1.0)
    return {"status": "resumed"}


@app.get("/", tags=["UI"])
def serve_ui():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))