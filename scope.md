# ThreatGraph — Scope & Implementation Plan

**Document version:** 1.0  
**Date:** 2026-08-17  
**Status:** Planning — awaiting approval before code changes

---

## 1. Project Purpose

ThreatGraph is a **Knowledge Graph-Based E-Commerce Fraud Detection Framework** that models relationships among customers, IP addresses, devices, and transactions as a directed graph (NetworkX). Rule-based inference scores each transaction; a decision engine classifies outcomes as **Safe**, **Suspicious**, or **Fraud**. Results are exposed via a FastAPI REST API and visualized with static (matplotlib) and interactive (PyVis) graph renderings.

The **target evolution** is a web-based **AI + Knowledge Graph Security and Fraud Assessment System** that:

1. Accepts transactions through a web UI
2. Auto-captures client public IP where technically possible
3. Analyzes graph relationships using existing rules
4. Displays fraud decision, risk score, and interactive subgraph
5. Reports six **security assessment dimensions** (Authenticity, Integrity, Confidentiality, Access Control, Security, Non-repudiation)
6. Eventually integrates **SecureBERT** (cybersecurity text analysis) and **Protégé + Pellet/HermiT** (ontology/reasoning)
7. Produces measurable research results

All tooling must remain **free/open-source**. No paid APIs or infrastructure.

---

## 2. Current Architecture

### 2.1 High-Level Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         FastAPI (app.py)                                │
│  Lifespan: dataset → graph → engines → visualizer → EventStream setup   │
└─────────────────────────────────────────────────────────────────────────┘
         │                    │                         │
         ▼                    ▼                         ▼
┌──────────────┐    ┌─────────────────┐    ┌──────────────────────────┐
│ index.html   │    │ POST /detect    │    │ RealtimeSimulator        │
│ (dashboard)  │───▶│ GET /graph/*    │    │ + EventStream (disabled) │
└──────────────┘    │ GET /stream/*   │    └──────────────────────────┘
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         ▼                   ▼                   ▼
┌─────────────────┐  ┌──────────────┐  ┌─────────────────┐
│ InferenceEngine │  │ DecisionEngine│  │ Visualizer      │
│ (inference_     │  │ (decision_    │  │ (PyVis +        │
│  engine.py)     │  │  engine.py)   │  │  matplotlib)    │
└────────┬────────┘  └──────────────┘  └─────────────────┘
         │
         ▼
┌─────────────────┐     ┌──────────────────┐
│ KnowledgeGraph  │◀───▶│ fraud_rules.py   │
│ (graph_engine)  │     │ (7 rule functions)│
└─────────────────┘     └──────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│ NetworkX DiGraph — nodes: customer, ip, device, txn     │
│ Edges: payment, from_ip, uses_device                   │
└─────────────────────────────────────────────────────────┘
```

### 2.2 Module Responsibilities

| Module | Role |
|--------|------|
| `dataset_generator.py` | Loads Kaggle CSV, or generates synthetic `fraud_ecommerce.csv` |
| `graph_engine.py` | NetworkX graph build, CSV ingest, dynamic `add_transaction`, indexes |
| `fraud_rules.py` | 7 pluggable rules → `RuleResult` list |
| `inference_engine.py` | Adds txn to graph, runs rules, aggregates score (cap 100), flags nodes |
| `decision_engine.py` | Thresholds: ≥60 Fraud, ≥30 Suspicious, else Safe; `final_action`: BLOCK/OTP/ALLOW |
| `propagation_engine.py` | 1–2 hop risk propagation from shared device/IP (used in `/detect` only) |
| `fraud_story_engine.py` | Narrative explanation from graph traversal + triggered rules |
| `visualizer.py` | Regenerates `knowledge_graph.png` + `knowledge_graph_interactive.html` |
| `event_stream.py` | In-memory queue + SSE generator; direct pipeline (no HTTP) |
| `realtime_simulator.py` | Background synthetic txn generator (currently **not started**) |
| `app.py` | FastAPI entry, CORS, CSP middleware, all HTTP routes |
| `index.html` | Live dashboard: manual detect, graph iframe, sim controls, event feed |

### 2.3 Data Model (Graph)

**Node types:** `customer`, `ip`, `device`, `transaction`  
**Edge relations:** `payment` (customer→transaction), `from_ip` (customer→ip), `uses_device` (customer→device)

**Transaction input schema** (API `TransactionIn` / internal dict with Kaggle keys):

- `transaction_id`, `customer_id`, `ip_address`, `device_used`, `transaction_amount`
- `transaction_date`, `transaction_hour`, `account_age_days`
- Optional: `payment_method`, `product_category`, `quantity`, `customer_age`, `customer_location`, `is_fraudulent`

---

## 3. Existing Features

### 3.1 Fraud Rules (7)

| Rule | Signal | Score range |
|------|--------|-------------|
| `multi_customer_same_ip` | 2+ customers on same IP | 15–35 |
| `shared_device` | Device used by 2+ customers | 20–35 |
| `velocity_fraud` | 3+ txns in 10 minutes | 20–35 |
| `high_value_outlier` | Amount 4–20×+ customer avg | 8–30 |
| `new_account_high_spend` | Account <20 days + high spend | 12–30 |
| `odd_hour_high_value` | High spend at 00:00–03:59 | 5–15 |
| `known_fraud_customer` | Prior fraud flag on customer node | 40 |

### 3.2 FastAPI Endpoints (Current)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Serves `index.html` dashboard |
| GET | `/health` | Liveness: `{status, version}` |
| POST | `/detect` | Full fraud pipeline + viz refresh |
| GET | `/graph` | Serves interactive PyVis HTML |
| GET | `/graph/png` | Serves static PNG |
| GET | `/graph/stats` | Node/edge/customer/IP/device/txn/flagged counts |
| GET | `/graph/refresh` | Force regenerate PNG + HTML |
| GET | `/stream` | SSE feed (requires `sse-starlette`; fallback JSON) |
| GET | `/stream/events` | Last N events as JSON (polling) |
| GET | `/stream/stats` | Live counters + graph size |
| POST | `/stream/config` | Hot-change sim speed / viz throttle |
| GET | `/stream/pause` | Pause simulation |
| GET | `/stream/resume` | Resume simulation |

### 3.3 `/detect` Response (intended)

```json
{
  "transaction_id": "...",
  "customer_id": "...",
  "risk_score": 75.0,
  "decision": "Fraud",
  "explanation": "...",
  "triggered_rules": [{"rule": "...", "triggered": true, "score_contribution": 25, "reason": "..."}],
  "graph_png_url": "/graph/png",
  "graph_html_url": "/graph",
  "fraud_story": "...",
  "risk_propagation": [{"node": "...", "risk": 75, "reason": "..."}]
}
```

Also computed internally: `final_action` (BLOCK / OTP / ALLOW) — **not currently in response model**.

### 3.4 Frontend (index.html)

- JSON textarea → `POST /detect`
- Displays: transaction ID, customer, risk score, decision, explanation, fraud story
- Embeds `/graph` in iframe; search via `postMessage`
- Polls `/stream/events` and `/stream/stats` (simulator inactive → counters stay at 0)
- Simulation speed/pause controls wired to `/stream/*` endpoints

### 3.5 Tests

- `test_system.py`: 23 pytest tests covering graph engine, individual rules, decision thresholds, end-to-end pipeline
- **No** FastAPI integration tests (`TestClient` / httpx) yet

### 3.6 CLI Demo

- `run_demo.py`: batch-processes CSV rows, prints decisions, generates visualizations

---

## 4. Transaction Data Flow (Detailed)

```
1. Client sends POST /detect {TransactionIn JSON}
        │
2. app.py maps API fields → internal dict (Kaggle column names)
        │
3. InferenceEngine.analyze(txn)
   ├─ Optional location-jump metadata (_location_jump) — tracked in-memory, not a formal rule
   ├─ kg.add_transaction(txn)  [if txn_id not already in graph]
   ├─ evaluate_all_rules(txn, kg)  → 7 RuleResults
   ├─ raw_score = sum(triggered scores); risk_score = min(raw, 100)
   └─ kg.flag_nodes([txn_id, customer_id, ip, device]) if any rule triggered
        │
4. DecisionEngine.decide(inference_result)
   ├─ label: Safe | Suspicious | Fraud (thresholds 30, 60)
   ├─ final_action: ALLOW | OTP | BLOCK (with OTP→ALLOW adjustment if score < 60)
   └─ explanation string from triggered rule names + reasons
        │
5. FraudStoryEngine.reconstruct_story(txn_id, rules, device, ip)
        │
6. RiskPropagationEngine.propagate(start_customer)
   └─ Returns up to 5 related nodes with risk % and reason (shared device/IP/indirect)
        │
7. regenerate_visualizations(kg, focus_node=txn_id, highlight_nodes=risk_propagation)
   └─ Writes knowledge_graph.png + knowledge_graph_interactive.html to disk
        │
8. DetectOut JSON response returned to client
```

**Parallel path (EventStream — when simulator enabled):**

```
RealtimeSimulator._generate() → EventStream.process(txn)
  → same steps 3–7 (throttled viz every N events) → append to in-memory deque → SSE/poll
```

---

## 5. What the Frontend Can Currently Receive

| Source | Data available |
|--------|----------------|
| `POST /detect` | risk_score, decision, explanation, triggered_rules[], graph URLs, fraud_story, risk_propagation[] |
| `GET /graph/stats` | total_nodes, edges, customers, ips, devices, transactions, flagged |
| `GET /graph`, `/graph/png` | Pre-rendered files (not per-request JSON graph) |
| `GET /stream/events` | transaction_id, customer_id, ip, device, amount, decision, risk_score, rules_triggered[], pattern, elapsed_ms |
| `GET /stream/stats` | total_processed, fraud/suspicious/safe counts, graph_nodes, flagged_nodes, simulator_running |

**Not available today:**

- Six security assessment dimensions
- Client IP auto-detection endpoint
- Structured subgraph JSON (nodes/edges) for custom rendering
- `final_action` in API response
- Per-assessment explanations tied to rules/graph
- SecureBERT text analysis output
- Ontology/reasoner-derived inferences

---

## 6. New Target Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     Web UI (enhanced index.html or /static/)             │
│  Transaction form │ Decision panel │ 6-dimension security scores         │
│  Graph iframe OR embedded vis.js subgraph from /graph/subgraph           │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │ REST
┌───────────────────────────────▼──────────────────────────────────────────┐
│                          FastAPI (app.py)                                │
│  /detect (extended)  /client-ip  /assessment/*  /graph/subgraph          │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐    ┌────────────────────┐    ┌─────────────────────┐
│ Existing      │    │ SecurityAssessment │    │ Graph export layer  │
│ fraud pipeline│    │ Engine (NEW)       │    │ (subgraph JSON)     │
└───────────────┘    └────────────────────┘    └─────────────────────┘
        │                       │
        ▼                       ▼
┌───────────────┐    ┌────────────────────┐
│ KnowledgeGraph│    │ (Future) SecureBERT  │
│ (unchanged)   │    │ (Future) OWL/Pellet  │
└───────────────┘    └────────────────────┘
```

**Design principle:** Wrap and extend — do **not** replace `InferenceEngine`, `DecisionEngine`, or `fraud_rules.py`.

---

## 7. Technology Stack

### Current (keep)

| Layer | Technology |
|-------|------------|
| Language | Python 3.10+ |
| API | FastAPI, Uvicorn, Pydantic v2 |
| Graph | NetworkX |
| Visualization | PyVis, matplotlib |
| Testing | pytest, httpx (listed, unused for API) |
| Frontend | Vanilla HTML/CSS/JS (no build step) |

### Planned additions (minimal, OSS only)

| Need | Candidate | Notes |
|------|-----------|-------|
| Client IP | FastAPI `Request.client.host` + `X-Forwarded-For` | Works behind reverse proxy; local dev may show `127.0.0.1` |
| Subgraph API | NetworkX subgraph export → JSON | No new viz library required for MVP |
| Security dimensions | New Python module mapping rules/graph signals → 6 scores | Rule-derived, not ML |
| SSE (optional) | `sse-starlette` | Add to requirements if SSE is desired |
| Future SecureBERT | Hugging Face `transformers` + open model weights | Phase 4+ only |
| Future ontology | `rdflib`, `owlready2`, or export to Protégé | Phase 5+ only |

**Explicitly avoid for MVP:** React/Vue build chains, paid cloud graph DBs, commercial fraud APIs, Neo4j (unless later justified).

---

## 8. Functional Requirements

### FR-1 Transaction submission (Web UI)

- Form fields matching `TransactionIn` (required + common optional fields)
- Submit triggers `POST /detect`
- Display loading/error states

### FR-2 Client IP capture

- Backend endpoint or middleware extracts client IP from request headers
- UI may pre-fill `ip_address` when user leaves field empty
- Document limitation: localhost / NAT / VPN scenarios

### FR-3 Fraud analysis (existing)

- Preserve current rule engine and thresholds
- Show decision (Safe/Suspicious/Fraud), risk score (0–100), triggered rules, explanation

### FR-4 Knowledge graph visualization

- Show transaction-focused subgraph after each detection
- Highlight flagged nodes and risk-propagated neighbors
- Support search/zoom (existing PyVis iframe acceptable for MVP)

### FR-5 Six security assessment dimensions

For each transaction, compute and display scores (0–100) and brief rationale for:

1. **Authenticity** — identity consistency (device/IP sharing, known fraud, new account signals)
2. **Integrity** — data/behavior consistency (velocity, amount outliers, odd-hour patterns)
3. **Confidentiality** — exposure via shared infrastructure (shared IP/device fan-out)
4. **Access Control** — unauthorized access indicators (shared device, multi-customer IP, account age)
5. **Security** — composite operational security posture (weighted blend of above + decision)
6. **Non-repudiation** — traceability strength (graph linkage completeness, timeline depth, rule evidence count)

Implementation: **deterministic mapping** from existing `RuleResult`, graph stats, and propagation — not a separate ML model in MVP.

### FR-6 Research metrics (basic)

- Log assessment outcomes (JSON lines or SQLite) for later analysis
- Counters: decisions by label, avg score, rule hit rates

---

## 9. Non-Functional Requirements

| ID | Requirement |
|----|-------------|
| NFR-1 | OSS-only dependencies |
| NFR-2 | Single-process deployment (`uvicorn app:app`) for MVP |
| NFR-3 | `/detect` p95 latency < 2s for graphs ≤ 500 nodes (viz regeneration is main cost) |
| NFR-4 | Backward-compatible API: existing `/detect` fields preserved; new fields additive |
| NFR-5 | Thread-safe graph updates (lock around shared `KnowledgeGraph` if sim re-enabled) |
| NFR-6 | pytest coverage for new assessment module and API extensions |

---

## 10. Explicit Non-Goals (Current Phase)

- **Do not** integrate SecureBERT yet
- **Do not** redesign or replace the fraud rule engine
- **Do not** rebuild the application from scratch
- **Do not** polish UI to production design standards
- **Do not** add unnecessary dependencies
- **Do not** integrate Protégé/Pellet/HermiT yet
- **Do not** require Kaggle credentials for MVP (synthetic data is acceptable)
- **Do not** implement user authentication / multi-tenancy in MVP
- **Do not** commit secrets or paid API keys

---

## 11. Implementation Phases

### Phase 0 — Stabilize existing codebase (prerequisite)

- Fix known bugs blocking `/detect` and dashboard
- Re-enable or formally disable realtime simulator (document choice)
- Add missing dependency declarations
- Add minimal API integration tests

**Deliverable:** Server starts cleanly; manual detect works end-to-end.

### Phase 1 — Architecture proof (MVP)

- Transaction web form (structured fields, not raw JSON only)
- `GET /client-ip` or IP injection in `/detect` when `ip_address` omitted
- `SecurityAssessmentEngine` → 6 dimension scores in `/detect` response
- `GET /graph/subgraph?focus=<txn_id>` → JSON nodes/edges for involved entities
- UI panels for decision + 6 dimensions + graph iframe refresh

**Deliverable:** User submits txn → sees decision, scores, and focused graph.

### Phase 2 — Enhanced visualization & observability

- Optional: render subgraph from JSON in UI (reduce full-graph reload)
- Display `final_action`, `risk_propagation`, full triggered rules in UI
- Basic assessment logging for research (`assessments.jsonl` or SQLite)
- Re-enable realtime simulator with thread-safe graph access (optional demo mode)

### Phase 3 — Research instrumentation

- Batch evaluation script against CSV / `sample_transactions.json` (adapted schema)
- Metrics report: precision/recall vs `is_fraudulent` label (where available)
- Export graph snapshots per flagged case

### Phase 4 — SecureBERT integration (later)

- Define text inputs: fraud story, rule reasons, optional user notes
- Classify / score cybersecurity-relevant text (e.g., incident category, severity language)
- Merge SecureBERT signal as **supplementary** score — not replacing rules

### Phase 5 — Ontology & reasoning (later)

- Model entities/relations in OWL (align with graph node/edge types)
- Export RDF/TTL from NetworkX or parallel store
- Run Pellet/HermiT consistency checks and inferred classes
- Surface inferred triples as additional explanation in UI

---

## 12. API Changes Required

### 12.1 Extend `POST /detect` (additive)

**Request changes:**

- Make `ip_address` optional; server fills from client IP when absent
- Optional: `use_client_ip: bool` flag (default true when ip omitted)

**Response additions:**

```json
{
  "final_action": "BLOCK",
  "client_ip_detected": "203.0.113.10",
  "security_assessment": {
    "authenticity":       {"score": 42, "level": "Medium", "factors": ["..."]},
    "integrity":          {"score": 65, "level": "High",   "factors": ["..."]},
    "confidentiality":    {"score": 55, "level": "Medium", "factors": ["..."]},
    "access_control":     {"score": 70, "level": "High",   "factors": ["..."]},
    "security":           {"score": 58, "level": "Medium", "factors": ["..."]},
    "non_repudiation":    {"score": 80, "level": "High",   "factors": ["..."]}
  },
  "subgraph_url": "/graph/subgraph?focus=TXN-99999"
}
```

### 12.2 New endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/client-ip` | Returns detected public/client IP + source header used |
| GET | `/graph/subgraph` | JSON `{nodes: [...], edges: [...]}` ego-graph around focus node |
| GET | `/assessment/schema` | Describes dimension definitions and scoring rubric (for UI/docs) |

### 12.3 Optional fixes / consistency

- Align README graph URL paths (`/graph` vs `/static/...`)
- Add `sse-starlette` to `requirements.txt` if SSE is kept
- Extend `DetectOut` Pydantic model to include all returned fields

---

## 13. Frontend Requirements

### MVP UI (functional, not polished)

1. **Transaction form** — labeled inputs with validation; device ID text field; amount numeric
2. **IP field** — editable; show "Detected: x.x.x.x" from `/client-ip` on load
3. **Submit** — calls `/detect`; disable button while pending
4. **Results panel**
   - Decision badge (color-coded Safe/Suspicious/Fraud)
   - Risk score gauge or large numeric
   - `final_action` (ALLOW / OTP / BLOCK)
   - Triggered rules table (rule name, score, reason)
   - Fraud story (collapsible)
5. **Security assessment panel** — 6 rows: dimension name, score, level, top factors
6. **Graph panel** — iframe to `/graph?t=<cache_bust>` after detect; optional subgraph summary list
7. **Error handling** — show API validation errors clearly

### Keep from existing dashboard

- Graph search (`postMessage` to PyVis)
- Graph refresh button
- Header stats from `/graph/stats` (extend with assessment counts later)

### Defer

- Real-time sim feed (until simulator re-enabled)
- Responsive/mobile polish
- Dark/light theme toggle

---

## 14. Knowledge Graph Visualization Requirements

### MVP (Phase 1)

- Continue PyVis file-based rendering for full interactive graph
- Add **focused subgraph** on each `/detect`:
  - Center: current transaction node
  - Include: customer, IP, device, 1-hop neighbors
  - Highlight: flagged nodes + risk_propagation nodes (purple/red)
- Expose subgraph as JSON for future custom rendering

### Phase 2+

- Consider ego-graph-only HTML generation (faster than full graph regen)
- Edge tooltips: amount, timestamp, relation type
- Legend always visible (already in PNG; ensure HTML parity)

### Performance

- Throttle full graph regeneration (already done in EventStream via `viz_every`)
- For `/detect`, regenerate focused view first; full graph refresh optional/query param

---

## 15. Six Security Assessment Requirements

Each dimension returns: **score (0–100)**, **level** (Low / Medium / High / Critical), **factors** (string list).

| Dimension | Primary signals (MVP mapping) |
|-----------|-------------------------------|
| Authenticity | `known_fraud_customer`, `shared_device`, `multi_customer_same_ip`, account age |
| Integrity | `velocity_fraud`, `high_value_outlier`, `odd_hour_high_value`, amount vs avg |
| Confidentiality | Count of customers sharing IP/device; propagation fan-out |
| Access Control | Shared device/IP, new account + high spend, `final_action` |
| Security | Weighted aggregate of above + `risk_score` / decision |
| Non-repudiation | Timeline length, graph edge count for entity, number of triggered rules with evidence |

**Scoring approach (MVP):** Rule-to-dimension weight matrix + graph metrics → clamp 0–100. Document rubric in `/assessment/schema`.

---

## 16. SecureBERT Integration (Later Phase)

**Purpose:** Analyze free-text fields (fraud story, analyst notes, merchant descriptions) for cybersecurity/fraud language patterns.

**Planned approach:**

- Model: open Hugging Face cybersecurity BERT variant (e.g., SecureBERT or SecBERT-class)
- Input: concatenated explanation + fraud_story + optional `notes` field from UI
- Output: label probabilities or embedding similarity to fraud/incident templates
- Integration point: supplementary `nlp_risk_score` added to security dimension or separate panel
- Constraints: local inference only; no external API; lazy model load to keep startup fast

**Not in scope until Phase 4 approved.**

---

## 17. Protégé / Reasoner Integration (Later Phase)

**Purpose:** Formal ontology for e-commerce fraud entities; DL reasoning for inferred threats.

**Planned approach:**

1. Define OWL classes: `Customer`, `Transaction`, `IPAddress`, `Device`, `FraudEvent`, etc.
2. Object properties mirror graph edges: `makesPayment`, `connectsFromIP`, `usesDevice`
3. Export graph snapshot → RDF/TTL
4. Reason with Pellet or HermiT (Java, OSS) via CLI or `owlready2`
5. Display inferred classifications (e.g., `Customer ⊓ ∃usesDevice.Device ⊓ ∃connectsFromIP.IP → SuspiciousActor`)

**Not in scope until Phase 5 approved.**

---

## 18. Testing Strategy

| Layer | Tests |
|-------|-------|
| Unit | Security assessment scoring; subgraph extraction; IP extraction helper |
| Integration | `TestClient`: `/detect` with/without IP; `/graph/subgraph`; `/client-ip` |
| Regression | Existing 23 tests must pass unchanged |
| Manual | UI submit → verify decision, 6 scores, graph focus |
| Research | Script comparing decisions to `is_fraudulent` on CSV sample |

**CI suggestion:** `pytest test_system.py test_api.py -v` on push (future).

---

## 19. Current Limitations & Known Issues

| Issue | Impact | Priority |
|-------|--------|----------|
| `app.py` line 252: invalid `"final_action":` kwarg syntax in `DetectOut(...)` | `/detect` may fail to import/run | P0 |
| `DetectOut` model missing `final_action` field | Field dropped even if syntax fixed | P0 |
| `simulator.start(...)` commented out in lifespan | Live feed always empty; sim controls no-op | P1 |
| `sse-starlette` not in `requirements.txt` | `/stream` falls back to static JSON | P2 |
| `index.html` line 355: stray `id="fix_ui_1"` breaks JS | Manual detect may error | P0 |
| `refreshCounter` declared inside poll callback | Graph auto-refresh logic broken | P2 |
| Viz regenerates **entire** graph on every `/detect` | Slow at scale | P2 |
| No thread lock on `KnowledgeGraph` for concurrent `/detect` | Race if sim re-enabled | P2 |
| `sample_transactions.json` / `users.json` use legacy schema | Unused by current pipeline | P3 |
| Client IP behind localhost shows `127.0.0.1` | Misleading in dev unless documented | P3 |
| Location-jump tracked in inference but no dedicated rule | Signal unused in scoring | P3 |
| No security dimensions implemented | Gap vs target | Phase 1 |
| README references `/static/` paths; app serves `/graph` | Documentation drift | P3 |

---

## 20. Definition of "Working MVP"

A **working MVP** is achieved when all of the following are true:

1. `uvicorn app:app` starts without errors on a clean install (`pip install -r requirements.txt`)
2. User opens `/` and submits a transaction via **web form** (not only raw JSON)
3. Backend auto-fills client IP when the IP field is left empty (with clear dev/prod behavior)
4. Response shows **Fraud / Suspicious / Safe**, **risk score**, **triggered rules**, and **explanation**
5. **Six security assessment dimensions** display with scores and at least one factor each
6. **Interactive knowledge graph** updates to show the submitted transaction's relationships (iframe acceptable)
7. `GET /graph/subgraph?focus=<id>` returns valid JSON for the same entities
8. Existing pytest suite passes; new tests cover assessment + API extensions
9. No SecureBERT, no ontology reasoner, no paid services
10. `scope.md` approved and Phase 1 implemented without redesigning the fraud engine

---

## 21. Open Decisions (Require Stakeholder Approval)

1. **Simulator:** Re-enable background simulation for demo, or remove sim UI until Phase 2?
2. **IP strategy:** Override user-entered IP with detected IP, or only fill when empty?
3. **Security score rubric:** Equal weight across 6 dimensions, or weighted (e.g., Authenticity 20%, Security 25%)?
4. **Graph viz MVP:** Keep PyVis iframe only, or also build JSON→canvas subgraph panel?
5. **Assessment persistence:** JSONL file vs SQLite vs in-memory only for MVP?
6. **Project layout:** Stay flat (current) or introduce `static/` + `templates/` folders in Phase 1?
7. **Fix priority:** Address P0 bugs in Phase 0 before any new features — confirm?

---

## 22. Approval Gate

**No application code changes until this document is reviewed and approved.**

After approval, implementation order:

1. Phase 0 (bug fixes + tests)
2. Phase 1 (MVP features per sections 8, 12, 13, 14, 15)
3. Demo + research logging (Phase 2–3)
4. SecureBERT / ontology per separate approval

---

*End of scope document.*
