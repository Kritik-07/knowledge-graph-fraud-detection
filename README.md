# Knowledge Graph-Based Cyber Threat Detection

## E-Commerce Fraud Detection Framework — v2.0

---

## Project Structure (Flat — no nested folders)

```
threatgraph/
├── logger.py              # Centralised logging
├── dataset_generator.py   # Kaggle dataset loader / synthetic generator
├── graph_engine.py        # NetworkX knowledge graph + dynamic updates
├── fraud_rules.py         # 7 pluggable rule functions
├── inference_engine.py    # Rule orchestration + score aggregation
├── decision_engine.py     # Safe / Suspicious / Fraud classification
├── visualizer.py          # Static PNG + Interactive HTML (PyVis)
├── app.py                 # FastAPI REST API
├── run_demo.py            # CLI end-to-end demo
├── test_system.py         # pytest test suite (25 tests)
└── requirements.txt
```

---

## Dataset

This project uses the **Kaggle Fraudulent E-Commerce Transactions** dataset:

- **Dataset:** `shriyashjagtap/fraudulent-e-commerce-transactions`
- **Link:** https://www.kaggle.com/datasets/shriyashjagtap/fraudulent-e-commerce-transactions
- **Size:** 1.4M+ transactions, 16 features

**To use the real dataset:**

```bash
pip install kagglehub
# Set credentials in ~/.kaggle/kaggle.json or env vars
export KAGGLE_USERNAME=your_username
export KAGGLE_KEY=your_api_key
```

The system auto-downloads it on startup. Without credentials, it generates a
**realistic synthetic dataset** with the identical schema.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run CLI demo (generates dataset, builds graph, visualises)
python run_demo.py

# 3. Start API server
uvicorn app:app --reload --host 0.0.0.0 --port 8000

# 4. Run tests
python -m pytest test_system.py -v
```

---

## API

### `POST /detect`

```json
{
  "transaction_id": "TXN-99999",
  "customer_id": "CUST_1042",
  "ip_address": "192.168.1.10",
  "device_used": "mobile_4321",
  "transaction_amount": 4500.0,
  "transaction_date": "2024-06-15 02:15:00",
  "transaction_hour": 2,
  "account_age_days": 5
}
```

**Response:**

```json
{
  "transaction_id":  "TXN-99999",
  "customer_id":     "CUST_1042",
  "risk_score":      75.0,
  "decision":        "Fraud",
  "explanation":     "...",
  "triggered_rules": [...],
  "graph_png_url":   "/static/knowledge_graph.png",
  "graph_html_url":  "/static/knowledge_graph_interactive.html"
}
```

### `GET /graph/stats` — Live graph node/edge counts

### `GET /graph/refresh` — Force re-render of PNG + HTML

### `GET /health` — Liveness probe

Swagger UI: **http://localhost:8000/docs**

---

## Fraud Detection Rules

| Rule                     | Signal                        | Score |
| ------------------------ | ----------------------------- | ----- |
| `multi_customer_same_ip` | 2+ customers on same IP       | 15–35 |
| `shared_device`          | Device used by 2+ customers   | 20–35 |
| `velocity_fraud`         | 3+ transactions in 10 minutes | 20–35 |
| `high_value_outlier`     | Amount 4–20×+ customer avg    | 8–30  |
| `new_account_high_spend` | Account <20 days + big spend  | 12–30 |
| `odd_hour_high_value`    | High spend at midnight–4am    | 5–15  |
| `known_fraud_customer`   | Prior confirmed fraud history | 40    |

**Thresholds:** Score ≥ 60 → Fraud · 30–59 → Suspicious · < 30 → Safe

### Add a New Rule

```python
# In fraud_rules.py
def rule_my_signal(txn: dict, kg: KnowledgeGraph) -> RuleResult:
    triggered = ...
    return RuleResult("my_signal", triggered, score=25, reason="...")

ALL_RULES.append(rule_my_signal)  # done — no other files need changing
```

---

## Graph Update Flow

```
POST /detect
    │
    ▼
InferenceEngine.analyze(txn)
    │
    ├─► graph.add_transaction(txn)   ← graph grows dynamically
    │
    ├─► evaluate_all_rules()         ← rules see updated graph context
    │
    ├─► kg.flag_nodes(...)           ← suspicious nodes stored on graph
    │
    └─► regenerate_visualizations()  ← PNG + HTML always up-to-date
```

---

## Visualisation

```python
from visualizer import visualize_graph, regenerate_visualizations

# Full render
visualize_graph(
    graph=kg.graph,
    highlight_nodes=list(kg.flagged_nodes),  # red-flagged by engine
    output_dir=".",
    suspicious_only=False,  # True = show only flagged nodes
)

# Quick re-render after API call
regenerate_visualizations(kg, output_dir=".")
```

Node colours: 🔵 Customer · 🔴 IP · 🟢 Device · 🟠 Transaction · 🚨 Flagged
