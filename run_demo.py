"""
run_demo.py
-----------
End-to-end demo:
  1. Generate / load dataset
  2. Build knowledge graph
  3. Run inference on every transaction
  4. Visualise with engine-driven highlights (no hardcoded lists)

Run from project folder:
  python run_demo.py
"""
from __future__ import annotations

import csv
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from dataset_generator import ensure_dataset
from graph_engine       import load_graph_from_csv
from inference_engine   import InferenceEngine
from decision_engine    import DecisionEngine, LABEL_FRAUD, LABEL_SUSPICIOUS
from visualizer         import visualize_graph
from logger             import get_logger

logger = get_logger(__name__)

DEMO_ROWS = 100  # number of transactions to analyse in demo mode


def run() -> None:
    # ── 1. Dataset ────────────────────────────────────────────────────────────
    csv_path = ensure_dataset()

    # ── 2. Build initial graph ────────────────────────────────────────────────
    logger.info("Building knowledge graph…")
    kg = load_graph_from_csv(csv_path, max_rows=DEMO_ROWS)
    logger.info(f"Initial stats: {kg.stats()}")

    # ── 3. Inference on every row ─────────────────────────────────────────────
    inf_eng = InferenceEngine(kg)
    dec_eng = DecisionEngine()

    flagged: set[str] = set()

    print("\n" + "=" * 72)
    print(f"{'TXN ID':<24} {'CUSTOMER':<12} {'SCORE':>6}  {'DECISION':<12}  RULES")
    print("=" * 72)

    with open(csv_path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    for i, raw in enumerate(rows[:DEMO_ROWS]):
        txn = {
            "Transaction ID":     raw.get("Transaction ID", f"row_{i}"),
            "Customer ID":        raw.get("Customer ID", "UNKNOWN"),
            "IP Address":         raw.get("IP Address", "0.0.0.0"),
            "Device Used":        raw.get("Device Used", "unknown"),
            "Transaction Amount": float(raw.get("Transaction Amount", 0)),
            "Transaction Date":   raw.get("Transaction Date", "2024-01-01 12:00:00"),
            "Payment Method":     raw.get("Payment Method", "card"),
            "Transaction Hour":   int(raw.get("Transaction Hour", 12)),
            "Account Age Days":   int(float(raw.get("Account Age Days", 365))),
            "Is Fraudulent":      int(raw.get("Is Fraudulent", 0)),
            "Customer Location":  raw.get("Customer Location", "Unknown"),
            "Customer Age":       int(float(raw.get("Customer Age", 30))),
        }

        inf = inf_eng.analyze(txn)
        dec = dec_eng.decide(inf)

        emoji = "🔴" if dec.label == LABEL_FRAUD else ("🟡" if dec.label == LABEL_SUSPICIOUS else "🟢")
        print(
            f"{txn['Transaction ID'][:24]:<24} "
            f"{txn['Customer ID']:<12} "
            f"{dec.risk_score:>6.1f}  "
            f"{emoji} {dec.label:<10}  "
            f"{len(dec.triggered_rules)} rule(s)"
        )
        for r in dec.triggered_rules:
            print(f"  ↳ [{r.rule_name}] {r.reason}")

        if dec.label in (LABEL_FRAUD, LABEL_SUSPICIOUS):
            flagged.add(txn["Customer ID"])
            flagged.add(txn["IP Address"])
            flagged.add(txn["Device Used"])

    # Update graph's flagged set
    kg.flag_nodes(list(flagged))

    print("=" * 72)
    print(f"\n🚩 Flagged nodes: {len(kg.flagged_nodes)}")

    # ── 4. Visualise ──────────────────────────────────────────────────────────
    logger.info("Generating visualisations…")
    result = visualize_graph(
        graph=kg.graph,
        highlight_nodes=list(kg.flagged_nodes),
        output_dir=BASE_DIR,
    )

    print("\n📊 Output files:")
    for fmt, path in result.items():
        print(f"   {fmt.upper()}: {path}")

    print("\n✅ Demo complete.")
    print("   Open knowledge_graph_interactive.html in a browser for full interactivity.\n")


if __name__ == "__main__":
    run()