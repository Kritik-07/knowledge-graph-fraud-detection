"""
inference_engine.py
-------------------
Adds transaction to live graph BEFORE rule evaluation,
then aggregates scores and flags suspicious nodes.
ADDITION v3: flags transaction node itself + location-jump detection.
"""
from __future__ import annotations

from graph_engine import KnowledgeGraph
from fraud_rules  import evaluate_all_rules, RuleResult
from logger       import get_logger

logger = get_logger(__name__)
MAX_SCORE: int = 100

# Location history for rapid-location-change detection (in-memory)
_customer_last_location: dict[str, str] = {}


class InferenceResult:
    def __init__(
        self,
        txn_id: str,
        customer_id: str,
        raw_score: float,
        risk_score: float,
        triggered_rules: list[RuleResult],
        all_rules: list[RuleResult],
    ) -> None:
        self.transaction_id  = txn_id
        self.customer_id     = customer_id
        self.raw_score       = raw_score
        self.risk_score      = risk_score
        self.triggered_rules = triggered_rules
        self.all_rules       = all_rules

    def to_dict(self) -> dict:
        return {
            "transaction_id":  self.transaction_id,
            "customer_id":     self.customer_id,
            "risk_score":      round(self.risk_score, 2),
            "triggered_rules": [r.to_dict() for r in self.triggered_rules],
        }


class InferenceEngine:
    def __init__(self, kg: KnowledgeGraph) -> None:
        self.kg = kg
        logger.info("InferenceEngine ready.")

    def analyze(self, txn: dict) -> InferenceResult:
        txn_id = str(txn.get("Transaction ID", "unknown"))
        cid    = str(txn.get("Customer ID",    "unknown"))
        logger.info(f"Analysing: {txn_id}  customer={cid}")

        # ── ADDITION: inject location-jump signal into txn dict ──────────────
        current_loc = str(txn.get("Customer Location", ""))
        last_loc    = _customer_last_location.get(cid, "")
        if last_loc and current_loc and last_loc != current_loc:
            txn = dict(txn)                          # don't mutate caller's dict
            txn["_location_jump"] = True
            txn["_prev_location"] = last_loc
        _customer_last_location[cid] = current_loc
        # ─────────────────────────────────────────────────────────────────────

        # Step 1: add to graph so rules see updated context
        if not self.kg.node_exists(txn_id):
            self.kg.add_transaction(txn)

        # Step 2: evaluate all rules
        rule_results = evaluate_all_rules(txn, self.kg)

        # Step 3: aggregate
        raw_score  = sum(r.score for r in rule_results if r.triggered)
        risk_score = min(raw_score, MAX_SCORE)
        triggered  = [r for r in rule_results if r.triggered]

        # Step 4: flag nodes (transaction node itself + related nodes)
        if triggered:
            self.kg.flag_nodes([
                txn_id,                                    # transaction node
                cid,                                       # customer node
                str(txn.get("IP Address",  "")),
                str(txn.get("Device Used", "")),
            ])

        logger.info(f"  score={risk_score}  rules_hit={len(triggered)}")
        return InferenceResult(
            txn_id, cid, raw_score, risk_score, triggered, rule_results
        )