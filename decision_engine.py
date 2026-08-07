"""
decision_engine.py
------------------
Classifies inference results as Safe / Suspicious / Fraud.
"""
from __future__ import annotations

from inference_engine import InferenceResult
from fraud_rules      import RuleResult
from logger           import get_logger

logger = get_logger(__name__)

THRESHOLD_FRAUD:      int = 60
THRESHOLD_SUSPICIOUS: int = 30
LABEL_FRAUD      = "Fraud"
LABEL_SUSPICIOUS = "Suspicious"
LABEL_SAFE       = "Safe"


class DecisionResult:
    def __init__(
        self,
        txn_id: str,
        customer_id: str,
        risk_score: float,
        label: str,
        explanation: str,
        triggered_rules: list[RuleResult],
        final_action: str, 
    ) -> None:
        self.transaction_id  = txn_id
        self.customer_id     = customer_id
        self.risk_score      = risk_score
        self.label           = label
        self.explanation     = explanation
        self.triggered_rules = triggered_rules
        self.final_action    = final_action

    def to_dict(self) -> dict:
        return {
            "transaction_id":  self.transaction_id,
            "customer_id":     self.customer_id,
            "risk_score":      round(self.risk_score, 2),
            "decision":        self.label,
            "explanation":     self.explanation,
            "triggered_rules": [r.to_dict() for r in self.triggered_rules],
            "final_action": self.final_action,
        }


class DecisionEngine:
    def decide(self, inf: InferenceResult) -> DecisionResult:
        score = inf.risk_score
        if score >= THRESHOLD_FRAUD:
            label = LABEL_FRAUD
        elif score >= THRESHOLD_SUSPICIOUS:
            label = LABEL_SUSPICIOUS
        else:
            label = LABEL_SAFE
        # 🔥 Adaptive Step-Up Authentication
        if label == LABEL_FRAUD:
            final_action = "BLOCK"

        elif label == LABEL_SUSPICIOUS:
            final_action = "OTP"

        else:
            final_action = "ALLOW"

        # 🔥 Smart adjustment based on behavior
        if final_action == "OTP" and score < 60:
            final_action = "ALLOW"

        if not inf.triggered_rules:
            explanation = (
                f"Classified as {label} (score {score}/100). "
                "No suspicious patterns detected."
            )
        else:
            names   = ", ".join(r.rule_name for r in inf.triggered_rules)
            reasons = " | ".join(r.reason   for r in inf.triggered_rules)
            explanation = (
                f"Classified as {label} (score {score}/100). "
                f"Triggered: [{names}]. {reasons}"
            )

        logger.info(f"Decision [{inf.transaction_id}]: {label} score={score}")
        return DecisionResult(
            inf.transaction_id, inf.customer_id,
            score, label, explanation, inf.triggered_rules,
            final_action,
        )