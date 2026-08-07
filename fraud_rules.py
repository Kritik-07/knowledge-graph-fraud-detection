"""
fraud_rules.py
--------------
7 pluggable fraud detection rules.
Add new ones by defining a function and appending to ALL_RULES.
"""
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from logger import get_logger

if TYPE_CHECKING:
    from graph_engine import KnowledgeGraph

logger = get_logger(__name__)


class RuleResult:
    def __init__(
        self,
        rule_name: str,
        triggered: bool,
        score: float,
        reason: str,
    ) -> None:
        self.rule_name = rule_name
        self.triggered = triggered
        self.score     = score
        self.reason    = reason

    def to_dict(self) -> dict:
        return {
            "rule":               self.rule_name,
            "triggered":          self.triggered,
            "score_contribution": self.score,
            "reason":             self.reason,
        }


def _within_seconds(ref: datetime, ts_str: str, window: int) -> bool:
    try:
        ts = datetime.fromisoformat(ts_str)
        return abs((ref - ts).total_seconds()) <= window
    except (ValueError, TypeError):
        return False


# ── rules ─────────────────────────────────────────────────────────────────────

def rule_multi_customer_same_ip(txn: dict, kg: "KnowledgeGraph") -> RuleResult:
    ip    = str(txn.get("IP Address", ""))
    cid   = str(txn.get("Customer ID", ""))
    total = len(kg.customers_on_ip(ip) | {cid})
    if total >= 5:
        return RuleResult("multi_customer_same_ip", True, 35,
            f"IP {ip} shared by {total} customers — severe botnet risk.")
    if total >= 3:
        return RuleResult("multi_customer_same_ip", True, 25,
            f"IP {ip} shared by {total} customers — account-farm risk.")
    if total >= 2:
        return RuleResult("multi_customer_same_ip", True, 15,
            f"IP {ip} shared by 2 customers — monitor.")
    return RuleResult("multi_customer_same_ip", False, 0,
        f"IP {ip} — single customer, normal.")


def rule_shared_device(txn: dict, kg: "KnowledgeGraph") -> RuleResult:
    device = str(txn.get("Device Used", ""))
    cid    = str(txn.get("Customer ID", ""))
    total  = len(kg.customers_on_device(device) | {cid})
    if total >= 4:
        return RuleResult("shared_device", True, 35,
            f"Device {device} used by {total} customers — likely cloned.")
    if total >= 2:
        return RuleResult("shared_device", True, 20,
            f"Device {device} shared by {total} customers — suspicious.")
    return RuleResult("shared_device", False, 0,
        f"Device {device} — unique to one customer.")


def rule_velocity_fraud(txn: dict, kg: "KnowledgeGraph") -> RuleResult:
    cid    = str(txn.get("Customer ID", ""))
    ts_str = str(txn.get("Transaction Date", ""))
    try:
        current = datetime.fromisoformat(ts_str)
    except ValueError:
        return RuleResult("velocity_fraud", False, 0, "Cannot parse timestamp.")
    past   = kg.transactions_for_customer(cid)
    recent = sum(1 for t in past
                 if _within_seconds(current, str(t.get("timestamp", "")), 600))
    if recent >= 5:
        return RuleResult("velocity_fraud", True, 35,
            f"Customer {cid}: {recent} txns in 10 min — severe velocity fraud.")
    if recent >= 3:
        return RuleResult("velocity_fraud", True, 20,
            f"Customer {cid}: {recent} txns in 10 min — velocity anomaly.")
    return RuleResult("velocity_fraud", False, 0, "Transaction velocity normal.")


def rule_high_value_outlier(txn: dict, kg: "KnowledgeGraph") -> RuleResult:
    cid    = str(txn.get("Customer ID", ""))
    amount = float(txn.get("Transaction Amount", 0))
    node   = kg.graph.nodes.get(cid, {})
    avg    = float(node.get("avg_transaction_amount", 200.0))
    ratio  = amount / avg if avg > 0 else float("inf")
    if ratio >= 20:
        return RuleResult("high_value_outlier", True, 30,
            f"${amount:.2f} is {ratio:.1f}x avg (${avg:.2f}) — extreme outlier.")
    if ratio >= 8:
        return RuleResult("high_value_outlier", True, 18,
            f"${amount:.2f} is {ratio:.1f}x avg — elevated risk.")
    if ratio >= 4:
        return RuleResult("high_value_outlier", True, 8,
            f"${amount:.2f} is {ratio:.1f}x avg — slightly elevated.")
    return RuleResult("high_value_outlier", False, 0,
        f"${amount:.2f} within normal range.")


def rule_new_account_high_spend(txn: dict, kg: "KnowledgeGraph") -> RuleResult:
    cid    = str(txn.get("Customer ID", ""))
    amount = float(txn.get("Transaction Amount", 0))
    node   = kg.graph.nodes.get(cid, {})
    age    = int(node.get("account_age_days", 999))
    if age <= 3 and amount >= 200:
        return RuleResult("new_account_high_spend", True, 30,
            f"Account {age}d old, ${amount:.2f} — very high new-account risk.")
    if age <= 10 and amount >= 500:
        return RuleResult("new_account_high_spend", True, 20,
            f"Account {age}d old, ${amount:.2f} — new-account fraud risk.")
    if age <= 20 and amount >= 1000:
        return RuleResult("new_account_high_spend", True, 12,
            f"Account {age}d old, ${amount:.2f} — suspicious for age.")
    return RuleResult("new_account_high_spend", False, 0,
        f"Account age ({age}d) and amount (${amount:.2f}) consistent.")


def rule_odd_hour_high_value(txn: dict, kg: "KnowledgeGraph") -> RuleResult:
    hour   = int(txn.get("Transaction Hour", 12))
    amount = float(txn.get("Transaction Amount", 0))
    if hour in (0, 1, 2, 3) and amount >= 500:
        return RuleResult("odd_hour_high_value", True, 15,
            f"${amount:.2f} at {hour:02d}:xx — high-value late-night transaction.")
    if hour in (0, 1, 2, 3):
        return RuleResult("odd_hour_high_value", True, 5,
            f"Transaction at {hour:02d}:xx — late-night activity.")
    return RuleResult("odd_hour_high_value", False, 0,
        f"Hour {hour} — normal business window.")


def rule_known_fraud_customer(txn: dict, kg: "KnowledgeGraph") -> RuleResult:
    cid  = str(txn.get("Customer ID", ""))
    node = kg.graph.nodes.get(cid, {})
    if node.get("known_fraud", 0):
        return RuleResult("known_fraud_customer", True, 40,
            f"Customer {cid} has confirmed fraud history in dataset.")
    return RuleResult("known_fraud_customer", False, 0,
        f"No prior fraud history for {cid}.")


ALL_RULES = [
    rule_multi_customer_same_ip,
    rule_shared_device,
    rule_velocity_fraud,
    rule_high_value_outlier,
    rule_new_account_high_spend,
    rule_odd_hour_high_value,
    rule_known_fraud_customer,
]


def evaluate_all_rules(
    txn: dict, kg: "KnowledgeGraph"
) -> list[RuleResult]:
    results: list[RuleResult] = []
    for fn in ALL_RULES:
        try:
            r = fn(txn, kg)
            results.append(r)
            if r.triggered:
                logger.info(f"  ↳ [{r.rule_name}] +{r.score:.0f}  {r.reason}")
        except Exception as exc:
            logger.error(f"Rule error in {fn.__name__}: {exc}")
    return results