"""
test_system.py — pytest suite (23 tests)
Run: python -m pytest test_system.py -v
"""
from __future__ import annotations
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest
from graph_engine     import KnowledgeGraph
from inference_engine import InferenceEngine, InferenceResult
from decision_engine  import (
    DecisionEngine,
    LABEL_FRAUD, LABEL_SUSPICIOUS, LABEL_SAFE,
)
from fraud_rules import (
    rule_multi_customer_same_ip, rule_shared_device,
    rule_velocity_fraud, rule_high_value_outlier,
    rule_new_account_high_spend, rule_odd_hour_high_value,
)


@pytest.fixture
def fresh_kg():
    return KnowledgeGraph()


@pytest.fixture
def seeded_kg():
    kg  = KnowledgeGraph()
    avg = {"C_A": 200.0, "C_B": 300.0, "C_C": 150.0}
    rows = [
        {"Transaction ID": "T001", "Customer ID": "C_A",
         "IP Address": "10.0.0.1", "Device Used": "mobile_111",
         "Transaction Amount": "200", "Transaction Date": "2024-01-15 10:00:00",
         "Transaction Hour": "10", "Account Age Days": "500",
         "Is Fraudulent": "0", "Customer Location": "NY",
         "Customer Age": "35", "Payment Method": "credit card"},
        {"Transaction ID": "T002", "Customer ID": "C_B",
         "IP Address": "10.0.0.1", "Device Used": "mobile_222",
         "Transaction Amount": "300", "Transaction Date": "2024-01-15 10:01:00",
         "Transaction Hour": "10", "Account Age Days": "200",
         "Is Fraudulent": "0", "Customer Location": "LA",
         "Customer Age": "25", "Payment Method": "debit card"},
        {"Transaction ID": "T003", "Customer ID": "C_C",
         "IP Address": "10.0.0.1", "Device Used": "mobile_111",
         "Transaction Amount": "150", "Transaction Date": "2024-01-15 10:02:00",
         "Transaction Hour": "10", "Account Age Days": "8",
         "Is Fraudulent": "0", "Customer Location": "SG",
         "Customer Age": "22", "Payment Method": "PayPal"},
    ]
    for r in rows:
        kg._ingest_row(r, avg)
    return kg


@pytest.fixture
def pipeline(seeded_kg):
    return {"kg": seeded_kg, "inf": InferenceEngine(seeded_kg), "dec": DecisionEngine()}


class TestGraphEngine:
    def test_empty(self, fresh_kg):
        assert fresh_kg.graph.number_of_nodes() == 0

    def test_add_customer(self, fresh_kg):
        fresh_kg.add_customer("C_X", account_age_days=100)
        assert fresh_kg.graph.nodes["C_X"]["type"] == "customer"

    def test_add_ip(self, fresh_kg):
        fresh_kg.add_ip("1.2.3.4")
        assert fresh_kg.graph.nodes["1.2.3.4"]["type"] == "ip"

    def test_add_device(self, fresh_kg):
        fresh_kg.add_device("dev_001")
        assert fresh_kg.graph.nodes["dev_001"]["type"] == "device"

    def test_stats(self, seeded_kg):
        s = seeded_kg.stats()
        assert s["customers"] == 3 and s["transactions"] == 3

    def test_ip_index(self, seeded_kg):
        assert len(seeded_kg.customers_on_ip("10.0.0.1")) == 3

    def test_device_index(self, seeded_kg):
        assert "C_A" in seeded_kg.customers_on_device("mobile_111")

    def test_dynamic_add(self, seeded_kg):
        before = seeded_kg.graph.number_of_nodes()
        seeded_kg.add_transaction({
            "Transaction ID": "T_new", "Customer ID": "C_NEW",
            "IP Address": "9.9.9.9", "Device Used": "tablet_new",
            "Transaction Amount": 50.0, "Transaction Date": "2024-06-01 12:00:00",
            "Transaction Hour": 12, "Account Age Days": 200, "Is Fraudulent": 0,
        })
        assert seeded_kg.graph.number_of_nodes() > before

    def test_flag_nodes(self, seeded_kg):
        seeded_kg.flag_nodes(["C_A", "10.0.0.1"])
        assert "C_A" in seeded_kg.flagged_nodes


class TestFraudRules:
    def _t(self, **kw):
        base = {
            "Transaction ID": "T_t", "Customer ID": "C_t",
            "IP Address": "99.0.0.1", "Device Used": "dev_t",
            "Transaction Amount": 100.0,
            "Transaction Date": "2024-01-15 10:00:00",
            "Transaction Hour": 10, "Account Age Days": 500, "Is Fraudulent": 0,
        }
        base.update(kw)
        return base

    def test_multi_ip_triggers(self, seeded_kg):
        r = rule_multi_customer_same_ip(
            self._t(**{"IP Address": "10.0.0.1", "Customer ID": "C_NEW"}), seeded_kg)
        assert r.triggered

    def test_multi_ip_clean(self, seeded_kg):
        r = rule_multi_customer_same_ip(
            self._t(**{"IP Address": "200.200.200.200"}), seeded_kg)
        assert not r.triggered

    def test_shared_device_triggers(self, seeded_kg):
        r = rule_shared_device(
            self._t(**{"Device Used": "mobile_111", "Customer ID": "C_NEW"}), seeded_kg)
        assert r.triggered

    def test_high_value_triggers(self, seeded_kg):
        seeded_kg.graph.nodes["C_A"]["avg_transaction_amount"] = 50.0
        r = rule_high_value_outlier(
            self._t(**{"Customer ID": "C_A", "Transaction Amount": 5000.0}), seeded_kg)
        assert r.triggered and r.score >= 15

    def test_new_account_triggers(self, seeded_kg):
        r = rule_new_account_high_spend(
            self._t(**{"Customer ID": "C_C", "Transaction Amount": 800.0}), seeded_kg)
        assert r.triggered

    def test_odd_hour_triggers(self, seeded_kg):
        r = rule_odd_hour_high_value(
            self._t(**{"Transaction Hour": 2, "Transaction Amount": 1000.0}), seeded_kg)
        assert r.triggered

    def test_velocity_triggers(self, seeded_kg):
        for i in range(5):
            seeded_kg._ingest_row({
                "Transaction ID": f"V_{i}", "Customer ID": "C_A",
                "IP Address": "1.1.1.1", "Device Used": "dev_v",
                "Transaction Amount": "10", "Transaction Date": f"2024-01-15 10:0{i}:00",
                "Transaction Hour": "10", "Account Age Days": "500",
                "Is Fraudulent": "0", "Customer Location": "NY",
                "Customer Age": "30", "Payment Method": "card",
            }, {"C_A": 200.0})
        r = rule_velocity_fraud(
            self._t(**{"Customer ID": "C_A", "Transaction Date": "2024-01-15 10:04:30"}),
            seeded_kg)
        assert r.triggered


class TestDecisionEngine:
    def _mock(self, score):
        return InferenceResult("T_m", "C_m", score, score, [], [])

    def test_safe(self):        assert DecisionEngine().decide(self._mock(10)).label == LABEL_SAFE
    def test_suspicious(self):  assert DecisionEngine().decide(self._mock(45)).label == LABEL_SUSPICIOUS
    def test_fraud(self):       assert DecisionEngine().decide(self._mock(75)).label == LABEL_FRAUD
    def test_boundary_sus(self):assert DecisionEngine().decide(self._mock(30)).label == LABEL_SUSPICIOUS
    def test_boundary_fr(self): assert DecisionEngine().decide(self._mock(60)).label == LABEL_FRAUD


class TestEndToEnd:
    def test_high_risk(self, pipeline):
        kg, inf, dec = pipeline["kg"], pipeline["inf"], pipeline["dec"]
        kg.add_customer("C_RISK", avg_transaction_amount=50.0,
                        account_age_days=3, known_fraud=0)
        result = dec.decide(inf.analyze({
            "Transaction ID": "E2E_001", "Customer ID": "C_RISK",
            "IP Address": "10.0.0.1", "Device Used": "mobile_111",
            "Transaction Amount": 5000.0, "Transaction Date": "2024-01-15 02:30:00",
            "Transaction Hour": 2, "Account Age Days": 3, "Is Fraudulent": 0,
        }))
        assert result.risk_score >= 30
        assert result.label in (LABEL_SUSPICIOUS, LABEL_FRAUD)

    def test_safe(self, pipeline):
        kg, inf, dec = pipeline["kg"], pipeline["inf"], pipeline["dec"]
        kg.add_customer("C_SAFE", avg_transaction_amount=100.0,
                        account_age_days=800, known_fraud=0)
        result = dec.decide(inf.analyze({
            "Transaction ID": "E2E_002", "Customer ID": "C_SAFE",
            "IP Address": "200.100.50.25", "Device Used": "laptop_safe",
            "Transaction Amount": 95.0, "Transaction Date": "2024-06-01 14:00:00",
            "Transaction Hour": 14, "Account Age Days": 800, "Is Fraudulent": 0,
        }))
        assert result.label == LABEL_SAFE