"""
graph_engine.py
---------------
Knowledge Graph engine — flat structure, dynamic updates.

Node types : customer · ip · device · transaction
Edge types : payment · from_ip · uses_device
"""
from __future__ import annotations

import csv
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

import networkx as nx

from logger import get_logger

logger = get_logger(__name__)


class KnowledgeGraph:
    NODE_CUSTOMER    = "customer"
    NODE_IP          = "ip"
    NODE_DEVICE      = "device"
    NODE_TRANSACTION = "transaction"

    EDGE_PAYMENT     = "payment"
    EDGE_FROM_IP     = "from_ip"
    EDGE_USES_DEVICE = "uses_device"

    def __init__(self) -> None:
        self.graph: nx.DiGraph = nx.DiGraph()
        self._ip_customers:     dict[str, set[str]]   = defaultdict(set)
        self._device_customers: dict[str, set[str]]   = defaultdict(set)
        self._customer_txns:    dict[str, list[dict]]  = defaultdict(list)
        self.flagged_nodes:     set[str]               = set()
        logger.info("KnowledgeGraph initialised.")

    # ── node helpers ──────────────────────────────────────────────────────────

    def _upsert(self, node_id: str, **attrs: object) -> None:
        if not self.graph.has_node(node_id):
            self.graph.add_node(node_id, **attrs)
        else:
            existing = self.graph.nodes[node_id]
            for k, v in attrs.items():
                if k not in existing:
                    existing[k] = v

    def add_customer(self, cid: str, **profile: object) -> None:
        self._upsert(cid, type=self.NODE_CUSTOMER, **profile)

    def add_ip(self, ip: str) -> None:
        self._upsert(ip, type=self.NODE_IP)

    def add_device(self, dev: str) -> None:
        self._upsert(dev, type=self.NODE_DEVICE)

    def add_transaction_node(self, txn_id: str, **meta: object) -> None:
        self._upsert(txn_id, type=self.NODE_TRANSACTION, **meta)

    def add_edge(self, src: str, dst: str, relation: str, **kw: object) -> None:
        self.graph.add_edge(src, dst, relation=relation, **kw)

    # ── CSV ingestion ─────────────────────────────────────────────────────────

    def build_from_csv(self, csv_path: str, max_rows: Optional[int] = None) -> None:
        logger.info(f"Building graph from: {csv_path}")

        customer_amounts: dict[str, list[float]] = defaultdict(list)
        with open(csv_path, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                try:
                    customer_amounts[row["Customer ID"]].append(
                        float(row["Transaction Amount"])
                    )
                except (KeyError, ValueError):
                    pass

        customer_avg: dict[str, float] = {
            cid: sum(v) / len(v) for cid, v in customer_amounts.items()
        }

        count = 0
        with open(csv_path, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if max_rows is not None and count >= max_rows:
                    break
                try:
                    self._ingest_row(row, customer_avg)
                    count += 1
                except Exception as exc:
                    logger.debug(f"Row skipped: {exc}")

        logger.info(
            f"Graph ready — {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges ({count} rows ingested)."
        )

    def _ingest_row(self, row: dict[str, str], customer_avg: dict[str, float]) -> None:
        txn_id   = row["Transaction ID"].strip()
        cid      = row["Customer ID"].strip()
        ip       = row["IP Address"].strip()
        device   = row["Device Used"].strip()
        amount   = float(row["Transaction Amount"])
        ts       = row["Transaction Date"].strip()
        acct_age = int(float(row.get("Account Age Days", "365")))
        is_fraud = int(row.get("Is Fraudulent", "0"))
        hour     = int(row.get("Transaction Hour", "12"))
        location = row.get("Customer Location", "Unknown")
        cust_age = int(float(row.get("Customer Age", "30")))
        payment  = row.get("Payment Method", "card")

        self.add_customer(
            cid,
            account_age_days=acct_age,
            avg_transaction_amount=round(customer_avg.get(cid, amount), 2),
            location=location,
            customer_age=cust_age,
            known_fraud=is_fraud,
        )
        self.add_ip(ip)
        self.add_device(device)
        self.add_transaction_node(
            txn_id,
            amount=amount,
            timestamp=ts,
            hour=hour,
            is_fraudulent=is_fraud,
            payment_method=payment,
        )

        self.add_edge(cid, txn_id, self.EDGE_PAYMENT,     amount=amount, timestamp=ts)
        self.add_edge(cid, ip,     self.EDGE_FROM_IP,     timestamp=ts)
        self.add_edge(cid, device, self.EDGE_USES_DEVICE, timestamp=ts)

        self._ip_customers[ip].add(cid)
        self._device_customers[device].add(cid)
        self._customer_txns[cid].append(
            {"txn_id": txn_id, "amount": amount, "timestamp": ts}
        )

    # ── dynamic single-transaction add ────────────────────────────────────────

    def add_transaction(self, txn: dict[str, object]) -> None:
        """Add ONE new transaction to the live graph before inference."""

        cid = str(txn.get("Customer ID", "unknown"))
        ip = str(txn.get("IP Address", "0.0.0.0"))
        device = str(txn.get("Device Used", "unknown_device"))

        # ✅ SAFE CONVERSIONS
        raw_amount = txn.get("Transaction Amount", 0)
        amount = float(raw_amount) if isinstance(raw_amount, (int, float, str)) else 0.0

        raw_hour = txn.get("Transaction Hour", datetime.now(timezone.utc).hour)
        hour = int(raw_hour) if isinstance(raw_hour, (int, float, str)) else datetime.now(timezone.utc).hour

        raw_age = txn.get("Account Age Days", 365)
        account_age_days = int(raw_age) if isinstance(raw_age, (int, float, str)) else 365

        raw_fraud = txn.get("Is Fraudulent", 0)
        is_fraud = int(raw_fraud) if isinstance(raw_fraud, (int, float, str)) else 0

        ts = str(txn.get("Transaction Date", datetime.now(timezone.utc).isoformat()))
        txn_id = str(txn.get("Transaction ID", f"dyn_{id(txn)}"))

        # Calculate avg
        existing = self._customer_txns[cid]
        all_amts = [t["amount"] for t in existing] + [amount]
        avg_amt = round(sum(all_amts) / len(all_amts), 2)

        self.add_customer(
            cid,
            avg_transaction_amount=avg_amt,
            account_age_days=account_age_days,
            known_fraud=is_fraud,
        )

        self.add_ip(ip)
        self.add_device(device)

        self.add_transaction_node(
            txn_id,
            amount=amount,
            timestamp=ts,
            hour=hour,
            is_fraudulent=is_fraud,
            payment_method=str(txn.get("Payment Method", "card")),
        )

        self.add_edge(cid, txn_id, self.EDGE_PAYMENT, amount=amount, timestamp=ts)
        self.add_edge(cid, ip, self.EDGE_FROM_IP, timestamp=ts)
        self.add_edge(cid, device, self.EDGE_USES_DEVICE, timestamp=ts)

        self._ip_customers[ip].add(cid)
        self._device_customers[device].add(cid)

        self._customer_txns[cid].append(
            {"txn_id": txn_id, "amount": amount, "timestamp": ts}
        )

        logger.info(f"Dynamic node added: {txn_id} (customer={cid})")

    # ── query helpers ─────────────────────────────────────────────────────────

    def customers_on_ip(self, ip: str) -> set[str]:
        return self._ip_customers.get(ip, set())

    def customers_on_device(self, device: str) -> set[str]:
        return self._device_customers.get(device, set())

    def transactions_for_customer(self, cid: str) -> list[dict]:
        return self._customer_txns.get(cid, [])

    def get_nodes_by_type(self, ntype: str) -> list[str]:
        return [n for n, d in self.graph.nodes(data=True) if d.get("type") == ntype]

    def node_exists(self, nid: str) -> bool:
        return self.graph.has_node(nid)

    def flag_nodes(self, nodes: list[str]) -> None:
        self.flagged_nodes.update(nodes)

    def stats(self) -> dict[str, int]:
        return {
            "total_nodes":  self.graph.number_of_nodes(),
            "total_edges":  self.graph.number_of_edges(),
            "customers":    len(self.get_nodes_by_type(self.NODE_CUSTOMER)),
            "ips":          len(self.get_nodes_by_type(self.NODE_IP)),
            "devices":      len(self.get_nodes_by_type(self.NODE_DEVICE)),
            "transactions": len(self.get_nodes_by_type(self.NODE_TRANSACTION)),
        }


def load_graph_from_csv(
    csv_path: str, max_rows: Optional[int] = None
) -> KnowledgeGraph:
    kg = KnowledgeGraph()
    kg.build_from_csv(csv_path, max_rows=max_rows)
    return kg