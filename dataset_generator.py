"""
dataset_generator.py
--------------------
Generates a realistic synthetic e-commerce fraud dataset.
Schema matches the Kaggle dataset:
  shriyashjagtap/fraudulent-e-commerce-transactions

To use the REAL Kaggle dataset instead:
  1. pip install kagglehub
  2. Set KAGGLE_USERNAME + KAGGLE_KEY env vars (or ~/.kaggle/kaggle.json)
  3. Call ensure_dataset() — it auto-downloads when credentials exist.
"""
from __future__ import annotations

import csv
import os
import random
import uuid
from datetime import datetime, timedelta
from typing import Optional

from logger import get_logger

logger = get_logger(__name__)

DEVICES: list[str] = ["mobile", "tablet", "desktop", "laptop"]
PAYMENT: list[str] = ["credit card", "debit card", "bank transfer", "PayPal", "crypto"]
CATEGORIES: list[str] = [
    "electronics", "clothing", "groceries", "jewelry",
    "sports", "books", "gaming", "beauty", "automotive",
]
LOCATIONS: list[str] = [
    "New York", "Los Angeles", "Chicago", "Houston", "Phoenix",
    "London", "Mumbai", "Toronto", "Sydney", "Berlin",
    "Lagos", "Moscow", "Beijing", "Dubai", "Singapore",
    "Sao Paulo", "Mexico City", "Istanbul", "Seoul", "Jakarta",
]

SCHEMA: list[str] = [
    "Transaction ID", "Customer ID", "Transaction Amount", "Transaction Date",
    "Payment Method", "Product Category", "Quantity", "Customer Age",
    "Customer Location", "Device Used", "IP Address", "Is Fraudulent",
    "Account Age Days", "Transaction Hour",
]


def _rand_ip(pool: Optional[list[str]] = None) -> str:
    if pool and random.random() < 0.35:
        return random.choice(pool)
    return (
        f"{random.randint(1, 254)}.{random.randint(0, 255)}"
        f".{random.randint(0, 255)}.{random.randint(1, 254)}"
    )


def _rand_device(pool: Optional[list[str]] = None) -> str:
    base = random.choice(DEVICES)
    if pool and random.random() < 0.30:
        return random.choice(pool)
    return f"{base}_{random.randint(1000, 9999)}"


def generate(
    n_records: int = 500,
    fraud_rate: float = 0.18,
    seed: int = 42,
    output_path: Optional[str] = None,
) -> str:
    """Generate synthetic dataset and save as CSV. Returns file path."""
    random.seed(seed)
    logger.info(f"Generating {n_records} records ({fraud_rate * 100:.0f}% fraud)…")

    shared_ips: list[str] = [_rand_ip() for _ in range(10)]
    shared_devices: list[str] = [
        f"{random.choice(DEVICES)}_{random.randint(1000, 9999)}" for _ in range(8)
    ]

    customers: dict[str, dict] = {}
    for i in range(150):
        cid = f"CUST_{1000 + i:04d}"
        customers[cid] = {
            "avg_spend":   round(random.uniform(30, 400), 2),
            "account_age": random.randint(30, 1500),
            "age":         random.randint(18, 75),
            "location":    random.choice(LOCATIONS),
        }

    base_date = datetime(2024, 1, 1)
    rows: list[dict] = []

    for _ in range(n_records):
        is_fraud = random.random() < fraud_rate
        cid      = random.choice(list(customers.keys()))
        profile  = customers[cid]

        if is_fraud:
            ip       = _rand_ip(shared_ips)
            device   = _rand_device(shared_devices)
            amount   = round(random.uniform(800, 9000), 2)
            acct_age = random.randint(1, 25)
            hour     = random.choice([0, 1, 2, 3, 22, 23])
        else:
            ip       = _rand_ip()
            device   = _rand_device()
            raw_amt  = random.gauss(profile["avg_spend"], profile["avg_spend"] * 0.3)
            amount   = max(5.0, round(abs(raw_amt), 2))
            acct_age = profile["account_age"]
            hour     = random.randint(8, 21)

        ts = base_date + timedelta(
            days=random.randint(0, 180),
            hours=hour,
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )

        rows.append({
            "Transaction ID":     str(uuid.uuid4())[:22],
            "Customer ID":        cid,
            "Transaction Amount": amount,
            "Transaction Date":   ts.strftime("%Y-%m-%d %H:%M:%S"),
            "Payment Method":     random.choice(PAYMENT),
            "Product Category":   random.choice(CATEGORIES),
            "Quantity":           random.randint(1, 10),
            "Customer Age":       profile["age"],
            "Customer Location":  profile["location"],
            "Device Used":        device,
            "IP Address":         ip,
            "Is Fraudulent":      int(is_fraud),
            "Account Age Days":   acct_age,
            "Transaction Hour":   hour,
        })

    if output_path is None:
        output_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "fraud_ecommerce.csv"
        )

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=SCHEMA)
        writer.writeheader()
        writer.writerows(rows)

    fraud_n = sum(int(r["Is Fraudulent"]) for r in rows)
    logger.info(
        f"Dataset → {output_path} | {n_records} rows | "
        f"{fraud_n} fraud ({fraud_n / n_records * 100:.1f}%)"
    )
    return output_path


def ensure_dataset(path: Optional[str] = None) -> str:
    """Return path to CSV. Priority: existing file → Kaggle → synthetic."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    target   = path or os.path.join(base_dir, "fraud_ecommerce.csv")

    if os.path.exists(target):
        logger.info(f"Using existing dataset: {target}")
        return target

    try:
        import kagglehub  # type: ignore
        dl = kagglehub.dataset_download(
            "shriyashjagtap/fraudulent-e-commerce-transactions"
        )
        for fname in os.listdir(dl):
            if fname.endswith(".csv"):
                logger.info(f"Kaggle dataset: {os.path.join(dl, fname)}")
                return os.path.join(dl, fname)
    except Exception as exc:
        logger.warning(f"Kaggle unavailable ({exc}) — generating synthetic data.")

    return generate(output_path=target)