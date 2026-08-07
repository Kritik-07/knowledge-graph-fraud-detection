"""
realtime_simulator.py
---------------------
Generates realistic e-commerce transaction events continuously.
Simulates fraud patterns: shared IPs, cloned devices, velocity bursts,
location jumps, and odd-hour high-value purchases.

Usage:
    sim = RealtimeSimulator(events_per_second=2, num_users=20)
    sim.start(callback=my_function)   # non-blocking background thread
    sim.stop()
"""
from __future__ import annotations

import random
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional

from logger import get_logger

logger = get_logger(__name__)

# ── realistic data pools ──────────────────────────────────────────────────────

_DEVICES    = ["mobile", "tablet", "desktop", "laptop"]
_PAYMENT    = ["credit card", "debit card", "bank transfer", "PayPal", "crypto"]
_CATEGORIES = ["electronics", "clothing", "groceries", "jewelry",
                "sports", "books", "gaming", "beauty", "automotive"]
_LOCATIONS  = [
    "New York", "Los Angeles", "Chicago", "London", "Mumbai",
    "Toronto", "Sydney", "Berlin", "Dubai", "Singapore",
    "Lagos", "Seoul", "São Paulo", "Istanbul", "Moscow",
]

# Fraud infrastructure shared across malicious actors
_FRAUD_IPS:     list[str] = [
    f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    for _ in range(6)
]
_FRAUD_DEVICES: list[str] = [
    f"{random.choice(_DEVICES)}_{random.randint(1000, 1099)}"
    for _ in range(5)
]


def _rand_ip(fraud: bool = False) -> str:
    if fraud:
        return random.choice(_FRAUD_IPS)
    return (
        f"{random.randint(1, 254)}.{random.randint(0, 255)}"
        f".{random.randint(0, 255)}.{random.randint(1, 254)}"
    )


def _rand_device(fraud: bool = False) -> str:
    if fraud:
        return random.choice(_FRAUD_DEVICES)
    return f"{random.choice(_DEVICES)}_{random.randint(2000, 9999)}"


class CustomerProfile:
    """Stable profile per simulated customer, mimics real user behaviour."""

    def __init__(self, cid: str) -> None:
        self.customer_id   = cid
        self.avg_spend     = round(random.uniform(30, 350), 2)
        self.account_age   = random.randint(30, 1500)
        self.age           = random.randint(18, 70)
        self.location      = random.choice(_LOCATIONS)
        self.home_ip       = _rand_ip()
        self.home_device   = _rand_device()
        self.is_bad_actor  = random.random() < 0.15   # 15% fraudsters


class RealtimeSimulator:
    """
    Background thread that fires transaction events at a configurable rate.

    Args:
        events_per_second:  How many transactions to emit per second (float).
        num_users:          Size of the simulated customer pool.
        seed:               Random seed for reproducibility (None = random).
    """

    def __init__(
        self,
        events_per_second: float = 1.0,
        num_users: int = 30,
        seed: Optional[int] = None,
    ) -> None:
        self.events_per_second = max(0.1, events_per_second)
        self.num_users         = max(5, num_users)
        self._seed             = seed

        self._customers: list[CustomerProfile] = []
        self._thread:    Optional[threading.Thread] = None
        self._stop_evt:  threading.Event = threading.Event()
        self._lock:      threading.Lock  = threading.Lock()

        # Velocity tracking: customer_id → list of recent timestamps
        self._recent_times: dict[str, list[float]] = {}
        # Location tracking: customer_id → last known location
        self._last_location: dict[str, str] = {}

        self._total_emitted = 0

    # ── public API ─────────────────────────────────────────────────────────────

    def start(self, callback: Callable[[dict], None]) -> None:
        """
        Start emitting transactions in a background daemon thread.
        callback is called with each transaction dict (Kaggle-schema keys).
        """
        if self._thread and self._thread.is_alive():
            logger.warning("Simulator already running.")
            return

        if self._seed is not None:
            random.seed(self._seed)

        self._customers = [
            CustomerProfile(f"SIM_{i:04d}") for i in range(self.num_users)
        ]
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._loop,
            args=(callback,),
            daemon=True,
            name="RealtimeSimulator",
        )
        self._thread.start()
        logger.info(
            f"Simulator started — {self.events_per_second} evt/s, "
            f"{self.num_users} users."
        )

    def stop(self) -> None:
        """Signal the background thread to stop."""
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=3)
        logger.info(f"Simulator stopped after {self._total_emitted} events.")

    def update_speed(self, events_per_second: float) -> None:
        """Hot-change emission rate without restart."""
        with self._lock:
            self.events_per_second = max(0.1, events_per_second)
        logger.info(f"Simulator speed updated → {self.events_per_second} evt/s")

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive()
                    and not self._stop_evt.is_set())

    # ── internal loop ──────────────────────────────────────────────────────────

    def _loop(self, callback: Callable[[dict], None]) -> None:
        while not self._stop_evt.is_set():
            with self._lock:
                delay = 1.0 / self.events_per_second

            try:
                txn = self._generate()
                callback(txn)
                self._total_emitted += 1
            except Exception as exc:
                logger.error(f"Simulator callback error: {exc}")

            self._stop_evt.wait(timeout=delay)

    # ── transaction generation ─────────────────────────────────────────────────

    def _generate(self) -> dict:
        """
        Build a single transaction dict with realistic fraud patterns:
          • 15% bad actors → shared IPs, shared devices, odd hours, high spend
          • velocity burst: bad actors fire multiple txns in quick succession
          • location jump: customer location changes from last known location
          • new-account spike: occasionally simulate brand-new accounts
        """
        customer = random.choice(self._customers)
        cid      = customer.customer_id
        now      = datetime.now(timezone.utc)
        is_fraud = customer.is_bad_actor and random.random() < 0.60

        # ── velocity tracking ──────────────────────────────────────────────────
        ts_now = now.timestamp()
        recent = self._recent_times.get(cid, [])
        # Keep only timestamps within last 10 minutes
        recent = [t for t in recent if ts_now - t < 600]
        recent.append(ts_now)
        self._recent_times[cid] = recent

        # ── fraud pattern selection ────────────────────────────────────────────
        pattern = random.choice(["shared_ip", "shared_device", "odd_hour",
                                 "high_spend", "location_jump", "normal"]) \
                  if is_fraud else "normal"

        if pattern == "shared_ip":
            ip     = _rand_ip(fraud=True)
            device = customer.home_device
            amount = round(random.uniform(500, 8000), 2)
            hour   = now.hour

        elif pattern == "shared_device":
            ip     = customer.home_ip
            device = _rand_device(fraud=True)
            amount = round(random.uniform(300, 5000), 2)
            hour   = now.hour

        elif pattern == "odd_hour":
            ip     = _rand_ip(fraud=True)
            device = _rand_device(fraud=True)
            amount = round(random.uniform(800, 9000), 2)
            hour   = random.choice([0, 1, 2, 3, 23])

        elif pattern == "high_spend":
            ip     = customer.home_ip
            device = customer.home_device
            amount = round(customer.avg_spend * random.uniform(15, 40), 2)
            hour   = now.hour

        elif pattern == "location_jump":
            # Customer's location suddenly changes
            last_loc  = self._last_location.get(cid, customer.location)
            new_locs  = [l for l in _LOCATIONS if l != last_loc]
            customer.location = random.choice(new_locs)
            ip     = _rand_ip()                # new IP for new location
            device = customer.home_device
            amount = round(random.uniform(200, 3000), 2)
            hour   = now.hour

        else:  # normal
            ip     = customer.home_ip
            device = customer.home_device
            raw    = random.gauss(customer.avg_spend, customer.avg_spend * 0.25)
            amount = max(5.0, round(abs(raw), 2))
            hour   = now.hour

        # Track location
        self._last_location[cid] = customer.location

        # Occasionally simulate brand-new account (high risk)
        acct_age = (
            random.randint(1, 7)
            if is_fraud and random.random() < 0.3
            else customer.account_age
        )

        txn_id = f"SIM-{uuid.uuid4().hex[:12].upper()}"

        return {
            "Transaction ID":     txn_id,
            "Customer ID":        cid,
            "Transaction Amount": amount,
            "Transaction Date":   now.strftime("%Y-%m-%d %H:%M:%S"),
            "Payment Method":     random.choice(_PAYMENT),
            "Product Category":   random.choice(_CATEGORIES),
            "Quantity":           random.randint(1, 5),
            "Customer Age":       customer.age,
            "Customer Location":  customer.location,
            "Device Used":        device,
            "IP Address":         ip,
            "Is Fraudulent":      int(is_fraud),
            "Account Age Days":   acct_age,
            "Transaction Hour":   hour,
            # Extra metadata for UI / SSE display
            "_simulated":         True,
            "_pattern":           pattern,
            "_velocity_count":    len(recent),
        }