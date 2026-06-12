#!/usr/bin/env python3
"""
NSX-T Tier-1 Router Monitor — nsx-monitor.py

Monitors traffic statistics for NSX-T Tier-1 routers.
Supports snapshot, delta-report, and interval-based monitoring modes.

Usage:
    # Take a snapshot of current T1 counters
    python nsx-monitor.py --snapshot

    # Compare current counters against a saved snapshot
    python nsx-monitor.py --report --snapshot-file snapshot_20250101_120000.json

    # Monitor over a time interval (N minutes)
    python nsx-monitor.py --minutes 5

    # Specify custom output file for HTML report
    python nsx-monitor.py --minutes 10 --output /tmp/report.html

Requirements:
    - requests>=2.28.0
    - pyyaml>=6.0
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml

# ---------------------------------------------------------------------------
# Suppress InsecureRequestWarning for self-signed certificates
# ---------------------------------------------------------------------------
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("nsx-monitor")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR / "config.yaml"
DEFAULT_WORKERS = 8
REQUEST_TIMEOUT = (60, 300)  # (connect, read) seconds — увеличен для медленных NSX


# ===================================================================
# Data Classes
# ===================================================================

class T1Snapshot:
    """Statistics snapshot for a single Tier-1 router at one point in time."""

    __slots__ = (
        "t1_id", "display_name",
        "rx_bytes", "tx_bytes",
        "rx_packets", "tx_packets",
        "rx_dropped", "tx_dropped",
        "timestamp_ms",
    )

    def __init__(
        self,
        t1_id: str,
        display_name: str = "",
        rx_bytes: int = 0,
        tx_bytes: int = 0,
        rx_packets: int = 0,
        tx_packets: int = 0,
        rx_dropped: int = 0,
        tx_dropped: int = 0,
        timestamp_ms: int = 0,
    ):
        self.t1_id = t1_id
        self.display_name = display_name or t1_id
        self.rx_bytes = rx_bytes
        self.tx_bytes = tx_bytes
        self.rx_packets = rx_packets
        self.tx_packets = tx_packets
        self.rx_dropped = rx_dropped
        self.tx_dropped = tx_dropped
        self.timestamp_ms = timestamp_ms

    @property
    def name(self) -> str:
        return self.display_name or self.t1_id

    def to_dict(self) -> dict:
        return {
            "id": self.t1_id,
            "display_name": self.display_name,
            "rx_bytes": self.rx_bytes,
            "tx_bytes": self.tx_bytes,
            "rx_packets": self.rx_packets,
            "tx_packets": self.tx_packets,
            "rx_dropped": self.rx_dropped,
            "tx_dropped": self.tx_dropped,
            "timestamp_ms": self.timestamp_ms,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "T1Snapshot":
        return cls(
            t1_id=data["id"],
            display_name=data.get("display_name", ""),
            rx_bytes=data.get("rx_bytes", 0),
            tx_bytes=data.get("tx_bytes", 0),
            rx_packets=data.get("rx_packets", 0),
            tx_packets=data.get("tx_packets", 0),
            rx_dropped=data.get("rx_dropped", 0),
            tx_dropped=data.get("tx_dropped", 0),
            timestamp_ms=data.get("timestamp_ms", 0),
        )

    def __repr__(self) -> str:
        return (
            f"T1Snapshot({self.name}, "
            f"rx={self.rx_bytes}, tx={self.tx_bytes})"
        )


class T1EdgeInfo:
    """Edge placement and HA status for a single Tier-1 router."""

    __slots__ = (
        "t1_id", "display_name",
        "edge_cluster_name",
        "preferred_edges",
        "ha_active_edge",
        "ha_standby_edge",
        "ha_mode",
    )

    def __init__(
        self,
        t1_id: str,
        display_name: str = "",
        edge_cluster_name: str = "",
        preferred_edges: list = None,
        ha_active_edge: str = "",
        ha_standby_edge: str = "",
        ha_mode: str = "",
    ):
        self.t1_id = t1_id
        self.display_name = display_name or t1_id
        self.edge_cluster_name = edge_cluster_name
        self.preferred_edges = preferred_edges or []
        self.ha_active_edge = ha_active_edge
        self.ha_standby_edge = ha_standby_edge
        self.ha_mode = ha_mode

    @property
    def name(self) -> str:
        return self.display_name or self.t1_id

    def to_dict(self) -> dict:
        return {
            "id": self.t1_id,
            "display_name": self.display_name,
            "edge_cluster_name": self.edge_cluster_name,
            "preferred_edges": self.preferred_edges,
            "ha_active_edge": self.ha_active_edge,
            "ha_standby_edge": self.ha_standby_edge,
            "ha_mode": self.ha_mode,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "T1EdgeInfo":
        return cls(
            t1_id=data["id"],
            display_name=data.get("display_name", ""),
            edge_cluster_name=data.get("edge_cluster_name", ""),
            preferred_edges=data.get("preferred_edges", []),
            ha_active_edge=data.get("ha_active_edge", ""),
            ha_standby_edge=data.get("ha_standby_edge", ""),
            ha_mode=data.get("ha_mode", ""),
        )

    def __repr__(self) -> str:
        return (
            f"T1EdgeInfo({self.name}, "
            f"cluster={self.edge_cluster_name}, "
            f"active={self.ha_active_edge})"
        )


class T1Delta:
    """Computed delta (rate) between two snapshots for a single T1."""

    __slots__ = (
        "name", "t1_id",
        "rx_bytes_delta", "tx_bytes_delta",
        "rx_packets_delta", "tx_packets_delta",
        "rx_dropped_delta", "tx_dropped_delta",
        "elapsed_sec",
    )

    def __init__(
        self,
        name: str,
        t1_id: str,
        rx_bytes_delta: int,
        tx_bytes_delta: int,
        rx_packets_delta: int,
        tx_packets_delta: int,
        rx_dropped_delta: int,
        tx_dropped_delta: int,
        elapsed_sec: float,
    ):
        self.name = name
        self.t1_id = t1_id
        self.rx_bytes_delta = rx_bytes_delta
        self.tx_bytes_delta = tx_bytes_delta
        self.rx_packets_delta = rx_packets_delta
        self.tx_packets_delta = tx_packets_delta
        self.rx_dropped_delta = rx_dropped_delta
        self.tx_dropped_delta = tx_dropped_delta
        self.elapsed_sec = elapsed_sec

    # --- Computed rates ------------------------------------------------

    @property
    def rx_bytes_per_sec(self) -> float:
        if self.elapsed_sec <= 0:
            return 0.0
        return self.rx_bytes_delta / self.elapsed_sec

    @property
    def tx_bytes_per_sec(self) -> float:
        if self.elapsed_sec <= 0:
            return 0.0
        return self.tx_bytes_delta / self.elapsed_sec

    @property
    def rx_mb_per_sec(self) -> float:
        """Megabytes per second (1 MB = 1 000 000 bytes)."""
        return self.rx_bytes_per_sec / 1_000_000

    @property
    def tx_mb_per_sec(self) -> float:
        return self.tx_bytes_per_sec / 1_000_000

    @property
    def rx_mbps(self) -> float:
        """Megabits per second (1 Mbps = 1 000 000 bits/s)."""
        return self.rx_bytes_per_sec * 8 / 1_000_000

    @property
    def tx_mbps(self) -> float:
        return self.tx_bytes_per_sec * 8 / 1_000_000

    @property
    def rx_packets_per_sec(self) -> float:
        if self.elapsed_sec <= 0:
            return 0.0
        return self.rx_packets_delta / self.elapsed_sec

    @property
    def tx_packets_per_sec(self) -> float:
        if self.elapsed_sec <= 0:
            return 0.0
        return self.tx_packets_delta / self.elapsed_sec

    def __repr__(self) -> str:
        return (
            f"T1Delta({self.name}, "
            f"rx={self.rx_mbps:.2f} Mbps, tx={self.tx_mbps:.2f} Mbps, "
            f"Δt={self.elapsed_sec:.1f}s)"
        )


# ===================================================================
# NSX-T API Client
# ===================================================================

class NSXMonitor:
    """Client for the NSX-T Policy API to collect Tier-1 statistics."""

    def __init__(self, config: dict):
        self.base_url = config["nsx_url"].rstrip("/")
        self._auth = (config["username"], config["password"])
        self.timeout = config.get("timeout", REQUEST_TIMEOUT)
        if isinstance(self.timeout, int):
            self.timeout = (self.timeout, self.timeout)

        # Thread-local sessions so each worker thread gets its own
        # connection pool (thread-safe by construction).
        self._local = threading.local()

    # ------------------------------------------------------------------
    # Low-level HTTP
    # ------------------------------------------------------------------

    def _session(self) -> requests.Session:
        """Get a thread-local requests Session."""
        if not hasattr(self._local, "session"):
            sess = requests.Session()
            sess.auth = self._auth
            sess.verify = False
            sess.headers.update({
                "Accept": "application/json",
                "Content-Type": "application/json",
            })
            self._local.session = sess
        return self._local.session

    def _get(self, path: str, params: dict = None) -> Optional[dict]:
        """Perform a GET request, return parsed JSON or None on 404."""
        url = f"{self.base_url}{path}"
        try:
            resp = self._session().get(url, params=params, timeout=self.timeout)
        except requests.exceptions.Timeout:
            log.warning("Timeout: GET %s", url)
            raise
        except requests.exceptions.ConnectionError as exc:
            log.warning("Connection error: GET %s — %s", url, exc)
            raise
        except requests.exceptions.RequestException as exc:
            log.warning("Request failed: GET %s — %s", url, exc)
            raise

        if resp.status_code == 404:
            return None
        if resp.status_code == 401:
            log.error(
                "Authentication failed (HTTP 401) — check username / password "
                "in %s", CONFIG_PATH
            )
            sys.exit(1)
        if resp.status_code == 403:
            log.error(
                "Forbidden (HTTP 403) — check user '%s' has read permissions",
                self._auth[0],
            )
            sys.exit(1)

        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, json_body: dict = None) -> Optional[dict]:
        """Perform a POST request, return parsed JSON."""
        url = f"{self.base_url}{path}"
        try:
            resp = self._session().post(url, json=json_body, timeout=self.timeout)
        except requests.exceptions.Timeout:
            log.warning("Timeout: POST %s", url)
            raise
        except requests.exceptions.ConnectionError as exc:
            log.warning("Connection error: POST %s — %s", url, exc)
            raise
        except requests.exceptions.RequestException as exc:
            log.warning("Request failed: POST %s — %s", url, exc)
            raise

        if resp.status_code == 401:
            log.error(
                "Authentication failed (HTTP 401) — check username / password "
                "in %s", CONFIG_PATH
            )
            sys.exit(1)
        if resp.status_code == 403:
            log.error(
                "Forbidden (HTTP 403) — check user '%s' has read permissions",
                self._auth[0],
            )
            sys.exit(1)

        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Tier-1 discovery (paginated)
    # ------------------------------------------------------------------

    def get_all_tier1s(self) -> List[dict]:
        """Fetch the full list of Tier-1 routers, handling cursor pagination."""
        tier1s: List[dict] = []
        cursor = None
        page = 0

        while True:
            params: Dict[str, str] = {}
            if cursor:
                params["cursor"] = cursor

            data = self._get("/policy/api/v1/infra/tier-1s", params=params)
            if data is None:
                log.error("Tier-1 list endpoint returned 404")
                return []

            results = data.get("results", [])
            tier1s.extend(results)
            page += 1

            cursor = data.get("cursor")
            if not cursor:
                break

            log.debug("Page %d: %d results (cursor=%s)", page, len(results), cursor)

        log.info("Discovered %d Tier-1 routers", len(tier1s))
        return tier1s

    # ------------------------------------------------------------------
    # Single T1 statistics
    # ------------------------------------------------------------------

    def get_t1_statistics(self, t1_id: str) -> Optional[dict]:
        """Fetch the traffic statistics summary for one Tier-1 router."""
        path = (
            f"/policy/api/v1/infra/tier-1s/{t1_id}"
            f"/tier-0-interface/statistics/summary"
        )
        return self._get(path)

    def collect_one_t1(self, t1_info: dict) -> Optional[T1Snapshot]:
        """Collect a snapshot for a single T1; return None on failure."""
        t1_id = t1_info["id"]
        display_name = t1_info.get("display_name", "")
        name = display_name or t1_id

        try:
            stats = self.get_t1_statistics(t1_id)
        except requests.exceptions.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "?"
            if status == 429:
                log.warning("T1 '%s' (%s): rate limited (429), skipped", name, t1_id)
            elif status == 400:
                log.debug("T1 '%s' (%s): bad request (400) — no T0 interface?", name, t1_id)
            else:
                log.warning("T1 '%s' (%s): HTTP %s — %s", name, t1_id, status, exc)
            return None
        except Exception as exc:
            log.warning("T1 '%s' (%s): failed — %s", name, t1_id, exc)
            return None

        if stats is None:
            # 404 — this T1 probably has no tier-0 interface
            log.debug("T1 '%s' (%s): statistics endpoint returned 404 (no tier-0 iface?)", name, t1_id)
            return None

        try:
            rx = stats.get("rx", {})
            tx = stats.get("tx", {})
            timestamp_ms = stats.get("last_update_timestamp", 0)

            return T1Snapshot(
                t1_id=t1_id,
                display_name=display_name,
                rx_bytes=rx.get("total_bytes", 0),
                tx_bytes=tx.get("total_bytes", 0),
                rx_packets=rx.get("total_packets", 0),
                tx_packets=tx.get("total_packets", 0),
                rx_dropped=rx.get("dropped_packets", 0),
                tx_dropped=tx.get("dropped_packets", 0),
                timestamp_ms=timestamp_ms,
            )
        except Exception as exc:
            log.warning("Error parsing stats for T1 '%s' (%s): %s", name, t1_id, exc)
            return None

    # ------------------------------------------------------------------
    # Full snapshot
    # ------------------------------------------------------------------

    def collect_snapshot(self, max_workers: int = DEFAULT_WORKERS,
                         t1_names: Optional[List[str]] = None) -> Tuple[float, List[T1Snapshot]]:
        """
        Collect statistics for Tier-1 routers in parallel.

        Args:
            max_workers: Number of parallel worker threads.
            t1_names: If provided, only collect T1s whose display_name or id
                      matches one of these values (case-insensitive).

        Returns:
            (start_timestamp_epoch, list_of_T1Snapshot)
        """
        tier1s = self.get_all_tier1s()
        if not tier1s:
            log.error("No Tier-1 routers returned by the API")
            return time.time(), []

        # Filter by specific T1 name(s) if requested
        if t1_names:
            names_lower = [n.lower() for n in t1_names]
            filtered: List[dict] = []
            for t1 in tier1s:
                t1_display = (t1.get("display_name") or "").lower()
                t1_id = (t1.get("id") or "").lower()
                if any(n in t1_display or n in t1_id for n in names_lower):
                    filtered.append(t1)
            if not filtered:
                log.warning("No T1s matched filter %s (out of %d total)", t1_names, len(tier1s))
                return time.time(), []
            tier1s = filtered
            log.info("Filtered to %d T1s matching '%s'", len(tier1s), t1_names)

        start_ts = time.time()
        snapshots: List[T1Snapshot] = []
        errors = 0
        total = len(tier1s)

        log.info("Collecting statistics for %d T1s (%d workers)…", total, max_workers)

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            fut_map = {pool.submit(self.collect_one_t1, t1): t1 for t1 in tier1s}

            done = 0
            for future in as_completed(fut_map):
                done += 1
                t1 = fut_map[future]
                t1_name = t1.get("display_name") or t1["id"]
                try:
                    snap = future.result()
                    if snap is not None:
                        snapshots.append(snap)
                    else:
                        errors += 1
                except Exception as exc:
                    errors += 1
                    log.warning("Unhandled error for T1 '%s' (%s): %s", t1_name, t1["id"], exc)

                if done % 50 == 0 or done == total:
                    log.info(
                        "Progress: %d/%d — %d OK, %d errors",
                        done, total, len(snapshots), errors,
                    )

        elapsed = time.time() - start_ts
        log.info(
            "Snapshot done: %d/%d successful, %d errors in %.1fs",
            len(snapshots), total, errors, elapsed,
        )
        return start_ts, snapshots

    # ------------------------------------------------------------------
    # Batch snapshot (Batch API — single POST for all T1s)
    # ------------------------------------------------------------------

    def _parse_stats_body(self, t1_id: str, display_name: str, body: dict) -> Optional[T1Snapshot]:
        """Parse a statistics response body into a T1Snapshot."""
        try:
            rx = body.get("rx", {})
            tx = body.get("tx", {})
            timestamp_ms = body.get("last_update_timestamp", 0)
            return T1Snapshot(
                t1_id=t1_id,
                display_name=display_name,
                rx_bytes=rx.get("total_bytes", 0),
                tx_bytes=tx.get("total_bytes", 0),
                rx_packets=rx.get("total_packets", 0),
                tx_packets=tx.get("total_packets", 0),
                rx_dropped=rx.get("dropped_packets", 0),
                tx_dropped=tx.get("dropped_packets", 0),
                timestamp_ms=timestamp_ms,
            )
        except Exception as exc:
            log.warning("Error parsing stats for T1 '%s' (%s): %s", display_name or t1_id, t1_id, exc)
            return None

    def collect_snapshot_batch(self) -> Tuple[float, List[T1Snapshot]]:
        """
        Collect statistics for *all* Tier-1 routers via the Batch API.

        Sends a single POST with 400 URIs inside — NSX-T processes them
        server-side and returns all results in one response.
        """
        tier1s = self.get_all_tier1s()
        if not tier1s:
            log.error("No Tier-1 routers returned by the API")
            return time.time(), []

        start_ts = time.time()
        total = len(tier1s)

        log.info("Collecting statistics for %d T1s via Batch API (1 POST)…", total)

        # Build batch request items
        # Batch endpoint: POST /policy/api/v1/batch
        # Each item URI is relative to /policy/api/v1/
        requests = []
        t1_map = {}  # position-in-array -> t1_info
        for i, t1 in enumerate(tier1s):
            t1_id = t1["id"]
            requests.append({
                "method": "GET",
                "uri": f"/policy/api/v1/infra/tier-1s/{t1_id}/tier-0-interface/statistics/summary",
            })
            t1_map[str(i)] = t1

        batch_body = {
            "continue_on_error": True,
            "requests": requests,
        }

        # Send one POST instead of 400 GETs
        try:
            data = self._post("/api/v1/batch", json_body=batch_body)
        except Exception as exc:
            log.error("Batch API request failed: %s", exc)
            log.error("Falling back to parallel GET mode. Use without --batch.")
            return start_ts, []

        if data is None:
            log.error("Batch API returned no data — empty response")
            return start_ts, []

        results = data.get("results", [])
        snapshots: List[T1Snapshot] = []
        errors = 0
        skipped = 0  # 404s (no tier-0 interface)

        log.info("Processing %d batch responses…", len(results))

        for i, result in enumerate(results):
            code = result.get("code", 0)
            t1 = t1_map.get(str(i))
            if not t1:
                continue

            t1_id = t1["id"]
            display_name = t1.get("display_name", "")

            if code == 200 and result.get("body"):
                snap = self._parse_stats_body(t1_id, display_name, result["body"])
                if snap:
                    snapshots.append(snap)
                else:
                    errors += 1
            elif code == 404:
                skipped += 1
            else:
                errors += 1
                log.debug(
                    "T1 '%s' (%s): HTTP %d",
                    display_name or t1_id, t1_id, code,
                )

        elapsed = time.time() - start_ts
        log.info(
            "Batch snapshot done: %d OK, %d skipped (no T0 iface), "
            "%d errors in %.1fs",
            len(snapshots), skipped, errors, elapsed,
        )
        return start_ts, snapshots

    # ------------------------------------------------------------------
    # Edge placement & HA status
    # ------------------------------------------------------------------

    def _get_paginated(self, path: str) -> List[dict]:
        """Fetch all results from a paginated NSX API endpoint."""
        all_results: List[dict] = []
        cursor = None
        page = 0
        while True:
            params: Dict[str, str] = {}
            if cursor:
                params["cursor"] = cursor
            data = self._get(path, params=params)
            if not data:
                break
            results = data.get("results", [])
            all_results.extend(results)
            page += 1
            cursor = data.get("cursor")
            if not cursor:
                break
            log.debug("Page %d: %d results (cursor=%s)", page, len(results), cursor)
        log.debug("Fetched %d items from %s", len(all_results), path)
        return all_results

    def _resolve_ha_from_status(
        self,
        status: dict,
        tn_map: dict[str, str],
    ) -> tuple[str, str, str]:
        """
        Parse HA status response in any NSX-T format.
        Returns (ha_active, ha_standby, ha_mode).
        """
        ha_active = ""
        ha_standby = ""
        ha_mode = ""

        if not status:
            return ha_active, ha_standby, ha_mode

        # Format 1: per_node_status (NSX 4.x)
        per_node = status.get("per_node_status", [])
        if isinstance(per_node, list) and per_node:
            for pns in per_node:
                tn_id = pns.get("transport_node_id", "")
                tn_name = tn_map.get(tn_id, tn_id)
                role = pns.get("high_availability_status", "")
                if role == "ACTIVE":
                    ha_active = tn_name
                elif role == "STANDBY":
                    ha_standby = tn_name
            if ha_active or ha_standby:
                ha_mode = "ACTIVE_STANDBY"

        # Format 2: transport_node_statuses (NSX-T 3.x)
        if not ha_active:
            tn_statuses = status.get("transport_node_statuses", [])
            if isinstance(tn_statuses, list):
                for tn_s in tn_statuses:
                    tn_id = tn_s.get("transport_node_id", "")
                    tn_name = tn_map.get(tn_id, tn_id)
                    role = tn_s.get("ha_role", "")
                    if role == "ACTIVE":
                        ha_active = tn_name
                    elif role == "STANDBY":
                        ha_standby = tn_name
                if tn_statuses and (ha_active or ha_standby):
                    ha_mode = "ACTIVE_STANDBY"

        # Format 3: service_router_id (NSX 4.x fallback)
        if not ha_active:
            sr_id = status.get("service_router_id", "")
            if sr_id:
                ha_active = tn_map.get(sr_id, sr_id)
                ha_mode = status.get("high_availability_mode", "ACTIVE_STANDBY")

        # Format 4: high_availability_status (overall)
        if not ha_mode:
            ha_status_str = status.get("high_availability_status", "")
            if ha_status_str:
                ha_mode = "ACTIVE_STANDBY"

        return ha_active, ha_standby, ha_mode

    def collect_t1_edge_placement(
        self, max_workers: int = DEFAULT_WORKERS
    ) -> List[T1EdgeInfo]:
        """
        Collect edge placement and HA status for all Tier-1 routers.

        For each T1, resolves:
          - Edge cluster name (from locale-services)
          - Preferred edge transport node hostnames
          - Active/Standby HA status (from logical-router status)

        Uses parallel workers for locale-services and LR status calls.
        """
        tier1s = self.get_all_tier1s()
        if not tier1s:
            log.error("No Tier-1 routers returned by the API")
            return []

        log.info("Collecting edge placement for %d T1s…", len(tier1s))

        # --- 1. Pre-load maps: edge-cluster + transport-node (paginated) ---
        ec_list = self._get_paginated("/api/v1/edge-clusters")
        ec_map: dict[str, str] = {}
        for ec in ec_list:
            ec_map[ec["id"]] = ec.get("display_name", ec["id"])
        log.debug("Loaded %d edge clusters", len(ec_map))

        tn_list = self._get_paginated("/api/v1/transport-nodes")
        tn_map: dict[str, str] = {}
        for tn in tn_list:
            tn_map[tn["id"]] = tn.get("display_name", tn["id"])
        log.debug("Loaded %d transport nodes", len(tn_map))

        # --- 2. Collect locale-services for all T1s (parallel) ---
        ls_map: dict[str, list] = {}
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            fut_map = {}
            for t1 in tier1s:
                tid = t1["id"]
                fut = pool.submit(
                    self._get,
                    f"/policy/api/v1/infra/tier-1s/{tid}/locale-services",
                )
                fut_map[fut] = tid

            for future in as_completed(fut_map):
                tid = fut_map[future]
                try:
                    data = future.result()
                    if data and data.get("results"):
                        ls_map[tid] = data["results"]
                except Exception:
                    pass
        log.debug("Locale-services collected for %d T1s", len(ls_map))

        # --- 3. Get all logical routers (TIER1) for HA status ---
        lr_data = self._get("/api/v1/logical-routers?router_type=TIER1")
        logical_routers = lr_data.get("results") or [] if lr_data else []
        log.debug("Fetched %d logical routers (TIER1)", len(logical_routers))

        # Index LRs by edge_cluster_id (from user's data: LR has `edge_cluster_id`)
        lr_by_cluster: dict[str, list[dict]] = {}
        lr_by_name_global: dict[str, dict] = {}
        for lr in logical_routers:
            dn = lr.get("display_name", "")
            ec_id = lr.get("edge_cluster_id", "")
            if dn:
                lr_by_name_global[dn] = lr
                if ec_id:
                    lr_by_cluster.setdefault(ec_id, []).append(lr)

        # Collect HA statuses (parallel)
        ha_statuses: dict[str, dict] = {}
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            fut_map = {}
            for lr in logical_routers:
                dn = lr.get("display_name", "")
                if dn and lr.get("id"):
                    fut = pool.submit(
                        self._get,
                        f"/api/v1/logical-routers/{lr['id']}/status",
                    )
                    fut_map[fut] = dn

            for future in as_completed(fut_map):
                dn = fut_map[future]
                try:
                    data = future.result()
                    if data:
                        ha_statuses[dn] = data
                except Exception:
                    pass
        log.debug("HA statuses collected for %d logical routers", len(ha_statuses))

        # --- 4. Build T1EdgeInfo objects ---
        result: list[T1EdgeInfo] = []
        for t1 in tier1s:
            t1_id = t1["id"]
            display_name = t1.get("display_name", "") or t1_id

            # Locale-services → edge cluster + preferred edges
            edge_cluster_name = ""
            t1_ec_id = ""
            preferred_edges: list[str] = []

            services = ls_map.get(t1_id, [])
            if services:
                ls = services[0]
                ec_path = ls.get("edge_cluster_path", "")
                if ec_path:
                    t1_ec_id = ec_path.strip("/").split("/")[-1]
                    edge_cluster_name = ec_map.get(t1_ec_id, t1_ec_id)

                for edge_path in ls.get("preferred_edge_paths", []):
                    tn_id = edge_path.strip("/").split("/")[-1]
                    tn_name = tn_map.get(tn_id, tn_id)
                    if tn_name != tn_id or not edge_cluster_name:
                        preferred_edges.append(tn_name)

            # Match T1 to logical router by edge_cluster_id + display_name
            lr = None
            candidates = lr_by_cluster.get(t1_ec_id, []) if t1_ec_id else []

            # 1) Exact display_name match within same edge cluster
            for c in candidates:
                if c.get("display_name") == display_name:
                    lr = c
                    break

            # 2) Partial id match within same edge cluster
            if not lr:
                for c in candidates:
                    dn = c.get("display_name", "")
                    if t1_id in dn or dn in t1_id:
                        lr = c
                        log.debug("T1 '%s' matched LR '%s' by partial id in cluster '%s'",
                                  display_name, dn, t1_ec_id)
                        break

            # 3) Fallback: global match by display_name (any cluster)
            if not lr:
                lr = lr_by_name_global.get(display_name)
                if lr:
                    log.debug("T1 '%s' matched LR globally (no cluster filter)", display_name)

            lr_key = lr.get("display_name", "") if lr else ""
            ha_active = ""
            ha_standby = ""
            ha_mode = ""

            if lr and lr_key:
                status = ha_statuses.get(lr_key)
                if not status:
                    log.debug("T1 '%s': no HA status found for LR '%s'", display_name, lr_key)
                ha_active, ha_standby, ha_mode = self._resolve_ha_from_status(status, tn_map)

            # If preferred_edges empty but we have HA edges — use those
            if not preferred_edges:
                if ha_active:
                    preferred_edges.append(ha_active)
                if ha_standby and ha_standby not in preferred_edges:
                    preferred_edges.append(ha_standby)

            result.append(T1EdgeInfo(
                t1_id=t1_id,
                display_name=display_name,
                edge_cluster_name=edge_cluster_name,
                preferred_edges=preferred_edges,
                ha_active_edge=ha_active,
                ha_standby_edge=ha_standby,
                ha_mode=ha_mode,
            ))

        with_ec = sum(1 for r in result if r.edge_cluster_name)
        with_ha = sum(1 for r in result if r.ha_active_edge)
        with_standby = sum(1 for r in result if r.ha_standby_edge)
        log.info(
            "Edge placement done: %d T1s — %d with edge cluster, "
            "%d with active edge, %d with standby edge",
            len(result), with_ec, with_ha, with_standby,
        )
        return result


# ===================================================================
# Delta Computation
# ===================================================================

def compute_deltas(
    snap1_list: List[T1Snapshot],
    snap2_list: List[T1Snapshot],
    fallback_elapsed_sec: float = 1.0,
) -> Dict[str, T1Delta]:
    """
    Compute deltas between two snapshots, matched by T1 ID.

    The elapsed time for rate calculation is taken from the API's
    *last_update_timestamp* difference when both are valid and positive;
    otherwise the *fallback_elapsed_sec* (snapshot wall-clock delta) is used.

    Returns a dict of ``{t1_id: T1Delta}``.
    """
    by_id_1 = {s.t1_id: s for s in snap1_list}
    by_id_2 = {s.t1_id: s for s in snap2_list}

    deltas: Dict[str, T1Delta] = {}
    matched = 0
    snap1_only = 0
    snap2_only = 0

    for t1_id, s2 in by_id_2.items():
        s1 = by_id_1.get(t1_id)
        if s1 is None:
            snap2_only += 1
            continue

        # Determine elapsed time
        ts1 = s1.timestamp_ms / 1000.0 if s1.timestamp_ms else 0.0
        ts2 = s2.timestamp_ms / 1000.0 if s2.timestamp_ms else 0.0

        if ts1 > 0 and ts2 > 0 and ts2 > ts1:
            elapsed = ts2 - ts1
        else:
            elapsed = fallback_elapsed_sec

        delta = T1Delta(
            name=s2.name,
            t1_id=t1_id,
            rx_bytes_delta=max(0, s2.rx_bytes - s1.rx_bytes),
            tx_bytes_delta=max(0, s2.tx_bytes - s1.tx_bytes),
            rx_packets_delta=max(0, s2.rx_packets - s1.rx_packets),
            tx_packets_delta=max(0, s2.tx_packets - s1.tx_packets),
            rx_dropped_delta=max(0, s2.rx_dropped - s1.rx_dropped),
            tx_dropped_delta=max(0, s2.tx_dropped - s1.tx_dropped),
            elapsed_sec=elapsed,
        )
        deltas[t1_id] = delta
        matched += 1

    for t1_id in by_id_1:
        if t1_id not in by_id_2:
            snap1_only += 1

    log.info(
        "Delta: %d matched, %d only in snap1, %d only in snap2",
        matched, snap1_only, snap2_only,
    )
    return deltas


# ===================================================================
# Snapshot Persistence (JSON)
# ===================================================================

def save_snapshot(snapshots: List[T1Snapshot], timestamp: float, filepath: str = None) -> str:
    """Save a snapshot to JSON file. Returns the path of the saved file."""
    if filepath is None:
        ts_str = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        filepath = str(SCRIPT_DIR / f"snapshot_{ts_str}.json")

    data = {
        "timestamp": timestamp,
        "timestamp_iso": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
        "t1_count": len(snapshots),
        "t1_list": [s.to_dict() for s in snapshots],
    }

    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)

    log.info("Snapshot saved → %s  (%d T1s)", filepath, len(snapshots))
    return filepath


def load_snapshot(filepath: str) -> Tuple[float, List[T1Snapshot]]:
    """Load a snapshot from a JSON file. Returns (timestamp, list_of_T1Snapshot)."""
    with open(filepath, "r") as fh:
        data = json.load(fh)

    timestamp = data.get("timestamp", 0.0)
    t1_list = [T1Snapshot.from_dict(item) for item in data.get("t1_list", [])]

    log.info(
        "Loaded snapshot ← %s  (ts=%s, %d T1s)",
        filepath, data.get("timestamp_iso", timestamp), len(t1_list),
    )
    return timestamp, t1_list


# ===================================================================
# HTML Report Generator
# ===================================================================

def _fmt_mbps(val: float) -> str:
    """Format Mbps value with appropriate precision."""
    if val >= 1000:
        return f"{val:.2f}"
    if val >= 1:
        return f"{val:.2f}"
    if val >= 0.001:
        return f"{val:.4f}"
    return f"{val:.6f}"


def _fmt_mbps_color(val: float) -> str:
    """Return a CSS colour class based on Mbps value."""
    if val > 1000:
        return "color: #dc3545; font-weight: bold;"
    if val > 100:
        return "color: #e67e22; font-weight: bold;"
    return ""


def generate_html_report(
    deltas_dict: Dict[str, T1Delta],
    total_t1s: int,
    successful_t1s: int,
    errors: int,
    snap1_ts: float,
    snap2_ts: float,
    title: str = "NSX-T Tier-1 Router Traffic Report",
    edge_map: Optional[Dict[str, T1EdgeInfo]] = None,
) -> str:
    """Build a self-contained HTML report string from the delta data.

    If *edge_map* is provided, extra columns for edge cluster and HA
    role are added after the T1 Name column.
    """

    # Sort by TX Mbps descending
    sorted_deltas = sorted(deltas_dict.values(), key=lambda d: d.tx_mbps, reverse=True)

    edge_columns = edge_map is not None
    edge_extra_header = ""
    if edge_columns:
        edge_extra_header = (
            '            <th class="sortable">Edge Cluster</th>\n'
            '            <th class="sortable">Active Edge</th>\n'
            '            <th class="sortable">HA Mode</th>\n'
        )

    # --- Build table rows ------------------------------------------------
    rows_html = ""
    for i, d in enumerate(sorted_deltas, 1):
        rx_mb = d.rx_mb_per_sec
        tx_mb = d.tx_mb_per_sec
        rx_mbps = d.rx_mbps
        tx_mbps = d.tx_mbps
        rx_pps = d.rx_packets_per_sec
        tx_pps = d.tx_packets_per_sec

        tx_color = _fmt_mbps_color(tx_mbps)
        rx_color = _fmt_mbps_color(rx_mbps)

        # Short ID for display
        short_id = d.t1_id[:12] + "…" if len(d.t1_id) > 12 else d.t1_id

        # Edge info columns (optional)
        edge_cells = ""
        if edge_columns:
            ei = edge_map.get(d.t1_id)
            if ei and ei.edge_cluster_name:
                ec = ei.edge_cluster_name
                active = ei.ha_active_edge or "—"
                ha = ei.ha_mode or "—"
                active_style = ""
                if ei.ha_active_edge:
                    active_style = " style='color:#3fb950;font-weight:600'"
                edge_cells = (
                    f"  <td>{ec}</td>\n"
                    f"  <td{active_style}>{active}</td>\n"
                    f"  <td>{ha}</td>\n"
                )
            else:
                edge_cells = "  <td>—</td>\n  <td>—</td>\n  <td>—</td>\n"

        col_span_extra = "3" if edge_columns else ""

        rows_html += (
            f"<tr>\n"
            f"  <td>{i}</td>\n"
            f"  <td>{d.name}</td>\n"
            f"{edge_cells}"
            f"  <td class='mono' title='{d.t1_id}'>{short_id}</td>\n"
            f"  <td class='num'>{rx_mb:.4f}</td>\n"
            f"  <td class='num'>{tx_mb:.4f}</td>\n"
            f"  <td class='num' style='{rx_color}'>{_fmt_mbps(rx_mbps)}</td>\n"
            f"  <td class='num' style='{tx_color}'>{_fmt_mbps(tx_mbps)}</td>\n"
            f"  <td class='num'>{rx_pps:.1f}</td>\n"
            f"  <td class='num'>{tx_pps:.1f}</td>\n"
            f"  <td class='num'>{d.rx_bytes_delta / 1_000_000_000:.3f}</td>\n"
            f"  <td class='num'>{d.tx_bytes_delta / 1_000_000_000:.3f}</td>\n"
            f"  <td class='num'>{d.elapsed_sec:.1f}s</td>\n"
            f"</tr>\n"
        )

    # --- Summary stats ---------------------------------------------------
    dt1 = datetime.fromtimestamp(snap1_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    dt2 = datetime.fromtimestamp(snap2_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    elapsed_total = snap2_ts - snap1_ts

    total_tx_gb = sum(d.tx_bytes_delta for d in sorted_deltas) / 1_000_000_000
    total_rx_gb = sum(d.rx_bytes_delta for d in sorted_deltas) / 1_000_000_000
    top_tx_mbps = sorted_deltas[0].tx_mbps if sorted_deltas else 0.0

    # --- Assemble HTML ---------------------------------------------------
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                 'Helvetica Neue', Arial, sans-serif;
    background: #f0f2f5;
    color: #1a1a2e;
    padding: 24px;
  }}
  .container {{ max-width: 1600px; margin: 0 auto; }}
  h1 {{ font-size: 26px; font-weight: 700; margin-bottom: 4px; color: #16213e; }}
  .subtitle {{ color: #6c757d; font-size: 14px; margin-bottom: 24px; }}
  .subtitle a {{ color: #0d6efd; text-decoration: none; }}

  /* Summary cards */
  .summary {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }}
  .card {{
    background: #fff;
    border-radius: 10px;
    padding: 16px 20px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.08);
    flex: 1 1 140px;
    min-width: 130px;
  }}
  .card .label {{
    font-size: 11px;
    color: #8c8c8c;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    margin-bottom: 4px;
  }}
  .card .value {{ font-size: 24px; font-weight: 700; }}
  .card .value.blue  {{ color: #0d6efd; }}
  .card .value.green {{ color: #198754; }}
  .card .value.red   {{ color: #dc3545; }}
  .card .value.amber {{ color: #e67e22; }}

  /* Table */
  .table-wrap {{
    background: #fff;
    border-radius: 10px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.08);
    overflow-x: auto;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; min-width: 1000px; }}
  th {{
    background: #16213e;
    color: #fff;
    padding: 10px 8px;
    text-align: left;
    font-weight: 500;
    white-space: nowrap;
    position: sticky;
    top: 0;
  }}
  td {{ padding: 7px 8px; border-bottom: 1px solid #e9ecef; vertical-align: top; }}
  tr:hover td {{ background: #f0f4ff !important; }}
  tr:nth-child(even) td {{ background: #fafbfc; }}
  tr:nth-child(even):hover td {{ background: #f0f4ff !important; }}
  .num {{ text-align: right; font-family: 'SF Mono', 'Consolas', 'Liberation Mono', monospace; }}

  /* Sortable headers */
  th.sortable {{ cursor: pointer; user-select: none; }}
  th.sortable:hover {{ background: #1a2d5a; }}
  th.sortable::after {{ content: ' ↕'; font-size: 10px; opacity: 0.4; margin-left: 2px; }}
  th.sortable.asc::after {{ content: ' ↑'; opacity: 0.9; }}
  th.sortable.desc::after {{ content: ' ↓'; opacity: 0.9; }}

  .mono {{ font-family: 'SF Mono', 'Consolas', 'Liberation Mono', monospace; font-size: 11px; color: #6c757d; }}

  /* Footer */
  .footer {{
    text-align: center;
    color: #adb5bd;
    font-size: 11px;
    margin-top: 20px;
    padding: 12px 0;
  }}
</style>
</head>
<body>
<div class="container">

  <h1>{title}</h1>
  <div class="subtitle">
    Period: {dt1} &rarr; {dt2} &nbsp;·&nbsp; Δt = {elapsed_total:.1f}s ({elapsed_total/3600:.4f}h)
  </div>

  <div class="summary">
    <div class="card">
      <div class="label">Tier-1 Routers</div>
      <div class="value blue">{total_t1s}</div>
    </div>
    <div class="card">
      <div class="label">Successful</div>
      <div class="value green">{successful_t1s}</div>
    </div>
    <div class="card">
      <div class="label">Errors / Skipped</div>
      <div class="value red">{errors}</div>
    </div>
    <div class="card">
      <div class="label">Top TX (Mbps)</div>
      <div class="value amber">{top_tx_mbps:.2f}</div>
    </div>
    <div class="card">
      <div class="label">Total RX (GB)</div>
      <div class="value blue">{total_rx_gb:.4f}</div>
    </div>
    <div class="card">
      <div class="label">Total TX (GB)</div>
      <div class="value blue">{total_tx_gb:.4f}</div>
    </div>
  </div>

  <div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th class="sortable">#</th>
        <th class="sortable">T1 Name</th>
{edge_extra_header}        <th class="sortable">ID</th>
        <th class="sortable num">RX MB/s</th>
        <th class="sortable num">TX MB/s</th>
        <th class="sortable num">RX Mbps</th>
        <th class="sortable num">TX Mbps</th>
        <th class="sortable num">RX pkt/s</th>
        <th class="sortable num">TX pkt/s</th>
        <th class="sortable num">RX GB</th>
        <th class="sortable num">TX GB</th>
        <th class="sortable num">Interval</th>
      </tr>
    </thead>
    <tbody>
{rows_html}
    </tbody>
  </table>
  </div>

  <div class="footer">
    Generated by nsx-monitor.py &mdash; {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}
  </div>

</div>
<script>
const table = document.querySelector('table');
const tbody = table.querySelector('tbody');

table.querySelectorAll('th.sortable').forEach((th, colIdx) => {{
  th.addEventListener('click', () => {{
    const isAsc = th.classList.contains('asc');
    table.querySelectorAll('th.sortable').forEach(h => h.classList.remove('asc', 'desc'));
    th.classList.add(isAsc ? 'desc' : 'asc');

    const rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort((a, b) => {{
      let va = a.cells[colIdx].textContent.trim();
      let vb = b.cells[colIdx].textContent.trim();
      const na = parseFloat(va.replace(/[^0-9.-]/g, ''));
      const nb = parseFloat(vb.replace(/[^0-9.-]/g, ''));
      if (!isNaN(na) && !isNaN(nb)) {{
        return isAsc ? na - nb : nb - na;
      }}
      return isAsc ? va.localeCompare(vb) : vb.localeCompare(va);
    }});
    rows.forEach(r => tbody.appendChild(r));
  }});
}});
</script>
</body>
</html>"""
    return html


# ===================================================================
# Edge Placement HTML Report Generator
# ===================================================================

def generate_edge_html_report(
    edge_info_list: List[T1EdgeInfo],
    title: str = "NSX-T T1 Edge Placement Report",
) -> str:
    """Build a self-contained HTML report for T1 → Edge mapping + HA status."""

    # Stats
    total = len(edge_info_list)
    with_ec = sum(1 for e in edge_info_list if e.edge_cluster_name)
    without_ec = total - with_ec
    with_active = sum(1 for e in edge_info_list if e.ha_active_edge)
    with_standby = sum(1 for e in edge_info_list if e.ha_standby_edge)
    active_only = with_active - with_standby  # non-HA T1s that are just active

    # Sort: ones with edge cluster first, then by name
    sorted_list = sorted(
        edge_info_list,
        key=lambda e: (0 if e.edge_cluster_name else 1, e.name.lower()),
    )

    rows_html = ""
    for i, e in enumerate(sorted_list, 1):
        cluster = e.edge_cluster_name or "—"
        preferred = ", ".join(e.preferred_edges) if e.preferred_edges else "—"
        active = e.ha_active_edge or "—"
        standby = e.ha_standby_edge or "—"
        mode = e.ha_mode or "—"

        active_style = " style='color:#3fb950;font-weight:600'" if e.ha_active_edge else ""
        standby_style = " style='color:#8b949e'" if e.ha_standby_edge else ""

        cluster_cls = " class='cluster'" if e.edge_cluster_name else ""

        rows_html += (
            f"<tr>\n"
            f"  <td>{i}</td>\n"
            f"  <td>{e.name}</td>\n"
            f"  <td{cluster_cls}>{cluster}</td>\n"
            f"  <td>{preferred}</td>\n"
            f"  <td{active_style}>{active}</td>\n"
            f"  <td{standby_style}>{standby}</td>\n"
            f"  <td>{mode}</td>\n"
            f"</tr>\n"
        )

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                 'Helvetica Neue', Arial, sans-serif;
    background: #0d1117;
    color: #e6edf3;
    padding: 24px;
  }}
  .container {{ max-width: 1600px; margin: 0 auto; }}
  h1 {{ font-size: 24px; font-weight: 700; margin-bottom: 4px; color: #f0f6fc; }}
  .subtitle {{ color: #8b949e; font-size: 14px; margin-bottom: 24px; }}

  /* Summary cards */
  .summary {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }}
  .card {{
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px 20px;
    flex: 1 1 140px;
    min-width: 120px;
  }}
  .card .label {{
    font-size: 11px;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 4px;
  }}
  .card .value {{ font-size: 22px; font-weight: 700; }}
  .card .value.blue   {{ color: #58a6ff; }}
  .card .value.green  {{ color: #3fb950; }}
  .card .value.red    {{ color: #f85149; }}
  .card .value.amber  {{ color: #d29922; }}

  /* Table */
  .table-wrap {{
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    overflow-x: auto;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; min-width: 900px; }}
  th {{
    background: #1c2333;
    color: #8b949e;
    padding: 11px 12px;
    text-align: left;
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    border-bottom: 2px solid #30363d;
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
    position: sticky;
    top: 0;
  }}
  th:hover {{ color: #f0f6fc; background: #212a3e; }}
  th.sorted-asc::after {{ content: ' ▲'; font-size: 10px; color: #58a6ff; }}
  th.sorted-desc::after {{ content: ' ▼'; font-size: 10px; color: #58a6ff; }}
  td {{
    padding: 9px 12px;
    border-bottom: 1px solid #21262d;
    vertical-align: middle;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1c2333 !important; }}
  tr:nth-child(even) td {{ background: #0d1117; }}
  tr:nth-child(odd) td {{ background: #161b22; }}

  .cluster {{ border-left: 3px solid #58a6ff; }}

  .footer {{
    text-align: center;
    color: #484f58;
    font-size: 11px;
    margin-top: 20px;
    padding: 12px 0;
  }}

  .table-wrap::-webkit-scrollbar {{ height: 8px; }}
  .table-wrap::-webkit-scrollbar-track {{ background: #0d1117; }}
  .table-wrap::-webkit-scrollbar-thumb {{ background: #30363d; border-radius: 4px; }}
  .table-wrap::-webkit-scrollbar-thumb:hover {{ background: #484f58; }}
</style>
</head>
<body>
<div class="container">

  <h1>{title}</h1>
  <div class="subtitle">Generated: {ts}</div>

  <div class="summary">
    <div class="card">
      <div class="label">Total T1s</div>
      <div class="value blue">{total}</div>
    </div>
    <div class="card">
      <div class="label">With Edge Cluster</div>
      <div class="value green">{with_ec}</div>
    </div>
    <div class="card">
      <div class="label">Without Placement</div>
      <div class="value red">{without_ec}</div>
    </div>
    <div class="card">
      <div class="label">HA Active</div>
      <div class="value green">{with_active}</div>
    </div>
    <div class="card">
      <div class="label">HA Standby</div>
      <div class="value amber">{with_standby}</div>
    </div>
  </div>

  <div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th data-col="num" data-numeric="true">#</th>
        <th data-col="name">T1 Name</th>
        <th data-col="cluster">Edge Cluster</th>
        <th data-col="edges">Preferred Edges</th>
        <th data-col="active">Active Edge</th>
        <th data-col="standby">Standby Edge</th>
        <th data-col="mode">HA Mode</th>
      </tr>
    </thead>
    <tbody>
{rows_html}
    </tbody>
  </table>
  </div>

  <div class="footer">
    Generated by nsx-monitor.py &mdash; {ts}
  </div>

</div>
<script>
(function() {{
  'use strict';
  const table = document.querySelector('table');
  const tbody = table.querySelector('tbody');

  table.querySelectorAll('th').forEach((th, colIdx) => {{
    th.addEventListener('click', () => {{
      const isNumeric = th.hasAttribute('data-numeric');
      const isAsc = th.classList.contains('sorted-asc');
      table.querySelectorAll('th').forEach(h => h.classList.remove('sorted-asc', 'sorted-desc'));
      th.classList.add(isAsc ? 'sorted-desc' : 'sorted-asc');

      const rows = Array.from(tbody.querySelectorAll('tr'));
      rows.sort((a, b) => {{
        let va = a.cells[colIdx].textContent.trim();
        let vb = b.cells[colIdx].textContent.trim();
        if (isNumeric) {{
          const na = parseFloat(va.replace(/[^0-9.-]/g, ''));
          const nb = parseFloat(vb.replace(/[^0-9.-]/g, ''));
          if (!isNaN(na) && !isNaN(nb)) {{
            return isAsc ? na - nb : nb - na;
          }}
        }}
        return isAsc ? va.localeCompare(vb) : vb.localeCompare(va);
      }});
      rows.forEach(r => tbody.appendChild(r));
    }});
  }});
}})();
</script>
</body>
</html>"""
    return html


# ===================================================================
# Mode Handlers
# ===================================================================

def _print_top10(deltas: Dict[str, T1Delta]):
    """Print a top-10 list of busiest T1s to the console."""
    if not deltas:
        return
    sorted_d = sorted(deltas.values(), key=lambda d: d.tx_mbps, reverse=True)
    print()
    print("  Top 10 T1s by TX traffic:")
    print(f"  {'T1 Name':<30} {'RX Mbps':<10} {'TX Mbps':<10} {'RX MB/s':<10} {'TX MB/s':<10}")
    print("  " + "─" * 70)
    for d in sorted_d[:10]:
        print(
            f"  {d.name:<30} {d.rx_mbps:<10.2f} {d.tx_mbps:<10.2f} "
            f"{d.rx_mb_per_sec:<10.4f} {d.tx_mb_per_sec:<10.4f}"
        )
    print()


def _generate_and_save_report(
    deltas: Dict[str, T1Delta],
    total_t1s: int,
    successful_t1s: int,
    errors: int,
    snap1_ts: float,
    snap2_ts: float,
    output_path: str = "",
    edge_map: Optional[Dict[str, T1EdgeInfo]] = None,
) -> str:
    """Build the HTML report and write it to a file. Returns the file path."""
    if not output_path:
        ts_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = str(SCRIPT_DIR / f"report_{ts_str}.html")

    html = generate_html_report(
        deltas_dict=deltas,
        total_t1s=total_t1s,
        successful_t1s=successful_t1s,
        errors=errors,
        snap1_ts=snap1_ts,
        snap2_ts=snap2_ts,
        edge_map=edge_map,
    )
    with open(output_path, "w") as fh:
        fh.write(html)

    log.info("HTML report saved → %s", output_path)
    return output_path


# ------------------------------------------------------------------
# --snapshot
# ------------------------------------------------------------------

def handle_snapshot(monitor: NSXMonitor, args: argparse.Namespace):
    """Collect and save a snapshot of current T1 counters."""
    log.info("=== Mode: SNAPSHOT ===")
    t1_names = [args.t1_name] if args.t1_name else None
    ts, snapshots = monitor.collect_snapshot(max_workers=args.workers, t1_names=t1_names)
    if not snapshots:
        log.error("No statistics collected — nothing to save.")
        sys.exit(1)

    path = save_snapshot(snapshots, ts)
    print(f"\nSnapshot saved: {path}")
    print(f"  T1s collected: {len(snapshots)}")
    print(f"  Timestamp:     {datetime.fromtimestamp(ts, tz=timezone.utc)}")


# ------------------------------------------------------------------
# --report --snapshot-file <file>
# ------------------------------------------------------------------

def handle_report(monitor: NSXMonitor, args: argparse.Namespace):
    """Compare current counters against a saved snapshot."""
    log.info("=== Mode: REPORT ===")

    if not args.snapshot_file:
        log.error("--report requires --snapshot-file (-f).")
        sys.exit(1)

    snap_path = args.snapshot_file
    if not os.path.isfile(snap_path):
        log.error("Snapshot file not found: %s", snap_path)
        sys.exit(1)

    # Load saved snapshot
    snap1_ts, snap1_list = load_snapshot(snap_path)
    if not snap1_list:
        log.error("Loaded snapshot is empty — cannot proceed.")
        sys.exit(1)

    # Collect current snapshot
    t1_names = [args.t1_name] if args.t1_name else None
    snap2_ts, snap2_list = monitor.collect_snapshot(max_workers=args.workers, t1_names=t1_names)
    if not snap2_list:
        log.error("Current snapshot is empty")
        sys.exit(1)

    # Compute deltas
    fallback_elapsed = snap2_ts - snap1_ts
    deltas = compute_deltas(snap1_list, snap2_list, fallback_elapsed_sec=fallback_elapsed)
    if not deltas:
        log.warning("No matching T1s found between snapshots — delta is empty.")
        sys.exit(1)

    all_ids = {s.t1_id for s in snap1_list} | {s.t1_id for s in snap2_list}
    errors = len(all_ids) - len(deltas)

    report_path = _generate_and_save_report(
        deltas=deltas,
        total_t1s=len(all_ids),
        successful_t1s=len(deltas),
        errors=errors,
        snap1_ts=snap1_ts,
        snap2_ts=snap2_ts,
        output_path=args.output,
    )

    print(f"\nReport: {report_path}")
    print(f"  Snapshot 1: {len(snap1_list)} T1s  ({datetime.fromtimestamp(snap1_ts, tz=timezone.utc)})")
    print(f"  Snapshot 2: {len(snap2_list)} T1s  ({datetime.fromtimestamp(snap2_ts, tz=timezone.utc)})")
    print(f"  Matched:    {len(deltas)} T1s")
    print(f"  Errors:     {errors}")
    _print_top10(deltas)


# ------------------------------------------------------------------
# --minutes <N>
# ------------------------------------------------------------------

def handle_minutes(monitor: NSXMonitor, args: argparse.Namespace):
    """Snapshot, wait N minutes, snapshot again, produce delta report."""
    log.info("=== Mode: INTERVAL (%d minutes) ===", args.minutes)

    wait_sec = args.minutes * 60

    # --- First snapshot ---
    log.info("Taking initial snapshot…")
    t1_names = [args.t1_name] if args.t1_name else None
    snap1_ts, snap1_list = monitor.collect_snapshot(max_workers=args.workers, t1_names=t1_names)
    if not snap1_list:
        log.error("Initial snapshot is empty.")
        sys.exit(1)

    snap1_path = save_snapshot(snap1_list, snap1_ts)
    print(f"\nInitial snapshot: {snap1_path}  ({len(snap1_list)} T1s)")

    # --- Optional: collect edge info (during the wait window) ---
    edge_map: dict[str, T1EdgeInfo] = {}
    if args.with_edge_info:
        log.info("Collecting edge placement info (in parallel with wait)…")
        try:
            edge_list = monitor.collect_t1_edge_placement(max_workers=args.workers)
            edge_map = {e.t1_id: e for e in edge_list}
            log.info("Edge placement: %d T1s collected", len(edge_list))
        except Exception as exc:
            log.warning("Edge placement collection failed: %s", exc)

    # --- Wait ---
    resume_dt = datetime.fromtimestamp(time.time() + wait_sec, tz=timezone.utc)
    print(f"\nWaiting {args.minutes} minute(s) ({wait_sec}s)…")
    print(f"  Resume at ~ {resume_dt}")
    for remaining in range(wait_sec, 0, -60):
        mins, secs = divmod(remaining, 60)
        print(f"  {mins:2d}m {secs:02d}s remaining…", end="\r", flush=True)
        time.sleep(min(60, remaining))
    print(f"  Done waiting.{' ' * 20}")

    # --- Second snapshot ---
    log.info("Taking final snapshot…")
    snap2_ts, snap2_list = monitor.collect_snapshot(max_workers=args.workers, t1_names=t1_names)
    if not snap2_list:
        log.error("Final snapshot is empty")
        sys.exit(1)

    # --- Delta ---
    fallback_elapsed = snap2_ts - snap1_ts
    deltas = compute_deltas(snap1_list, snap2_list, fallback_elapsed_sec=fallback_elapsed)
    if not deltas:
        log.warning("No matching T1s found — delta is empty.")
        sys.exit(1)

    all_ids = {s.t1_id for s in snap1_list} | {s.t1_id for s in snap2_list}
    errors = len(all_ids) - len(deltas)

    report_path = _generate_and_save_report(
        deltas=deltas,
        total_t1s=len(all_ids),
        successful_t1s=len(deltas),
        errors=errors,
        snap1_ts=snap1_ts,
        snap2_ts=snap2_ts,
        output_path=args.output,
        edge_map=edge_map if edge_map else None,
    )

    print(f"\nReport: {report_path}")
    print(f"  Snapshot 1: {len(snap1_list)} T1s  ({datetime.fromtimestamp(snap1_ts, tz=timezone.utc)})")
    print(f"  Snapshot 2: {len(snap2_list)} T1s  ({datetime.fromtimestamp(snap2_ts, tz=timezone.utc)})")
    print(f"  Matched:    {len(deltas)} T1s")
    print(f"  Errors:     {errors}")
    print(f"  Wall-clock: {fallback_elapsed:.1f}s")
    _print_top10(deltas)


# ------------------------------------------------------------------
# --edge-map
# ------------------------------------------------------------------

def handle_edge_map(monitor: NSXMonitor, args: argparse.Namespace):
    """Collect and display T1 → Edge placement with HA status."""
    log.info("=== Mode: EDGE MAP ===")

    edge_info = monitor.collect_t1_edge_placement(max_workers=args.workers)
    if not edge_info:
        log.error("No edge placement data collected.")
        sys.exit(1)

    with_ec = sum(1 for e in edge_info if e.edge_cluster_name)
    with_ha = sum(1 for e in edge_info if e.ha_active_edge)

    # JSON output mode (for app.py subprocess)
    if getattr(args, "json", False):
        data = {
            "status": "ok",
            "total": len(edge_info),
            "with_edge_cluster": with_ec,
            "with_ha": with_ha,
            "t1_list": [e.to_dict() for e in edge_info],
        }
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return

    print(f"\nEdge Placement: {len(edge_info)} T1s collected")
    print(f"  With Edge Cluster: {with_ec}")
    print(f"  With HA Status:    {with_ha}")
    print()

    # Console table: top 20
    sorted_show = sorted(
        edge_info,
        key=lambda e: (0 if e.edge_cluster_name else 1, e.name.lower()),
    )[:20]

    print(f"  {'T1 Name':<30} {'Cluster':<20} {'Active Edge':<25} {'Standby Edge':<25} {'Mode':<14}")
    print("  " + "─" * 120)
    for e in sorted_show:
        cluster = e.edge_cluster_name or "—"
        active = e.ha_active_edge or "—"
        standby = e.ha_standby_edge or "—"
        mode = e.ha_mode or "—"
        print(f"  {e.name:<30} {cluster:<20} {active:<25} {standby:<25} {mode:<14}")

    if len(edge_info) > 20:
        print(f"  … and {len(edge_info) - 20} more T1s (use -o report.html for full view)")

    # Save HTML report if --output specified
    if args.output:
        html = generate_edge_html_report(edge_info)
        with open(args.output, "w") as fh:
            fh.write(html)
        print(f"\nHTML report saved → {args.output}")


# ===================================================================
# CLI argument parsing
# ===================================================================

def parse_args(argv: List[str] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="nsx-monitor.py",
        description="NSX-T Tier-1 Router Monitor — collect and compare traffic statistics.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\nExamples:\n  %(prog)s --snapshot\n  %(prog)s --report --snapshot-file snapshot_20250101_120000.json\n  %(prog)s --report -f snap.json -o report.html\n  %(prog)s --minutes 5\n  %(prog)s -m 10 -o /tmp/report.html\n        """,
    )

    # Modes (mutually exclusive enforced after parse)
    parser.add_argument(
        "--snapshot",
        action="store_true",
        help="Take a snapshot of current T1 counters and save to JSON",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate a delta report comparing current counters against a saved snapshot",
    )
    parser.add_argument(
        "--minutes", "-m",
        type=int,
        default=0,
        metavar="N",
        help="Monitor over N minutes: two snapshots N minutes apart, then delta report",
    )
    parser.add_argument(
        "--edge-map",
        action="store_true",
        help="Collect T1 → Edge placement with Active/Standby HA status",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="With --edge-map: output JSON to stdout (for app.py integration)",
    )

    # Snapshot file (required with --report)
    parser.add_argument(
        "--snapshot-file", "-f",
        type=str,
        default=None,
        metavar="FILE",
        help="Path to a saved snapshot JSON file (required with --report)",
    )

    # Output
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="",
        metavar="FILE",
        help="Path for the HTML report (auto-named if not specified)",
    )

    # Tuning
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        metavar="FILE",
        help="Path to config.yaml (default: next to the script)",
    )
    parser.add_argument(
        "--t1-name",
        type=str,
        default=None,
        metavar="NAME",
        help="Only collect traffic for a specific T1 (by display_name or id). Omit for all T1s.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        metavar="N",
        help="Number of parallel worker threads (default: %(default)s)",
    )
    parser.add_argument(
        "--with-edge-info",
        action="store_true",
        help="When used with --minutes or --report, also collect edge placement and "
             "add Edge Cluster / HA Role columns to the traffic report",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug-level logging",
    )

    return parser.parse_args(argv)


def load_config(config_path: Path = CONFIG_PATH) -> dict:
    """Load and validate the YAML configuration."""
    if not config_path.is_file():
        log.error("Configuration file not found: %s", config_path)
        log.error("Create a config.yaml next to the script with fields:")
        log.error("  nsx_url, username, password")
        sys.exit(1)

    with open(config_path, "r") as fh:
        config = yaml.safe_load(fh)

    if not isinstance(config, dict):
        log.error("config.yaml must be a YAML dictionary (key: value pairs).")
        sys.exit(1)

    missing = [k for k in ("nsx_url", "username", "password") if k not in config]
    if missing:
        log.error("Missing required field(s) in config.yaml: %s", ", ".join(missing))
        sys.exit(1)

    return config


# ===================================================================
# Entry Point
# ===================================================================

def main(argv: List[str] = None) -> None:
    args = parse_args(argv)

    # Log level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        log.debug("Debug logging enabled")

    # Ensure exactly one mode
    mode_count = sum([bool(args.snapshot), bool(args.report),
                      args.minutes > 0, bool(args.edge_map)])
    if mode_count == 0:
        log.error("No mode specified. Use --snapshot, --report, --minutes/-m, or --edge-map.")
        sys.exit(1)
    if mode_count > 1:
        log.error("Only one mode can be used at a time.")
        sys.exit(1)

    # Load config (custom path or default next to script)
    config_path = Path(args.config) if args.config else CONFIG_PATH
    config = load_config(config_path)
    monitor = NSXMonitor(config)

    # Route to handler
    if args.snapshot:
        handle_snapshot(monitor, args)
    elif args.report:
        handle_report(monitor, args)
    elif args.minutes > 0:
        if args.minutes < 1:
            log.warning("--minutes set to %d (minimum recommended is 1)", args.minutes)
        handle_minutes(monitor, args)
    elif args.edge_map:
        handle_edge_map(monitor, args)


if __name__ == "__main__":
    main()
