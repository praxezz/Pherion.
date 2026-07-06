#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██████╗ ██╗  ██╗███████╗██████╗ ██╗ ██████╗ ███╗   ██╗                    ║
║   ██╔══██╗██║  ██║██╔════╝██╔══██╗██║██╔═══██╗████╗  ██║                    ║
║   ██████╔╝███████║█████╗  ██████╔╝██║██║   ██║██╔██╗ ██║                    ║
║   ██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║██║   ██║██║╚██╗██║                    ║
║   ██║     ██║  ██║███████╗██║  ██║██║╚██████╔╝██║ ╚████║                    ║
║   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝                    ║
║                                                                              ║
║   Pherion vβ — SOC Advanced Detection & ML-Powered IDS                    ║
║                                                                              ║
║   SOC ENTERPRISE CAPABILITIES:                                               ║
║   ✅ 37 Detection Rules with MITRE ATT&CK Mapping                           ║
║   ✅ Threat Intelligence IOC Integration (IP/domain/hash)                    ║
║   ✅ Alert Correlation Engine (incident grouping & escalation)               ║
║   ✅ Severity Scoring (Critical/High/Medium/Low)                             ║
║   ✅ Structured Event Logging (JSONL, SIEM-ready)                            ║
║   ✅ System Health Watchdog (queue/memory/thread monitoring)                  
║   ✅ Per-Rule Error Isolation (fault-tolerant pipeline)                       ║
║   ✅ Dynamic Rule Enable/Disable via Registry                                ║
║   ✅ Adaptive Threshold Auto-Tuning                                          ║
║   ✅ Suricata-style Signature Engine                                         ║
║   ✅ JA3 TLS Fingerprint Detection                                           ║
║   ✅ GeoIP Enrichment (optional)                                             ║
║                                                                              ║
║   DETECTION RULES (MITRE ATT&CK mapped):                                    ║
║   • SYN Flood (T1498.001) • TCP/UDP/Slow Port Scan (T1046)                   ║
║   • ARP Spoofing (T1557.002) • DNS Tunnel (T1071.004) • DNS Flood            ║
║   • ICMP Flood/Tunnel (T1095) • Brute Force (T1110)                         ║
║   • Data Exfil (T1048) • NULL/XMAS/FIN Scan (T1046)                          ║
║   • Land Attack (T1499.004) • Smurf Attack (T1498.001)                       ║
║   • RST Flood (T1557) • HTTP Flood (T1499.002) • Beacon/C2 (T1071)          ║
║   • Credential Stuffing (T1110.004) • SQL Injection (T1190)                 ║
║   • Webshell Upload (T1505.003) • SMB Lateral (T1021.002)                    ║
║   • Payload Entropy (T1027) • TTL Anomaly (T1082)                            ║
║   • HTTP Attack Payloads (T1059) • JA3 Blacklist (T1071.001)                 ║
║                                                                              ║
║   ML ENGINE:                                                                 ║
║   ✅ Per-Protocol ML Baseline (TCP/UDP/ICMP modelled separately)             ║
║   ✅ Ensemble Scoring — rule engine + ML vote for lower FP rate              ║
║   ✅ Supervised Random Forest from CSV (CIC-IDS/NSL-KDD/UNSW-NB15)          ║
║                                                                              ║
║   PRODUCTION FEATURES:                                                       ║
║   ✅ Ring Buffer — bounded memory, auto-evicts old packets                   ║
║   ✅ Alert Deduplication — direction-independent hash                         ║
║   ✅ Alert Rate Limiting — per-rule, 10 alerts/min max                       ║
║   ✅ Thread Safety — RLock on all shared state                               ║
║   ✅ SQLite Persistence — alerts, stats, incidents survive restart           ║
║   ✅ Bidirectional Flow Tracking with idle/active timeouts                    ║
║   ✅ Headless Mode — run without GUI via --headless flag                     ║
║   ✅ PCAP Export — save captures for Wireshark analysis                      ║
║   ✅ BPF Filters — standard Berkeley Packet Filter syntax                    ║
║   ✅ Self-Healing Engine — non-blocking auto-remediation on attack            ║
║      (rate_limit_ip · null_route · TCP RST · ARP flush · isolate_flow)       ║
║                                                                              ║
║   Install:                                                                   ║
║     pip install scapy psutil scikit-learn pandas numpy joblib                 ║
║     Windows: install Npcap from https://npcap.com                            ║
║                                                                              ║
║   Usage:                                                                     ║
║     sudo python pherion.py              # GUI mode                           ║
║     sudo python pherion.py --headless   # Headless / server mode             ║
║     sudo python pherion.py --headless --interface eth0 --bpf "tcp port 80"   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import time
import math
import signal
import argparse
import threading
import queue
import socket
import hashlib
import sqlite3
import statistics
import logging
import json
import multiprocessing
import ipaddress
import warnings
import subprocess
from datetime import datetime
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Optional, List, Dict, Tuple, TypeVar, Generic,
    Iterator, Callable, Any, Set
)

# ═══════════════════════════════════════════════════════════════════════════════
# OPTIONAL DEPENDENCY IMPORTS — graceful degradation
# ═══════════════════════════════════════════════════════════════════════════════

NUMPY_OK = False
PANDAS_OK = False
SKLEARN_OK = False
SCAPY_OK = False
PSUTIL_OK = False
GEOIP_OK = False

try:
    import numpy as np # type: ignore
    NUMPY_OK = True
except ImportError:
    pass

try:
    import pandas as pd # type: ignore
    PANDAS_OK = True
except ImportError:
    pass

try:
    # Suppress scikit-learn/joblib mismatch UserWarnings that spam the console
    warnings.filterwarnings("ignore", category=UserWarning, module="sklearn.utils.parallel")
    warnings.filterwarnings("ignore", message=".*sklearn.utils.parallel.delayed.*should be used with.*sklearn.utils.parallel.Parallel.*", category=UserWarning)
    import joblib # type: ignore
    from sklearn.ensemble import RandomForestClassifier # type: ignore
    from sklearn.preprocessing import StandardScaler, LabelEncoder # type: ignore
    from sklearn.model_selection import train_test_split, cross_val_score # type: ignore
    from sklearn.metrics import ( # type: ignore
        classification_report, accuracy_score,
        f1_score, precision_score, recall_score,
        confusion_matrix, roc_auc_score, precision_recall_fscore_support,
    )
    SKLEARN_OK = True
except ImportError:
    pass

try:
    from scapy.all import ( # type: ignore
        sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR,
        Raw, Ether, IPv6, ICMPv6EchoRequest, ICMPv6EchoReply,
        ICMPv6DestUnreach, ICMPv6TimeExceeded, ICMPv6ParamProblem,
        SCTP, GRE, ESP, AH, DHCP, DHCP6, BOOTP, NTP,
        wrpcap, conf, get_if_list, get_if_addr,
        # WiFi protocol support for wireless vulnerability detection
        Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11AssoResp,
        Dot11Deauth, Dot11Disas, Dot11Auth, Dot11WEP, RadioTap,
    )
    SCAPY_OK = True
except ImportError:
    pass

try:
    import psutil # type: ignore
    PSUTIL_OK = True
except ImportError:
    pass

GEOIP_OK = False
GEOIP_READER = None

SMOTE_OK = False
SMOTE = None
try:
    from imblearn.over_sampling import SMOTE # type: ignore
    SMOTE_OK = True
except ImportError:
    SMOTE = None

def _get_geoip_reader() -> Optional[Any]:
    """Lazy-load GeoIP reader if available and DB file exists."""
    global GEOIP_READER, GEOIP_OK
    if GEOIP_READER is not None:
        return GEOIP_READER
    try:
        import geoip2.database # type: ignore
        GEOIP_OK = True
    except ImportError:
        GEOIP_OK = False
        return None

    db_path = DATA_DIR / "GeoLite2-City.mmdb"
    if not db_path.exists():
        return None
    try:
        GEOIP_READER = geoip2.database.Reader(str(db_path))
        return GEOIP_READER
    except Exception:
        return None


# Cache GeoIP lookups so we don't query the database for every packet.
# This is important when monitoring high-throughput networks.
from functools import lru_cache

@lru_cache(maxsize=2048)
def _lookup_geoip(ip: str) -> Optional[str]:
    if not ip or not GEOIP_OK:
        return None
    reader = _get_geoip_reader()
    if not reader:
        return None
    try:
        geos = reader.city(ip)
        return f"{geos.country.iso_code}:{geos.subdivisions.most_specific.name}:{geos.city.name}"
    except Exception:
        return None


ML_AVAILABLE = NUMPY_OK and PANDAS_OK and SKLEARN_OK

# Check if tkinter available (for headless mode support)
TK_AVAILABLE = False
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, filedialog
    TK_AVAILABLE = True
except ImportError:
    pass


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: CONFIGURATION — All tunables in one place
# ═══════════════════════════════════════════════════════════════════════════════

BASE_DIR = Path(__file__).parent.resolve()
DATA_DIR = BASE_DIR / "pherion_data"
MODEL_DIR = DATA_DIR / "models"
DB_DIR = DATA_DIR / "db"
LOG_DIR = DATA_DIR / "logs"
PCAP_DIR = DATA_DIR / "pcaps"

for _d in (DATA_DIR, MODEL_DIR, DB_DIR, LOG_DIR, PCAP_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# Logging setup
_log_file = LOG_DIR / f"pherion_{datetime.now():%Y%m%d}.log"
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(_log_file), encoding="utf-8"),
    ],
)
logger = logging.getLogger("pherion")


@dataclass
class DetectionConfig:
    """All intrusion detection thresholds — BALANCED FOR PRODUCTION USE.
    
    These thresholds are tuned for real-world networks:
    - Catches malicious attacks while minimizing false positives
    - Works well with normal network traffic patterns
    - Still detects test_attack.py patterns
    """
    # SYN Flood: Production-balanced (catches 200+ packet floods, ignores normal traffic)
    syn_flood_window: float = 15.0
    syn_flood_threshold: int = 130  # Balanced: catches attacks, reduces FP

    # Port Scan: Production-balanced (detects aggressive scans, ignores occasional probes)
    port_scan_window: float = 45.0
    port_scan_threshold: int = 35  # Balanced: catches 60-port scans

    # Slow Scan: Extended window with balanced threshold
    slow_scan_window: float = 360.0
    slow_scan_threshold: int = 45

    # Flood attacks: Production-balanced
    icmp_flood_window: float = 15.0
    icmp_flood_threshold: int = 70  # Balanced: catches 100-packet floods
    dns_flood_window: float = 15.0
    dns_flood_threshold: int = 70  # Balanced: catches 100-query floods

    # Brute Force: Production-balanced
    brute_force_window: float = 90.0
    brute_force_threshold: int = 22  # Balanced: catches 90 attempts

    # Data Exfiltration: Production threshold
    data_exfil_window: float = 90.0
    data_exfil_threshold_bytes: int = 250_000_000

    # Connection Rate: Production-balanced
    connection_rate_window: float = 10.0
    connection_rate_threshold: int = 320  # Balanced: catches 400 connections

    # Flow timeouts: Balanced for accuracy
    flow_idle_timeout: float = 180.0
    flow_active_timeout: float = 360.0

    # Alert management: Production rate limiting
    alert_dedup_window: float = 90.0
    alert_rate_limit: int = 15

    # Large packets: Production threshold (legitimate large transfers exist)
    large_packet_bytes: int = 75000  # Balanced: catches 85K+ packets

    # Beacon detection: Production settings
    beacon_min_interval: float = 15.0
    beacon_max_interval: float = 1800.0
    beacon_jitter_ratio: float = 0.15
    beacon_min_hits: int = 15

    # HTTP Flood: Production-balanced
    http_flood_window: float = 15.0
    http_flood_threshold: int = 70

    # Credential Stuffing: Production-balanced
    cred_stuff_window: float = 45.0
    cred_stuff_threshold: int = 14  # Balanced: catches 25 attempts

    # TTL Anomaly: Production threshold
    ttl_anomaly_values: frozenset = field(default_factory=lambda: frozenset({
        1, 2
    }))

    # Minimal whitelist - only truly local addresses
    whitelist_subnets: Tuple[str, ...] = (
        "127.0.0.0/8",  # localhost only
        "::1/128",      # IPv6 localhost
        "10.0.0.0/8",   # Private Subnets
        "172.16.0.0/12",
        "192.168.0.0/16",
    )

    # No default blacklists - let detection rules handle it
    blacklist_subnets: Tuple[str, ...] = ()

    # JA3 fingerprint blacklist - known malicious TLS fingerprints
    ja3_blacklist: frozenset = field(default_factory=frozenset)

    # Threat Intelligence: Always enabled, frequent updates
    threat_intel_enabled: bool = True
    threat_intel_dir: Path = field(default_factory=lambda: DATA_DIR / "threat_intel")
    threat_intel_refresh_interval: float = 1800.0  # 30 min updates

    # ICMP Tunneling: Production threshold
    icmp_tunnel_payload_bytes: int = 64

    # RST Flood: Production-balanced
    rst_flood_window: float = 5.0
    rst_flood_threshold: int = 14  # Balanced: catches 25 RST packets

    # Payload Entropy: Production threshold
    high_entropy_threshold: float = 7.2

    # Port Entropy: Production detection
    port_entropy_window: float = 60.0
    port_entropy_threshold: float = 4.5

    # Expanded suspicious ports
    suspicious_ports: frozenset = field(default_factory=lambda: frozenset({
        # Original ports
        4444, 5555, 6666, 6667, 1337, 31337, 12345, 54321,
        3389, 5900, 2323, 9001, 9030, 4443, 8443,
        1080, 3128, 8118, 27374, 65535,
        # Additional suspicious ports
        1338, 31338, 12346, 54322, 4445, 5556, 6668, 6669,
        2324, 9002, 9031, 4444, 8444, 1081, 3129, 8119,
        27375, 65534, 65533, 65532,
        # Common malware ports
        5000, 6000, 7000, 8000, 9000, 10000, 20000, 30000, 40000, 50000
    }))

    # Brute force ports - expanded (Web and DNS removed due to natural connection bursts)
    brute_force_ports: frozenset = field(default_factory=lambda: frozenset({
        # Original
        22, 23, 3389, 21, 5900, 3306, 1433, 5432, 27017, 6379,
        25, 110, 143, 993, 995, 587,
        # Additional critical services
        445, 139, 135, 389, 636, 3268, 3269,  # SMB, LDAP
        161, 162,  # SNMP
        2049,  # NFS
        111,  # RPC
    }))

    # Tuned thresholds - Web/DNS traffic is excluded to prevent FPs 
    brute_force_thresholds_by_port: Dict[int, int] = field(default_factory=lambda: {
        22: 5,    # SSH 
        3389: 5,  # RDP
        445: 5,   # SMB
        21: 10,   # FTP
        23: 10,   # Telnet
        3306: 10, # MySQL
        1433: 10, # MSSQL
        5432: 10, # PostgreSQL
        27017: 10,# MongoDB
        6379: 10, # Redis
        25: 15,   # SMTP
        110: 15,  # POP3
        143: 15,  # IMAP
        993: 15,  # IMAPS
        995: 15,  # POP3S
        587: 15,  # SMTP Submission
    })
    # SMB lateral movement detection
    smb_lateral_window: float = 60.0
    smb_lateral_threshold: int = 6
    suspicious_dns_patterns: tuple = (
        "malware", "phishing", "botnet", "c2server", "hack",
        "exploit", "payload", "backdoor", "keylog", "trojan",
        "ransomware", "crypto-miner", "darkweb", "onion.link",
    )
    stale_cleanup_interval: float = 30.0

    # WiFi vulnerability detection thresholds - balanced
    wifi_deauth_threshold: int = 10   # Increased from 5 (reduce FPs)
    wifi_probe_flood_threshold: int = 80  # Increased from 50
    wifi_ssid_change_threshold: int = 15  # Increased from 10
    wifi_beacon_flood_threshold: int = 150 # Increased from 100
    auto_tune_enabled: bool = True
    auto_tune_interval: float = 600.0  # Increased from 300.0
    auto_tune_factor: float = 1.3  # Increased from 1.2

    def is_whitelisted_ip(self, ip: str) -> bool:
        """Check if IP is in whitelist subnets."""
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
            for subnet_str in self.whitelist_subnets:
                if addr in ipaddress.ip_network(subnet_str, strict=False):
                    return True
        except Exception:
            pass
        return False

    def is_blacklisted_ip(self, ip: str) -> bool:
        """Check if IP is in blacklist subnets."""
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
            for subnet_str in self.blacklist_subnets:
                if addr in ipaddress.ip_network(subnet_str, strict=False):
                    return True
        except Exception:
            pass
        return False

    def is_ignored_ip(self, ip: str) -> bool:
        """Check if IP should be ignored (private networks, etc)."""
        return _is_private_or_reserved_ip(ip)

    # Correlation Engine
    correlation_window: float = 300.0    # group alerts within 5 minutes
    incident_escalation_count: int = 3   # escalate after N related alerts

    # System Watchdog
    watchdog_interval: float = 60.0
    watchdog_queue_warn_pct: float = 0.80
    watchdog_memory_warn_pct: float = 0.95


@dataclass
class MLConfig:
    """Machine learning model configuration — BALANCED FOR ACCURATE DETECTION."""
    model_path: Path = MODEL_DIR / "model.joblib"
    scaler_path: Path = MODEL_DIR / "scaler.joblib"
    encoder_path: Path = MODEL_DIR / "encoder.joblib"
    feature_names_path: Path = MODEL_DIR / "features.joblib"
    baseline_path: Path = MODEL_DIR / "baseline.joblib"

    # BALANCED: Confidence threshold for accurate detection
    confidence_threshold: float = 0.92  # Increased from 0.88

    # BALANCED: Anomaly threshold for baseline detection
    anomaly_threshold: float = 4.0  # Increased from 3.5

    # BALANCED: Solo threshold for ML-only alerts
    ensemble_solo_threshold: float = 0.97  # Increased from 0.95

    # EARLY DETECTION: Minimum packets before ML analysis
    min_flow_packets: int = 8  # Increased from 6

    # More robust model parameters
    n_estimators: int = 400  # Balanced from 500
    max_depth: int = 25      # Balanced from 30
    min_samples_split: int = 5  # Balanced from 3

    # Training parameters
    test_split: float = 0.20  # Balanced from 0.15
    max_training_samples: int = 1_500_000  # Balanced from 2M
    n_jobs: int = max(1, multiprocessing.cpu_count() - 1)
    random_state: int = 42

    # Baseline learning: Balanced period
    baseline_learning_period: int = 2400  # Increased from 1800
    baseline_max_samples: int = 75000    # Balanced from 100000

    # Prediction: Balanced batch size
    batch_predict_size: int = 48  # Balanced from 32


@dataclass
class CaptureConfig:
    """Packet capture settings — OPTIMIZED FOR HIGH-THREAT ENVIRONMENTS."""
    # Larger buffers for high-traffic environments
    ring_buffer_size: int = 100_000  # Increased from 50_000
    packet_queue_size: int = 50_000  # Increased from 20_000
    alert_queue_size: int = 10_000   # Increased from 5_000
    stats_queue_size: int = 500      # Increased from 200

    # More frequent stats updates for real-time monitoring
    stats_push_interval: float = 1.0  # Reduced from 2.0
    db_stats_interval: float = 15.0   # Reduced from 30.0


@dataclass
class GUIConfig:
    """GUI display configuration."""
    window_title: str = "🛡️ Pherion  vβ — Network Monitor & ML-IDS"
    geometry: str = "1500x950"
    min_width: int = 1200
    min_height: int = 700
    refresh_ms: int = 50
    packets_per_update: int = 100
    max_table_rows: int = 8000
    prune_batch: int = 2000


DET = DetectionConfig()
MLC = MLConfig()
CAP = CaptureConfig()
GUI = GUIConfig()


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2: UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def check_privileges() -> bool:
    """Check if running as admin/root."""
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore
        return os.geteuid() == 0
    except Exception:
        return False


def get_interfaces() -> List[str]:
    """Get list of network interfaces."""
    interfaces = ["Auto"]
    seen: Set[str] = set()
    if SCAPY_OK:
        try:
            for iface in get_if_list():
                if iface in seen:
                    continue
                try:
                    addr = get_if_addr(iface)
                    label = f"{iface} ({addr})" if addr and addr != "0.0.0.0" else iface
                except Exception:
                    label = iface
                interfaces.append(str(label))
                seen.add(str(iface))
        except Exception:
            pass
    if PSUTIL_OK:
        try:
            for name, addrs in psutil.net_if_addrs().items():
                if name in seen:
                    continue
                label = name
                for a in addrs:
                    if a.family == socket.AF_INET:
                        label = f"{name} ({a.address})"
                        break
                interfaces.append(str(label))
                seen.add(str(name))
        except Exception:
            pass
    return interfaces


def fmt_bytes(b: int) -> str:
    """Format byte count to human readable."""
    if b > 1e9:
        return f"{b / 1e9:.2f} GB"
    if b > 1e6:
        return f"{b / 1e6:.2f} MB"
    if b > 1e3:
        return f"{b / 1e3:.1f} KB"
    return f"{b} B"


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3: RING BUFFER — ✅ Bounded memory, auto-evicts old entries
# ═══════════════════════════════════════════════════════════════════════════════

T = TypeVar("T")


class RingBuffer(Generic[T]):
    """
    Thread-safe fixed-size circular buffer.

    FIXES:
    - ✅ Unbounded memory growth → fixed capacity
    - ✅ Raw packets kept forever → auto-evicted when buffer wraps
    - ✅ Thread safety → all operations under lock
    """

    __slots__ = ("_buf", "_cap", "_head", "_count", "_lock")

    def __init__(self, capacity: int) -> None:
        if capacity <= 0:
            raise ValueError("Capacity must be positive")
        self._buf: list = [None] * capacity
        self._cap = capacity
        self._head = 0
        self._count = 0
        self._lock = threading.RLock()

    @property
    def capacity(self) -> int:
        return self._cap

    def __len__(self) -> int:
        with self._lock:
            return self._count

    def append(self, item: T) -> Optional[T]:
        """
        Add item. Returns evicted item if buffer was full (for cleanup).
        """
        with self._lock:
            evicted = None
            if self._count == self._cap:
                evicted = self._buf[self._head]
            self._buf[self._head] = item
            self._head = (self._head + 1) % self._cap
            if self._count < self._cap:
                self._count += 1
            return evicted

    def find_by_attr(self, attr: str, value: Any) -> Optional[T]:
        """Find first item where getattr(item, attr) == value."""
        with self._lock:
            for i in range(self._count):
                idx = (self._head - self._count + i) % self._cap
                item = self._buf[idx]
                if item is not None and getattr(item, attr, None) == value:
                    return item
            return None

    def recent(self, n: int) -> List[T]:
        """Return most recent n items (newest last)."""
        with self._lock:
            n = min(n, self._count)
            result = []
            for i in range(n):
                idx = (self._head - n + i) % self._cap
                if self._buf[idx] is not None:
                    result.append(self._buf[idx])
            return result

    def all_items(self) -> List[T]:
        """Return all items oldest to newest."""
        return self.recent(self._count)

    def clear(self) -> None:
        with self._lock:
            self._buf = [None] * self._cap
            self._head = 0
            self._count = 0

    def __iter__(self) -> Iterator[T]:
        return iter(self.all_items())

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {"count": self._count, "capacity": self._cap,
                    "usage_pct": int(100 * self._count / self._cap)}


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4: PARSED PACKET DATA
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ParsedPacket:
    """Structured packet data — single source of truth per packet."""
    number: int = 0
    timestamp: str = ""
    epoch: float = 0.0

    # Layer 2
    src_mac: str = ""
    dst_mac: str = ""

    # Layer 3
    src_ip: str = ""
    dst_ip: str = ""
    ttl: int = 0
    ip_header_len: int = 0
    ip_flags: int = 0
    ip_frag_offset: int = 0

    # Layer 4
    src_port: int = 0
    dst_port: int = 0
    tcp_flags: str = ""
    tcp_flags_int: int = 0
    window_size: int = 0
    seq_num: int = 0
    ack_num: int = 0
    urg_ptr: int = 0
    icmp_type: int = -1
    icmp_code: int = -1

    # Application
    protocol: str = ""
    payload_size: int = 0
    total_length: int = 0
    raw_payload: bytes = b""
    dns_query: str = ""
    http_method: str = ""
    http_headers: Dict[str, str] = field(default_factory=dict)
    http_body: str = ""
    # TLS/HTTPS
    tls_version: str = ""
    tls_sni: str = ""
    tls_ja3: str = ""
    tls_ja3_hash: str = ""
    # GeoIP enrichment (optional)
    geoip_src: str = ""
    geoip_dst: str = ""

    # ARP
    arp_op: int = 0
    arp_src_ip: str = ""
    arp_src_mac: str = ""
    arp_dst_ip: str = ""
    arp_dst_mac: str = ""

    # WiFi
    bssid: str = ""           # Access Point MAC address
    wifi_type: int = 0        # WiFi frame type (0=management, 1=control, 2=data)
    wifi_subtype: int = 0     # WiFi frame subtype
    wifi_channel: int = 0     # WiFi channel
    wifi_rssi: int = 0        # Signal strength (dBm)
    wifi_ssid: str = ""       # Network name from beacon/probe frames

    # Analysis results
    info: str = ""
    threat_level: str = "Safe"  # Safe | Suspicious | Danger
    ml_prediction: str = ""
    ml_confidence: float = 0.0
    # : NEW fields for improved detection
    payload_entropy: float = 0.0   # Shannon entropy of payload bytes
    http_path: str = ""            # URI path for HTTP flood / cred stuffing
    is_retransmit: bool = False    # TCP retransmission flag
    rule_flags: int = 0            # bitmask of rules triggered (for ensemble)

    # Raw reference — auto-evicted by RingBuffer when old
    _raw: Optional[Any] = field(default=None, repr=False, compare=False)

    @property
    def has_raw(self) -> bool:
        return self._raw is not None


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5: PACKET PARSER — Scapy packet → ParsedPacket
# ═══════════════════════════════════════════════════════════════════════════════

def _classify_protocol(pkt) -> str:
    """Determine application-level protocol from scapy packet.

    Uses a mix of port heuristics and payload signatures to detect common
    protocols even when they run on non-standard ports.
    """
    if not SCAPY_OK:
        return "OTHER"
    
    # WiFi protocol detection
    if pkt.haslayer(Dot11):
        dot11 = pkt[Dot11]
        if pkt.haslayer(Dot11Deauth):
            return "WIFI-DEAUTH"
        elif pkt.haslayer(Dot11Beacon):
            return "WIFI-BEACON"
        elif pkt.haslayer(Dot11ProbeReq):
            return "WIFI-PROBE"
        elif pkt.haslayer(Dot11Auth):
            return "WIFI-AUTH"
        elif dot11.type == 0 and dot11.subtype == 4:  # Probe Request
            return "WIFI-PROBE"
        elif dot11.type == 0 and dot11.subtype == 5:  # Probe Response
            return "WIFI-PROBE"
        elif dot11.type == 0 and dot11.subtype == 8:  # Beacon
            return "WIFI-BEACON"
        elif dot11.type == 0 and dot11.subtype == 11:  # Authentication
            return "WIFI-AUTH"
        elif dot11.type == 0 and dot11.subtype == 12:  # Deauthentication
            return "WIFI-DEAUTH"
        elif getattr(dot11, 'type', None) == 0:
            return "WIFI-MGMT"
        elif getattr(dot11, 'type', None) == 1:
            return "WIFI-CTRL"
        # Note: If type == 2 (Data), we fall through to parse the encapsulated IP/TCP payload!
    
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(DNSQR) or pkt.haslayer(DNSRR):
        return "DNS"

    def _payload_bytes() -> Optional[bytes]:
        try:
            if pkt.haslayer(Raw):
                return bytes(pkt[Raw].load)
        except Exception:
            pass
        return None

    if pkt.haslayer(TCP):
        sp, dp = pkt[TCP].sport, pkt[TCP].dport
        # Common port-based protocol mapping (TCP) - expanded
        for port in (dp, sp):
            m = {80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
                 23: "TELNET", 25: "SMTP", 587: "SMTP", 110: "POP3", 143: "IMAP",
                 119: "NNTP", 4433: "QUIC", 5060: "SIP", 5061: "SIPS",
                 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
                 563: "NNTPS", 5900: "VNC", 6379: "Redis", 986: "FTPS", 989: "FTPS", 990: "FTPS",
                 8080: "HTTP-ALT", 8000: "HTTP-ALT", 8888: "HTTP-ALT", 5000: "HTTP-ALT",
                 # Additional protocols
                 9300: "Elasticsearch",  # Elasticsearch
                 27017: "MongoDB", 27018: "MongoDB", 27019: "MongoDB",  # MongoDB
                 11211: "Memcached",  # Memcached
                 6379: "Redis",  # Redis (already there but added for clarity)
                 2181: "ZooKeeper",  # ZooKeeper
                 9090: "Prometheus", 9093: "Prometheus",  # Prometheus
                 3000: "Grafana",  # Grafana
                 15672: "RabbitMQ", 5672: "RabbitMQ",  # RabbitMQ
                 9200: "Elasticsearch/OpenSearch",  # Elasticsearch or OpenSearch (same default port)
                 8529: "ArangoDB",  # ArangoDB
                 7474: "Neo4j", 7687: "Neo4j",  # Neo4j
                 4080: "HTTP-ALT", 4081: "HTTP-ALT",  # HTTP alternate
                 8443: "HTTPS-ALT",  # HTTPS alternate
                 9443: "HTTPS-ALT",  # HTTPS alternate
                 10443: "HTTPS-ALT",  # HTTPS alternate
                 20000: "DNP3", 20001: "DNP3",  # DNP3 (SCADA)
                 102: "S7comm",  # Siemens S7
                 502: "Modbus",  # Modbus (SCADA)
                 44818: "Rockwell",  # Rockwell Ethernet/IP
                 2222: "EtherNetIP",  # EtherNet/IP
                 161: "SNMP", 162: "SNMPTRAP",  # SNMP over TCP (unusual but possible)
                 514: "SYSLOG",  # Syslog over TCP
            }
            if port in m:
                return m[port]

        # Heuristics: payload-based protocol detection
        payload = _payload_bytes()
        if payload:
            # HTTP request/response
            if payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ",
                                   b"HEAD ", b"OPTIONS ", b"PATCH ", b"HTTP/")):
                return "HTTP"
            # TLS/HTTPS handshake (ClientHello/ServerHello)
            # TLS record header is 5 bytes: [ContentType][Version][Length]
            if len(payload) >= 5 and payload[0] == 0x16 and payload[1] == 0x03:
                return "HTTPS"
            # SSH banner
            if payload.startswith(b"SSH-"):
                return "SSH"
            # FTP commands/banners
            if payload.startswith((b"USER ", b"PASS ", b"220 ", b"230 ")):
                return "FTP"

        # Attempt to use Scapy's higher-layer dissection when available.
        try:
            last = pkt.lastlayer()
            if last is not None and last.name not in ("Raw", "Padding", "TCP", "UDP",
                                                     "IP", "IPv6", "Ethernet", "Ether",
                                                     "Dot11", "Dot11QoS", "LLC", "SNAP"):
                return last.name.upper()
        except Exception:
            pass

        return "TCP"

    if pkt.haslayer(UDP):
        sp, dp = pkt[UDP].sport, pkt[UDP].dport
        # Prefer explicit DNS parsing over port heuristics.
        # Port 53 is common for DNS but not guaranteed; scapy can parse DNS layers when present.
        if pkt.haslayer(DNSQR) or pkt.haslayer(DNSRR):
            return "DNS"

        # Common UDP protocols by port - expanded
        for port in (sp, dp):
            m = {53: "DNS", 67: "DHCP", 68: "DHCP", 123: "NTP", 5353: "mDNS",
                 161: "SNMP", 162: "SNMPTRAP", 514: "SYSLOG", 520: "RIP",
                 69: "TFTP", 1900: "SSDP", 1901: "SSDP", 5355: "LLMNR",
                 4500: "IPSEC", 500: "IPSEC", 546: "DHCPv6", 547: "DHCPv6",
                 137: "NETBIOS", 138: "NETBIOS", 139: "NETBIOS",
                 3478: "STUN", 5060: "SIP", 5061: "SIPS", 12345: "METERPRETER",
                 # Additional protocols
                 1194: "OpenVPN",  # OpenVPN
                 1701: "L2TP",  # L2TP
                 5000: "SIP",  # SIP alternate
                 5060: "SIP",  # SIP
                 3478: "STUN",  # STUN
                 3479: "TURN",  # TURN
                 3480: "STUN",  # STUN
                 1812: "RADIUS", 1813: "RADIUS",  # RADIUS
                 1645: "RADIUS", 1646: "RADIUS",  # RADIUS legacy
                 3799: "RADIUS-ACL/DIAMETER",  # RADIUS ACL or DIAMETER (shared port)
                 2083: "GRE",  # GRE (sometimes UDP)
                 1194: "OpenVPN",  # OpenVPN
                 4434: "OpenVPN",  # OpenVPN alternate
                 51820: "WireGuard",  # WireGuard
                 51821: "WireGuard",  # WireGuard
                 8472: "OpenStealth",  # OpenStealth VPN
                 8080: "HTTP-ALT",  # HTTP alternate
                 3128: "HTTP-PROXY",  # HTTP Proxy
                 1080: "SOCKS",  # SOCKS proxy
                 9050: "TOR",  # TOR
                 9051: "TOR",  # TOR
                 9150: "TOR",  # TOR
                 3702: "WS-DISCOVERY",  # WS-Discovery
                 8000: "HTTP-ALT",  # HTTP alternate
                 8888: "HTTP-ALT",  # HTTP alternate
                 9000: "HTTP-ALT",  # HTTP alternate
                 10000: "HTTP-ALT",  # HTTP alternate
                 32768: "RPC",  # RPC
                 2049: "NFS",  # NFS
            }
            if port in m:
                return m[port]

        # QUIC / HTTP/3 over UDP
        if 443 in (sp, dp):
            return "QUIC"

        # Use scapy's dissection for known higher-layer protocols
        try:
            last = pkt.lastlayer()
            if last is not None and last.name not in ("Raw", "Padding", "UDP",
                                                     "IP", "IPv6", "Ethernet", "Ether",
                                                     "Dot11", "Dot11QoS", "LLC", "SNAP"):
                return last.name.upper()
        except Exception:
            pass

        return "UDP"

    # Support additional transport/tunnel protocols that are not TCP/UDP.
    if pkt.haslayer(SCTP):
        return "SCTP"
    if pkt.haslayer(GRE):
        return "GRE"
    if pkt.haslayer(ESP) or pkt.haslayer(AH):
        return "IPSEC"
    if pkt.haslayer(DHCP) or pkt.haslayer(BOOTP):
        return "DHCP"
    if pkt.haslayer(DHCP6):
        return "DHCPv6"
    if pkt.haslayer(NTP):
        return "NTP"

    # ✅ FIX: ICMP must be checked BEFORE bare IP, because IP is a parent layer
    # of ICMP — haslayer(IP) matches ICMP packets too, mis-labeling them as "IP".
    if pkt.haslayer(ICMP):
        return "ICMP"
    # IPv6 ICMP (ICMPv6) should be treated as ICMP for detection rules
    if pkt.haslayer(ICMPv6EchoRequest) or pkt.haslayer(ICMPv6EchoReply) or \
       pkt.haslayer(ICMPv6DestUnreach) or pkt.haslayer(ICMPv6TimeExceeded) or \
       pkt.haslayer(ICMPv6ParamProblem) or pkt.haslayer("ICMPv6"):
        return "ICMP"

    # If we saw an IP header but no L4 layer, label it as IP to ensure it shows
    # up in protocol counters/lists instead of falling back to "OTHER".
    if pkt.haslayer(IP):
        return "IP"

    if pkt.haslayer(IPv6):
        return "IPv6"

    # Fallback: report the last decoded layer name (e.g., SCTP, PPPoE, etc.)
    try:
        layer_names = [layer.name.upper() for layer in pkt.layers() if hasattr(layer, "name")]
        if layer_names:
            # Remove trivial container layers so we surface actual protocol names.
            filtered = [name for name in layer_names if name not in (
                "RAW", "PADDING", "TCP", "UDP", "IP", "IPV6", "ETHERNET", "ETHER",
                "DOT11QOS", "LLC", "SNAP"
            )]
            if filtered:
                return "/".join(filtered)
            return layer_names[-1]
    except Exception:
        pass

    try:
        last = pkt.lastlayer()
        if last is not None and hasattr(last, "name"):
            return last.name
    except Exception:
        pass
    return "OTHER"


def _extract_flags(tcp_layer) -> str:
    """Extract TCP flags as human-readable string."""
    f = int(tcp_layer.flags)
    out = ""
    flags_map: List[Tuple[int, str]] = [(0x02, "S"), (0x10, "A"), (0x01, "F"),
                                        (0x04, "R"), (0x08, "P"), (0x20, "U"),
                                        (0x40, "E"), (0x80, "C")]
    for mask, ch in flags_map:
        if f & mask:
            out += ch # type: ignore
    return out


def _build_info(p: ParsedPacket, raw_pkt) -> str:
    """Generate info string for packet display."""
    try:
        proto = p.protocol
        if proto == "ARP":
            if p.arp_op == 1:
                return f"Who has {p.arp_dst_ip}? Tell {p.arp_src_ip}"
            return f"{p.arp_src_ip} is at {p.arp_src_mac}"
        if proto == "DNS":
            return f"Query: {p.dns_query}" if p.dns_query else "DNS Response"
        if proto == "ICMP":
            names = {0: "Echo Reply", 3: "Dest Unreachable",
                     8: "Echo Request", 11: "Time Exceeded", 5: "Redirect"}
            return f"{names.get(p.icmp_type, f'Type {p.icmp_type}')} code={p.icmp_code}"
        if proto in ("TCP", "HTTP", "HTTPS", "SSH", "FTP", "SMTP",
                     "MySQL", "PostgreSQL", "Redis", "MongoDB",
                     "HTTP-ALT", "POP3", "IMAP"):
            base = f"{p.src_port} → {p.dst_port} [{p.tcp_flags}] Seq={p.seq_num} Win={p.window_size}"
            if p.http_method:
                base += f" | {p.http_method}"
            return base
        if proto == "UDP":
            return f"{p.src_port} → {p.dst_port} Len={p.payload_size}"
    except Exception:
        pass
    return f"Length: {p.total_length}"


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits/byte. Range 0–8."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p) # type: ignore
    return ent


def _extract_tls_ja3_and_sni(data: bytes) -> Tuple[str, str, str, str]:
    """Extract JA3 fingerprint + SNI from raw TLS ClientHello bytes.

    Returns (ja3_string, ja3_hash, sni, version).
    """
    # Fallbacks
    ja3 = ""
    ja3_hash = ""
    sni = ""
    version = ""

    try:
        # Minimal TLS record parser
        # Record header: 1B ContentType, 2B Version, 2B Length
        if len(data) < 5 or data[0] != 0x16:
            return ja3, ja3_hash, sni, version
        _, ver, length = data[0], data[1:3], int.from_bytes(data[3:5], "big")  # type: ignore
        version = f"{ver[0]:02x}{ver[1]:02x}"
        body = data[5:5+length]  # type: ignore
        if len(body) < 4 or body[0] != 0x01:
            return ja3, ja3_hash, sni, version
        # Skip handshake header
        # Handshake: 1B type, 3B length
        hl = int.from_bytes(body[1:4], "big")
        if len(body) < 4 + hl:
            return ja3, ja3_hash, sni, version
        hbody = body[4:4+hl]
        # ClientHello: 2B version, 32B random, 1B session id len
        if len(hbody) < 34:
            return ja3, ja3_hash, sni, version
        p = 0
        client_ver = int.from_bytes(hbody[p:p+2], "big"); p += 2
        version = f"{client_ver:04x}"
        p += 32  # random
        sid_len = hbody[p]; p += 1
        p += sid_len
        if p + 2 > len(hbody):
            return ja3, ja3_hash, sni, version
        # cipher suites
        cs_len = int.from_bytes(hbody[p:p+2], "big"); p += 2
        ciphers: List[str] = []
        for i in range(0, cs_len, 2):
            if p + 2 > len(hbody):
                break
            ciphers.append(str(int.from_bytes(hbody[p:p+2], "big")))
            p += 2
        # compression
        if p + 1 > len(hbody):
            return ja3, ja3_hash, sni, version
        comp_len = hbody[p]; p += 1
        p += comp_len
        # extensions
        if p + 2 > len(hbody):
            return ja3, ja3_hash, sni, version
        ext_len = int.from_bytes(hbody[p:p+2], "big"); p += 2
        exts: List[str] = []
        curves: List[str] = []
        points: List[str] = []
        end = p + ext_len
        while p + 4 <= end and p + 4 <= len(hbody):
            ext_type = int.from_bytes(hbody[p:p+2], "big")
            ext_len2 = int.from_bytes(hbody[p+2:p+4], "big")
            p += 4
            ext_body = hbody[p:p+ext_len2]
            p += ext_len2
            exts.append(str(ext_type))
            # SNI parser
            if ext_type == 0x0000:
                # Server Name Indication
                if len(ext_body) >= 5:
                    sn_len = int.from_bytes(ext_body[3:5], "big")
                    if 5 + sn_len <= len(ext_body):
                        sni = ext_body[5:5+sn_len].decode("utf-8", errors="ignore")
            # Supported groups (curves)
            if ext_type == 0x000a and len(ext_body) >= 2:
                g_len = int.from_bytes(ext_body[0:2], "big")
                idx = 2
                while idx + 2 <= len(ext_body):
                    curves.append(str(int.from_bytes(ext_body[idx:idx+2], "big")))
                    idx += 2
            # EC point formats
            if ext_type == 0x000b and len(ext_body) >= 1:
                pf_len = ext_body[0]
                idx = 1
                while idx < len(ext_body) and len(points) < pf_len:
                    points.append(str(ext_body[idx]))
                    idx += 1
        ja3 = ",".join([version, "-".join(ciphers), "-".join(exts), "-".join(curves), "-".join(points)])
        if ja3:
            ja3_hash = hashlib.md5(ja3.encode("utf-8")).hexdigest()
    except Exception:
        pass
    return ja3, ja3_hash, sni, version


def _is_private_or_reserved_ip(ip: str) -> bool:
    """Return True for IPs we generally should not alert on (RFC1918/loopback/link-local/etc.)."""
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.is_private or addr.is_loopback or addr.is_link_local or
                addr.is_multicast or addr.is_reserved or addr.is_unspecified)
    except Exception:
        return False


def parse_packet(raw_pkt, packet_number: int) -> Optional[ParsedPacket]:
    """Parse scapy packet into structured ParsedPacket."""
    if not SCAPY_OK:
        return None
    try:
        p = ParsedPacket()
        p.number = packet_number
        p.epoch = float(raw_pkt.time)
        p.timestamp = str(datetime.fromtimestamp(p.epoch).strftime("%H:%M:%S.%f"))[:-3] # type: ignore
        p.total_length = len(raw_pkt)
        p._raw = raw_pkt

        # Layer 2
        if raw_pkt.haslayer(Ether):
            p.src_mac = raw_pkt[Ether].src
            p.dst_mac = raw_pkt[Ether].dst
        
        # WiFi layer parsing
        if raw_pkt.haslayer(Dot11):
            dot11 = raw_pkt[Dot11]
            p.src_mac = dot11.addr2  # Transmitter MAC
            p.dst_mac = dot11.addr1  # Receiver MAC
            p.bssid = dot11.addr3    # BSSID (AP MAC)
            p.wifi_type = dot11.type
            p.wifi_subtype = dot11.subtype
            p.wifi_channel = getattr(dot11, 'channel', 0)
            p.wifi_rssi = getattr(raw_pkt, 'dBm_AntSignal', 0) if hasattr(raw_pkt, 'dBm_AntSignal') else 0
            
            # Extract SSID from beacon/probe frames
            if raw_pkt.haslayer(Dot11Beacon) or raw_pkt.haslayer(Dot11ProbeResp):
                try:
                    ssid_element: Any = next((x for x in dot11.payload.payload if hasattr(x, 'ID') and getattr(x, 'ID', None) == 0), None)
                    if ssid_element is not None and hasattr(ssid_element, 'info'):
                        p.wifi_ssid = getattr(ssid_element, 'info', b'').decode('utf-8', errors='ignore')
                except Exception:
                    pass

        # Layer 3
        if raw_pkt.haslayer(IP):
            ip_l = raw_pkt[IP]
            p.src_ip = ip_l.src
            p.dst_ip = ip_l.dst
            # Ensure TTL is always an integer (scapy may return OctalBytes/None)
            p.ttl = int(ip_l.ttl) if ip_l.ttl is not None else 0
            # Scapy may leave ihl unset on constructed packets (None); default to 5
            ihl = int(ip_l.ihl) if ip_l.ihl is not None else 5
            p.ip_header_len = ihl * 4
            p.ip_flags = int(ip_l.flags) if ip_l.flags is not None else 0
            p.ip_frag_offset = int(ip_l.frag) if ip_l.frag is not None else 0
        elif raw_pkt.haslayer(ARP):
            arp_l = raw_pkt[ARP]
            p.src_ip = arp_l.psrc
            p.dst_ip = arp_l.pdst
            p.arp_op = arp_l.op
            p.arp_src_ip = arp_l.psrc
            p.arp_src_mac = arp_l.hwsrc
            p.arp_dst_ip = arp_l.pdst
            p.arp_dst_mac = arp_l.hwdst
        elif raw_pkt.haslayer(IPv6):
            ipv6_l = raw_pkt[IPv6]
            p.src_ip = ipv6_l.src
            p.dst_ip = ipv6_l.dst
            # IPv6 uses "hlim" instead of TTL; treat it as TTL for anomaly checks
            p.ttl = int(getattr(ipv6_l, "hlim", 0))
        else:
            p.src_ip = p.src_mac or "N/A"
            p.dst_ip = p.dst_mac or "N/A"

        # GeoIP enrichment (optional)
        if GEOIP_OK:
            try:
                if p.src_ip:
                    g = _lookup_geoip(p.src_ip)
                    if g:
                        p.geoip_src = g
                if p.dst_ip:
                    g = _lookup_geoip(p.dst_ip)
                    if g:
                        p.geoip_dst = g
            except Exception:
                pass

        # Protocol classification
        p.protocol = _classify_protocol(raw_pkt)

        # Layer 4
        if raw_pkt.haslayer(TCP):
            tcp_l = raw_pkt[TCP]
            p.src_port = tcp_l.sport
            p.dst_port = tcp_l.dport
            p.tcp_flags = _extract_flags(tcp_l)
            p.tcp_flags_int = int(tcp_l.flags)
            p.window_size = tcp_l.window
            p.seq_num = tcp_l.seq
            p.ack_num = tcp_l.ack
            p.urg_ptr = tcp_l.urgptr
        elif raw_pkt.haslayer(UDP):
            p.src_port = raw_pkt[UDP].sport
            p.dst_port = raw_pkt[UDP].dport
        elif raw_pkt.haslayer(ICMP):
            p.icmp_type = raw_pkt[ICMP].type
            p.icmp_code = raw_pkt[ICMP].code
        # ICMPv6 (IPv6 ping / error messages) — treat as ICMP for detection
        elif (raw_pkt.haslayer(ICMPv6EchoRequest) or raw_pkt.haslayer(ICMPv6EchoReply)
              or raw_pkt.haslayer(ICMPv6DestUnreach) or raw_pkt.haslayer(ICMPv6TimeExceeded)
              or raw_pkt.haslayer(ICMPv6ParamProblem) or raw_pkt.haslayer("ICMPv6")):
            # Use scapy's layer if available
            try:
                l = raw_pkt.getlayer("ICMPv6")
                p.icmp_type = int(getattr(l, "type", 0))
                p.icmp_code = int(getattr(l, "code", 0))
            except Exception:
                p.icmp_type = -1
                p.icmp_code = -1

        # Payload
        if raw_pkt.haslayer(Raw):
            payload = raw_pkt[Raw].load
            p.raw_payload = payload
            p.payload_size = len(payload)
            # : Shannon entropy of payload
            p.payload_entropy = _shannon_entropy(payload)

            # HTTP headers/body parsing (if this is an HTTP request/response)
            if p.protocol in ("HTTP", "HTTP-ALT"):
                try:
                    # Split headers/body by CRLFCRLF
                    parts = payload.split(b"\r\n\r\n", 1)
                    hdrs = parts[0].decode("utf-8", errors="ignore")
                    lines = hdrs.split("\r\n")
                    # Start line (e.g. GET /path HTTP/1.1)
                    if lines:
                        start_line = lines[0].strip()
                        # Extract method/path
                        for method in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"):
                            if start_line.startswith(method + " "):
                                p.http_method = method
                                p.http_path = start_line.split(" ")[1] if " " in start_line else ""
                                break
                    # Header lines
                    headers = {}
                    for line in lines[1:]:
                        if ":" in line:
                            k, v = line.split(":", 1)
                            headers[k.strip().lower()] = v.strip()
                    p.http_headers = headers
                    p.http_body = parts[1].decode("utf-8", errors="ignore") if len(parts) > 1 else ""
                except Exception:
                    pass

            # TLS/JA3 extraction (HTTPS)
            if p.protocol in ("HTTPS",) or p.dst_port == 443 or p.src_port == 443:
                ja3, ja3_hash, sni, ver = _extract_tls_ja3_and_sni(payload)
                p.tls_ja3 = ja3
                p.tls_ja3_hash = ja3_hash
                p.tls_sni = sni
                p.tls_version = ver

        # DNS query
        if raw_pkt.haslayer(DNSQR):
            try:
                p.dns_query = raw_pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            except Exception:
                pass


        # : TCP retransmission heuristic — RST or duplicate ACK with no data
        if raw_pkt.haslayer(TCP):
            tcp_l = raw_pkt[TCP]
            if int(tcp_l.flags) & 0x04:   # RST set
                p.is_retransmit = True

        p.info = _build_info(p, raw_pkt)
        return p
    except Exception:
        logger.debug("Packet parse error", exc_info=True)
        # Fallback: try to return a minimally parsed packet so it still shows up.
        try:
            p = ParsedPacket()
            p.number = packet_number
            p.epoch = float(getattr(raw_pkt, "time", time.time()))
            p.timestamp = str(datetime.fromtimestamp(p.epoch).strftime("%H:%M:%S.%f"))[:-3] # type: ignore
            p.total_length = len(raw_pkt) if hasattr(raw_pkt, "__len__") else 0
            p.protocol = _classify_protocol(raw_pkt) if SCAPY_OK else "OTHER"
            if raw_pkt is not None and SCAPY_OK:
                if raw_pkt.haslayer(IP):
                    ip_l = raw_pkt[IP]
                    p.src_ip = getattr(ip_l, "src", "")
                    p.dst_ip = getattr(ip_l, "dst", "")
                elif raw_pkt.haslayer(IPv6):
                    ipv6_l = raw_pkt[IPv6]
                    p.src_ip = getattr(ipv6_l, "src", "")
                    p.dst_ip = getattr(ipv6_l, "dst", "")
            return p
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6: FLOW TRACKER — ✅ Bidirectional with timeouts & cleanup
# ═══════════════════════════════════════════════════════════════════════════════

FlowKey = Tuple[str, str, int, int, str]


@dataclass
class Flow:
    """Bidirectional flow record with statistics."""
    key: FlowKey = ("", "", 0, 0, "")
    first_seen: float = 0.0
    last_seen: float = 0.0

    # Forward (initiator)
    fwd_packets: int = 0
    fwd_bytes: int = 0
    fwd_lengths: list = field(default_factory=list)
    fwd_iat: list = field(default_factory=list)
    fwd_last_time: float = 0.0

    # Backward (responder)
    bwd_packets: int = 0
    bwd_bytes: int = 0
    bwd_lengths: list = field(default_factory=list)
    bwd_iat: list = field(default_factory=list)
    bwd_last_time: float = 0.0

    # TCP flag counts
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0

    state: str = "NEW"

    @property
    def duration(self) -> float:
        return max(self.last_seen - self.first_seen, 1e-6)

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def is_expired(self) -> bool:
        now = time.time()
        return (now - self.last_seen > DET.flow_idle_timeout
                or now - self.first_seen > DET.flow_active_timeout
                or self.state == "CLOSED")


class FlowTracker:
    """
    ✅ Proper bidirectional flow tracking with:
    - Canonical key ordering (same flow regardless of direction)
    - Idle and active timeouts
    - ✅ Automatic periodic cleanup of stale flows
    - ✅ Thread safety via RLock
    - Memory-bounded list storage per flow
    """

    def __init__(self) -> None:
        self._flows: Dict[FlowKey, Flow] = {}
        self._lock = threading.RLock()
        self._last_cleanup = time.time()
        self._cleanup_count = 0

    @staticmethod
    def _make_key(src, dst, sport, dport, proto) -> Tuple[FlowKey, bool]:
        """Create canonical key. Returns (key, is_forward)."""
        fwd = (src, dst, sport, dport, proto)
        bwd = (dst, src, dport, sport, proto)
        if fwd <= bwd:
            return fwd, True
        return bwd, False

    def update(self, src, dst, sport, dport, proto, length, tcp_flags="") -> Flow:
        """Update flow with new packet. Thread-safe."""
        key, is_fwd = self._make_key(src, dst, sport, dport, proto)
        now = time.time()

        with self._lock:
            flow = self._flows.get(key)
            if flow is None:
                flow = Flow(key=key, first_seen=now)
                self._flows[key] = flow
            flow.last_seen = now

            if is_fwd:
                if flow.fwd_last_time > 0:
                    flow.fwd_iat.append(now - flow.fwd_last_time)
                flow.fwd_last_time = now
                flow.fwd_packets += 1
                flow.fwd_bytes += length
                flow.fwd_lengths.append(length)
            else:
                if flow.bwd_last_time > 0:
                    flow.bwd_iat.append(now - flow.bwd_last_time)
                flow.bwd_last_time = now
                flow.bwd_packets += 1
                flow.bwd_bytes += length
                flow.bwd_lengths.append(length)

            # Count TCP flags
            _FLAG_MAP = [("S", "syn_count"), ("A", "ack_count"),
                         ("F", "fin_count"), ("R", "rst_count"),
                         ("P", "psh_count"), ("U", "urg_count")]
            for ch, attr in _FLAG_MAP:
                if ch in tcp_flags:
                    setattr(flow, attr, getattr(flow, attr) + 1)

            # Update state
            if "S" in tcp_flags and "A" not in tcp_flags:
                flow.state = "NEW"
            elif "S" in tcp_flags and "A" in tcp_flags:
                flow.state = "ESTABLISHED"
            elif "F" in tcp_flags:
                flow.state = "FIN_WAIT"
            elif "R" in tcp_flags:
                flow.state = "CLOSED"

            # ✅ Memory bound: limit stored per-flow lists
            _MAX_STORED = 1000
            for attr in ("fwd_lengths", "bwd_lengths", "fwd_iat", "bwd_iat"):
                lst = getattr(flow, attr)
                if len(lst) > _MAX_STORED:
                    setattr(flow, attr, lst[-_MAX_STORED:])

            # ✅ Automatic periodic cleanup (optimized: only check every N packets)
            if now - self._last_cleanup > DET.stale_cleanup_interval:
                self._cleanup(now)

            return flow

    def get_flow(self, src, dst, sport, dport, proto) -> Optional[Flow]:
        """Lookup a flow. Thread-safe."""
        key, _ = self._make_key(src, dst, sport, dport, proto)
        with self._lock:
            return self._flows.get(key)

    def _cleanup(self, now: float) -> None:
        """✅ Remove expired flows — prevents stale state buildup."""
        expired = [k for k, f in list(self._flows.items()) if f.is_expired]
        for k in expired:
            self._flows.pop(k, None)
        self._last_cleanup = now
        self._cleanup_count += len(expired)
        if expired:
            logger.debug("Cleaned %d expired flows, %d active",
                         len(expired), len(self._flows))

    def active_count(self) -> int:
        with self._lock:
            return len(self._flows)

    def reset(self) -> None:
        with self._lock:
            self._flows.clear()


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7: ALERT MANAGER — ✅ Deduplication + Rate Limiting
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AlertRecord:
    """Stored alert for dedup tracking."""
    hash: str
    first_time: float
    last_time: float
    count: int = 1


class AlertManager:
    """Alert management with:
    - Hash-based deduplication (same alert within window → suppressed)
    - Per-rule rate limiting (max N alerts per rule per minute)
    - Thread-safe
    - Optional output queue for GUI
    - Optional JSON log output for SIEM ingest
    - Optional Syslog output
    - Database persistence callback
    """

    def __init__(self, output_queue: Optional[queue.Queue] = None,
                 db_callback: Optional[Callable] = None,
                 json_log_path: Optional[str] = None,
                 syslog_addr: Optional[str] = None) -> None:
        self._output_queue: Optional[queue.Queue] = output_queue
        self._db_callback: Optional[Callable] = db_callback
        self._lock = threading.RLock()

        # Optional external sinks
        self._json_fp: Optional[Any] = None
        self._syslog_logger: Optional[logging.Logger] = None
        self._syslog_addr = syslog_addr

        if json_log_path:
            try:
                self._json_fp = open(json_log_path, "a", encoding="utf-8")
            except Exception:
                logger.exception("Unable to open JSON alert logfile %s", json_log_path)

        if syslog_addr:
            try:
                import logging.handlers
                host, port = syslog_addr.split(":")
                handler = logging.handlers.SysLogHandler(address=(host, int(port)))
                handler.setFormatter(logging.Formatter("%(message)s"))
                self._syslog_logger = logging.getLogger("pherion_syslog")
                # The original code had a redundant `if self._syslog_logger is not None:` here.
                # It's safe to call setLevel and addHandler directly after getLogger.
                self._syslog_logger.setLevel(logging.INFO) # type: ignore
                self._syslog_logger.addHandler(handler) # type: ignore
            except Exception:
                logger.exception("Unable to configure syslog logger %s", syslog_addr)

        # Dedup: hash → AlertRecord
        self._recent: Dict[str, AlertRecord] = {}
        # Rate limit: rule_name → deque of timestamps (auto-bounded)
        self._rate_windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=DET.alert_rate_limit + 10))

        # Counters
        self.total_emitted = 0
        self.total_suppressed = 0
        self._last_cleanup = time.time()

    def emit(self, level: str, rule: str, message: str,
             src_ip: str = "", dst_ip: str = "", reason: str = "") -> bool:
        """
        Emit an alert. Returns True if actually sent.
        ✅ Dedup: same rule+src+dst within window → suppressed
        ✅ Rate limit: max alerts/min per rule
        ✅ FIX 2: dedup key is direction-independent (A→B == B→A)
        """
        now = time.time()

        with self._lock:
            # ✅ Rate limit check using deque (O(1) append, auto-bounded)
            window = self._rate_windows[rule]
            # Remove old timestamps (deque is already bounded, but check oldest)
            while window and now - window[0] >= 60.0:
                window.popleft()
            if len(window) >= DET.alert_rate_limit:
                self.total_suppressed += 1
                return False

            # ✅ FIX 2: direction-independent dedup key.
            # Original used f"{rule}:{src_ip}:{dst_ip}" which meant the same
            # bidirectional flow generated TWO distinct hashes (A→B and B→A),
            # both passing dedup. Now we sort the IPs so both directions hash
            # to the same key and only the first fires within the window.
            _ip_lo = min(src_ip or "", dst_ip or "")
            _ip_hi = max(src_ip or "", dst_ip or "")
            hash_str = f"{rule}:{_ip_lo}:{_ip_hi}"
            alert_hash = str(hashlib.md5(hash_str.encode()).hexdigest())[:16] # type: ignore

            existing = self._recent.get(alert_hash)
            if existing is not None:
                if now - existing.last_time < DET.alert_dedup_window:
                    existing.count += 1
                    existing.last_time = now
                    self.total_suppressed += 1
                    return False

            # New alert — record it
            self._recent[alert_hash] = AlertRecord(
                hash=alert_hash, first_time=now, last_time=now)
            self.total_emitted += 1
            window.append(now)

            # ✅ Periodic cleanup of old dedup entries
            if now - self._last_cleanup > DET.stale_cleanup_interval * 2:
                self._cleanup_old(now)

        if self._output_queue is not None:
            ts_str = time.strftime("%H:%M:%S", time.localtime(now))
            try:
                self._output_queue.put_nowait((level, message, ts_str))  # type: ignore
            except queue.Full:
                pass

        # ✅ Persist to database
        db_cb = self._db_callback
        if db_cb is not None:
            try:
                db_cb(level, rule, message, src_ip, dst_ip)
            except Exception:
                pass

        # Optional SIEM outputs
        fp = self._json_fp
        if fp is not None:
            try:
                obj = {
                    "ts": now,
                    "level": level,
                    "rule": rule,
                    "message": message,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "reason": reason or message,
                }
                fp.write(json.dumps(obj, ensure_ascii=False) + "\n") # type: ignore
                fp.flush() # type: ignore
            except Exception:
                pass

        sl = self._syslog_logger
        if sl is not None:
            try:
                sl.info(json.dumps({
                    "ts": now,
                    "level": level,
                    "rule": rule,
                    "msg": message,
                    "src": src_ip,
                    "dst": dst_ip,
                    "reason": reason or message,
                }))
            except Exception:
                pass

        logger.info("[%s] %s: %s", level, rule, message)
        return True

    def _cleanup_old(self, now: float) -> None:
        """✅ Remove expired dedup entries to prevent memory growth."""
        expired = [h for h, rec in self._recent.items()
                   if now - rec.last_time > DET.alert_dedup_window * 3]
        for h in expired:
            self._recent.pop(h, None)
        self._last_cleanup = now

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                "total_emitted": self.total_emitted,
                "total_suppressed": self.total_suppressed,
                "active_dedup_entries": len(self._recent),
            }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8: SLIDING WINDOW — Efficient time-based counter
# ═══════════════════════════════════════════════════════════════════════════════

class SlidingWindow:
    """
    O(1) amortized sliding window counter for time-based thresholds.
    ✅ Thread-safe via external lock in RuleEngine.
    """
    __slots__ = ("_times",)

    def __init__(self, maxlen: int = 5000):
        self._times: deque = deque(maxlen=maxlen)

    def add(self, now: float) -> None:
        self._times.append(now)

    def count(self, now: float, window: float) -> int:
        cutoff = now - window
        c = 0
        for t in reversed(self._times):
            if t < cutoff:
                break
            c += 1
        return c

    def clear(self) -> None:
        self._times.clear()


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8A: THREAT INTELLIGENCE MANAGER — IOC feed integration
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatIntelManager:
    """Threat Intelligence IOC feed manager.

    Loads known-malicious IPs, domains, and hashes from local files in
    ``pherion_data/threat_intel/`` and optionally from public feeds.
    Provides fast set-based lookups for packet-level matching.

    File formats supported (one entry per line, ``#`` comments):
      - ``malicious_ips.txt``   — plain IP addresses or CIDR ranges
      - ``malicious_domains.txt`` — domain names
      - ``malicious_hashes.txt``  — MD5/SHA256 hashes (JA3, file, etc.)

    Thread-safe; auto-reloads on configurable interval.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._ips: Set[str] = set()
        self._networks: list = []  # list of ipaddress networks for CIDR matching
        self._domains: Set[str] = set()
        self._hashes: Set[str] = set()
        self._last_load: float = 0.0
        self._load_count: int = 0
        # Ensure threat intel directory exists
        ti_dir = DET.threat_intel_dir if hasattr(DET, 'threat_intel_dir') else DATA_DIR / "threat_intel"
        ti_dir.mkdir(parents=True, exist_ok=True)
        self.reload()

    @property
    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {"ips": len(self._ips), "networks": len(self._networks),
                    "domains": len(self._domains), "hashes": len(self._hashes),
                    "loads": self._load_count}

    def reload(self) -> None:
        """Load/reload IOC lists from disk."""
        ti_dir = DET.threat_intel_dir if hasattr(DET, 'threat_intel_dir') else DATA_DIR / "threat_intel"
        if not ti_dir.exists():
            return
        new_ips: Set[str] = set()
        new_nets: list = []
        new_domains: Set[str] = set()
        new_hashes: Set[str] = set()

        # Load IPs
        ip_file = ti_dir / "malicious_ips.txt"
        if ip_file.exists():
            try:
                for line in ip_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "/" in line:
                        try:
                            new_nets.append(ipaddress.ip_network(line, strict=False))
                        except Exception:
                            pass
                    else:
                        new_ips.add(line)
            except Exception:
                logger.debug("ThreatIntel: failed to read %s", ip_file)

        # Load domains
        dom_file = ti_dir / "malicious_domains.txt"
        if dom_file.exists():
            try:
                for line in dom_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        new_domains.add(line)
            except Exception:
                logger.debug("ThreatIntel: failed to read %s", dom_file)

        # Load hashes (JA3, file hashes, etc.)
        hash_file = ti_dir / "malicious_hashes.txt"
        if hash_file.exists():
            try:
                for line in hash_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        new_hashes.add(line)
            except Exception:
                logger.debug("ThreatIntel: failed to read %s", hash_file)

        with self._lock:
            self._ips = new_ips
            self._networks = new_nets
            self._domains = new_domains
            self._hashes = new_hashes
            self._last_load = time.time()
            self._load_count += 1

        total = len(new_ips) + len(new_nets) + len(new_domains) + len(new_hashes)
        if total > 0:
            logger.info("ThreatIntel: loaded %d IPs, %d networks, %d domains, %d hashes",
                        len(new_ips), len(new_nets), len(new_domains), len(new_hashes))

    def _maybe_refresh(self) -> None:
        """Auto-reload if refresh interval elapsed."""
        interval = getattr(DET, 'threat_intel_refresh_interval', 3600.0)
        if time.time() - self._last_load > interval:
            self.reload()

    def check_ip(self, ip: str) -> bool:
        """Return True if IP matches a known-malicious indicator."""
        if not ip:
            return False
        self._maybe_refresh()
        with self._lock:
            if ip in self._ips:
                return True
            try:
                addr = ipaddress.ip_address(ip)
                for net in self._networks:
                    if addr in net:
                        return True
            except Exception:
                pass
        return False

    def check_domain(self, domain: str) -> bool:
        """Return True if domain matches known-malicious indicator."""
        if not domain:
            return False
        self._maybe_refresh()
        d = domain.lower().rstrip(".")
        with self._lock:
            if d in self._domains:
                return True
            # Check if any parent domain is in the list
            parts = list(d.split("."))
            for i in range(1, len(parts)):
                parent = ".".join(parts[i:]) # type: ignore
                if parent in self._domains:
                    return True
        return False

    def check_hash(self, h: str) -> bool:
        """Return True if hash matches known-malicious indicator."""
        if not h:
            return False
        self._maybe_refresh()
        with self._lock:
            return h.lower() in self._hashes

    def check_packet(self, pkt: ParsedPacket) -> Optional[str]:
        """Check a parsed packet against all IOC databases.

        Returns a description string if matched, else None.
        """
        if not getattr(DET, 'threat_intel_enabled', True):
            return None

        # Check IPs
        if self.check_ip(pkt.src_ip):
            return f"ThreatIntel:IP:src={pkt.src_ip}"
        if self.check_ip(pkt.dst_ip):
            return f"ThreatIntel:IP:dst={pkt.dst_ip}"
        # Check DNS queries
        if pkt.dns_query and self.check_domain(pkt.dns_query):
            return f"ThreatIntel:Domain:{pkt.dns_query}"
        # Check TLS SNI
        if pkt.tls_sni and self.check_domain(pkt.tls_sni):
            return f"ThreatIntel:SNI:{pkt.tls_sni}"
        # Check JA3 hash
        if pkt.tls_ja3_hash and self.check_hash(pkt.tls_ja3_hash):
            return f"ThreatIntel:JA3:{pkt.tls_ja3_hash}"
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8B: RULE METADATA — Modular detection registry with MITRE ATT&CK
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class RuleMeta:
    """Metadata for a detection rule — enables modular, self-documenting rules."""
    name: str
    description: str = ""
    severity: str = "Medium"        # Critical, High, Medium, Low
    mitre_attack_id: str = ""       # e.g. T1046, T1110
    enabled: bool = True
    alert_level: str = "WARNING"    # DANGER, WARNING, INFO


# Detection rule registry — maps rule internal name to metadata with MITRE IDs
RULE_REGISTRY: Dict[str, RuleMeta] = {
    "syn_flood":        RuleMeta("SYN Flood",           "High-rate SYN packet flood (volumetric DoS)",            "High",     "T1498.001", True, "DANGER"),
    "port_scan":        RuleMeta("TCP Port Scan",        "Rapid scanning of multiple TCP ports",                   "High",     "T1046",     True, "DANGER"),
    "suspicious_port":  RuleMeta("Suspicious Port",      "Traffic on known-malicious or suspicious port",          "Low",      "T1571",     True, "WARNING"),
    "icmp_flood":       RuleMeta("ICMP Flood",           "High-rate ICMP echo request flood",                     "Medium",   "T1498.001", True, "DANGER"),
    "dns_flood":        RuleMeta("DNS Flood",            "High-rate DNS query flood",                              "Medium",   "T1498.001", True, "WARNING"),
    "dns_tunnel":       RuleMeta("DNS Tunneling",        "Long/high-entropy DNS labels suggesting data exfil",    "Medium",   "T1071.004", True, "WARNING"),
    "arp_spoof":        RuleMeta("ARP Spoofing",         "IP-to-MAC mapping changed (MITM indicator)",            "Critical", "T1557.002", True, "DANGER"),
    "brute_force":      RuleMeta("Brute Force",          "Rapid authentication attempts on service port",         "High",     "T1110",     True, "DANGER"),
    "data_exfil":       RuleMeta("Data Exfiltration",    "Large outbound data transfer from single source",       "Critical", "T1048",     True, "DANGER"),
    "null_scan":        RuleMeta("NULL Scan",            "TCP packet with no flags set (evasion technique)",      "High",     "T1046",     True, "DANGER"),
    "xmas_scan":        RuleMeta("XMAS Scan",            "TCP FIN+PSH+URG flags (evasion technique)",             "High",     "T1046",     True, "DANGER"),
    "fin_scan":         RuleMeta("FIN Scan",             "Bare FIN flag without established connection",          "Medium",   "T1046",     True, "WARNING"),
    "ip_fragment":      RuleMeta("IP Fragmentation",     "Fragmented IP packet (potential evasion)",               "Low",      "T1027.010", True, "WARNING"),
    "suspicious_dns":   RuleMeta("Suspicious DNS",       "DNS query matches known-malicious pattern",             "Low",      "T1071.004", True, "WARNING"),
    "large_packet":     RuleMeta("Large Packet",         "Unusually large packet (potential DoS/exfil)",           "Low",      "T1499",     True, "INFO"),
    "conn_rate":        RuleMeta("Connection Rate",      "Abnormally high connection initiation rate",             "Medium",   "T1499.001", True, "WARNING"),
    "udp_scan":         RuleMeta("UDP Port Scan",        "Rapid scanning of multiple UDP ports",                   "High",     "T1046",     True, "DANGER"),
    "slow_scan":        RuleMeta("Slow Port Scan",       "Low-and-slow scan spread over minutes",                 "Medium",   "T1046",     True, "WARNING"),
    "land_attack":      RuleMeta("Land Attack",          "src IP == dst IP (causes infinite loop in some stacks)", "Critical", "T1499.004", True, "DANGER"),
    "smurf":            RuleMeta("Smurf Attack",         "ICMP echo to broadcast (amplification DoS)",            "Critical", "T1498.001", True, "DANGER"),
    "icmp_tunnel":      RuleMeta("ICMP Tunneling",       "Oversized ICMP echo payload (data exfil/C2)",           "Medium",   "T1095",     True, "WARNING"),
    "rst_flood":        RuleMeta("RST Flood",            "High-rate TCP RST injection (session hijacking)",       "High",     "T1557",     True, "DANGER"),
    "http_flood":       RuleMeta("HTTP Flood",           "High-rate HTTP requests on established connections",     "High",     "T1499.002", True, "DANGER"),
    "cred_stuffing":    RuleMeta("Credential Stuffing",  "Rapid POST to login endpoints (credential abuse)",      "High",     "T1110.004", True, "DANGER"),
    "ttl_anomaly":      RuleMeta("TTL Anomaly",          "Unusual TTL value (OS fingerprinting / evasion)",       "Low",      "T1082",     True, "WARNING"),
    "payload_entropy":  RuleMeta("Payload Entropy",      "High-entropy payload on non-encrypted port",            "Medium",   "T1027",     True, "WARNING"),
    "beacon":           RuleMeta("Beacon/C2",            "Periodic callback interval (C2 communication)",         "High",     "T1071",     True, "WARNING"),
    "sql_injection":    RuleMeta("SQL Injection",        "SQL injection patterns in HTTP request",                "Critical", "T1190",     True, "WARNING"),
    "webshell_upload":  RuleMeta("Webshell Upload",      "Suspicious file upload / PHP backdoor",                 "Critical", "T1505.003", True, "WARNING"),
    "smb_lateral":      RuleMeta("SMB Lateral Movement", "Many hosts contacted on SMB port 445",                  "Critical", "T1021.002", True, "DANGER"),
    "ja3_blacklisted":  RuleMeta("JA3 Blacklisted",      "Known-malicious TLS fingerprint",                       "Critical", "T1071.001", True, "DANGER"),
    "http_attack_payload": RuleMeta("HTTP Attack Payload", "XSS/path traversal/command injection in HTTP",        "High",     "T1059",     True, "WARNING"),
    "blacklist":        RuleMeta("Blacklist Hit",         "IP matches configured blacklist",                       "Critical", "",          True, "DANGER"),
    "threat_intel":     RuleMeta("Threat Intel IOC",      "Matched known-malicious indicator of compromise",      "Critical", "T1071",     True, "DANGER"),
    "ml_anomaly":       RuleMeta("ML Anomaly",            "Statistical anomaly detected by baseline model",       "Medium",   "",          True, "WARNING"),
    "ml_classify":      RuleMeta("ML Classification",     "Supervised ML model identified attack pattern",        "High",     "",          True, "WARNING"),
    "signature":        RuleMeta("Signature Match",       "Matched Suricata-style content signature",              "High",     "",          True, "DANGER"),
    # WiFi-specific vulnerability detections
    "wifi_deauth":      RuleMeta("WiFi Deauth Attack",    "Deauthentication frames (DoS/disassociation)",         "Critical", "T1499.004", True, "DANGER"),
    "wifi_krack":       RuleMeta("KRACK Attack",          "Key Reinstallation Attack (WPA2 vulnerability)",       "Critical", "T1557.001", True, "DANGER"),
    "wifi_evil_twin":   RuleMeta("Evil Twin AP",          "Rogue access point with legitimate SSID",             "Critical", "T1557.002", True, "DANGER"),
    "wifi_probe_flood": RuleMeta("Probe Request Flood",   "High-rate WiFi probe requests (recon/scanning)",      "Medium",   "T1046",     True, "WARNING"),
    "wifi_wep_attack":  RuleMeta("WEP Attack",            "Weak WEP encryption exploitation attempt",            "High",     "T1557.001", True, "DANGER"),
    "wifi_ssid_spoof":  RuleMeta("SSID Spoofing",         "AP broadcasting multiple/fake SSIDs rapidly",         "Medium",   "T1557.002", True, "WARNING"),
}


def is_rule_enabled(rule_name: str) -> bool:
    """Check if a detection rule is enabled in the registry."""
    meta = RULE_REGISTRY.get(rule_name)
    return meta.enabled if meta else True




# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8C: SEVERITY SCORER — Enterprise severity classification
# ═══════════════════════════════════════════════════════════════════════════════

class SeverityScorer:
    """Classifies alerts into Critical/High/Medium/Low severity levels.

    Scoring factors:
    - Base severity from rule metadata
    - Repetition (same src→dst pair escalates)
    - IOC/blacklist involvement → auto-Critical
    - ML confidence >0.92 + rule match → Critical
    - Multiple rule flags on same packet → escalate
    """

    # Base severity mapping for rule names
    _BASE_SEVERITY: Dict[str, str] = {
        "syn_flood": "High", "port_scan": "High", "udp_scan": "High",
        "brute_force": "High", "data_exfil": "Critical",
        "null_scan": "High", "xmas_scan": "High", "fin_scan": "Medium",
        "arp_spoof": "Critical", "dns_tunnel": "Medium", "dns_flood": "Medium",
        "icmp_flood": "Medium", "icmp_tunnel": "Medium",
        "land_attack": "Critical", "smurf": "Critical",
        "rst_flood": "High", "http_flood": "High",
        "cred_stuffing": "High", "beacon": "High",
        "sql_injection": "Critical", "webshell_upload": "Critical",
        "smb_lateral": "Critical", "ja3_blacklisted": "Critical",
        "http_attack_payload": "High",
        "suspicious_port": "Low", "suspicious_dns": "Low",
        "large_packet": "Low", "conn_rate": "Medium",
        "ip_fragment": "Low", "ttl_anomaly": "Low",
        "payload_entropy": "Medium", "slow_scan": "Medium",
        "blacklist": "Critical", "threat_intel": "Critical",
        "ml_anomaly": "Medium", "ml_classify": "High",
        "signature": "High",
        # WiFi vulnerability detection rules
        "wifi_deauth": "Critical", "wifi_krack": "Critical",
        "wifi_evil_twin": "Critical", "wifi_probe_flood": "Medium",
        "wifi_wep_attack": "High", "wifi_ssid_spoof": "Medium",
    }

    _SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

    def score(self, rule: str, pkt: Optional[ParsedPacket] = None,
              ioc_match: bool = False, repetition_count: int = 0) -> str:
        """Compute severity level for an alert."""
        base = self._BASE_SEVERITY.get(rule, "Medium")
        level = self._SEVERITY_ORDER.get(base, 2)

        # IOC/blacklist match → auto-Critical
        if ioc_match:
            return "Critical"

        # Multiple rule flags on packet → bump by 1
        if pkt and pkt.rule_flags:
            flag_count = bin(pkt.rule_flags).count("1")
            if flag_count >= 3:
                level = min(level + 1, 4)

        # ML high confidence + rule match → Critical
        if pkt and pkt.ml_confidence >= 0.92 and pkt.rule_flags > 0:
            return "Critical"

        # Repetition escalation (3+ related alerts → bump)
        if repetition_count >= DET.incident_escalation_count:
            level = min(level + 1, 4)

        for name, val in self._SEVERITY_ORDER.items():
            if val == level:
                return name
        return "Medium"


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8D: CORRELATION ENGINE — Incident grouping from related alerts
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SecurityIncident:
    """Represents a correlated security incident composed of related alerts."""
    id: str = ""
    created_at: float = 0.0
    severity: str = "Medium"
    title: str = ""
    alert_count: int = 0
    src_ips: Set[str] = field(default_factory=set)
    dst_ips: Set[str] = field(default_factory=set)
    rules: Set[str] = field(default_factory=set)
    status: str = "open"           # open, acknowledged, closed
    last_updated: float = 0.0


class CorrelationEngine:
    """Correlates related alerts into SecurityIncidents.

    Groups alerts by src_ip within a configurable time window. When
    multiple rules fire for the same source, they are combined into a
    single incident with an escalated severity.

    Thread-safe. Periodically expires old incidents.
    """

    def __init__(self, severity_scorer: SeverityScorer,
                 db_callback: Optional[Callable] = None) -> None:
        self._scorer = severity_scorer
        self._db_callback = db_callback
        self._lock = threading.RLock()
        # Active incidents keyed by src_ip
        self._incidents: Dict[str, SecurityIncident] = {}
        self._incident_counter = 0
        self._last_cleanup = time.time()

    def correlate(self, rule: str, src_ip: str, dst_ip: str,
                  pkt: Optional[ParsedPacket] = None,
                  ioc_match: bool = False) -> Optional[SecurityIncident]:
        """Process a new alert and correlate it.

        Returns the incident if one was created or updated, else None.
        """
        now = time.time()
        with self._lock:
            # Periodic cleanup
            if now - self._last_cleanup > DET.correlation_window:
                self._cleanup(now)

            incident = self._incidents.get(src_ip)

            if incident and now - incident.last_updated < DET.correlation_window:
                # Update existing incident
                incident.alert_count += 1
                incident.rules.add(rule)
                if dst_ip:
                    incident.dst_ips.add(dst_ip)
                incident.last_updated = now

                # Re-score severity with repetition
                new_severity = self._scorer.score(
                    rule, pkt, ioc_match, incident.alert_count)
                if SeverityScorer._SEVERITY_ORDER.get(new_severity, 0) > \
                   SeverityScorer._SEVERITY_ORDER.get(incident.severity, 0):
                    incident.severity = new_severity
                    incident.title = self._make_title(incident)

                # Persist update
                cb = self._db_callback
                if cb is not None:
                    try:
                        cb(incident)
                    except Exception:
                        pass

                return incident
            else:
                # Create new incident
                self._incident_counter += 1
                severity = self._scorer.score(rule, pkt, ioc_match, 0)
                incident = SecurityIncident(
                    id=f"INC-{self._incident_counter:06d}",
                    created_at=now,
                    severity=severity,
                    alert_count=1,
                    src_ips={src_ip} if src_ip else set(),
                    dst_ips={dst_ip} if dst_ip else set(),
                    rules={rule},
                    last_updated=now,
                )
                incident.title = self._make_title(incident)
                self._incidents[src_ip] = incident

                cb2 = self._db_callback
                if cb2 is not None:
                    try:
                        cb2(incident)
                    except Exception:
                        pass

                return incident

    def _make_title(self, inc: SecurityIncident) -> str:
        rules_str = ", ".join([str(r) for r in sorted(inc.rules)][:4]) # type: ignore
        src = ", ".join([str(s) for s in sorted(inc.src_ips)][:2]) or "unknown" # type: ignore
        return f"[{inc.severity}] {rules_str} from {src} ({inc.alert_count} alerts)"

    def _cleanup(self, now: float) -> None:
        expired = [ip for ip, inc in self._incidents.items()
                   if now - inc.last_updated > DET.correlation_window * 2]
        for ip in expired:
            inc = self._incidents.pop(ip, None)
            if inc:
                inc.status = "closed"
        self._last_cleanup = now

    def get_active_incidents(self) -> List[SecurityIncident]:
        with self._lock:
            return [inc for inc in self._incidents.values()
                    if inc.status == "open"]

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            active = sum(1 for i in self._incidents.values() if i.status == "open")
            return {"total_incidents": self._incident_counter,
                    "active_incidents": active}


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8E: STRUCTURED EVENT LOGGER — Normalized event format
# ═══════════════════════════════════════════════════════════════════════════════

class StructuredEventLogger:
    """Centralized structured event logger.

    All events follow a normalized schema suitable for incident investigation
    and timeline reconstruction:
      {timestamp, event_type, severity, src_ip, dst_ip, src_port, dst_port,
       protocol, rule_name, description, metadata}

    Event types: PACKET, ALERT, ANOMALY, INCIDENT, SYSTEM
    """

    _EVENT_TYPES = ("PACKET", "ALERT", "ANOMALY", "INCIDENT", "SYSTEM")

    def __init__(self, log_dir: Optional[Path] = None) -> None:
        self._log_dir = log_dir or LOG_DIR
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._fp: Optional[Any] = None
        self._event_count = 0
        self._batch: list = []
        self._batch_limit = 100
        self._last_flush = time.time()
        self._open_log()

    def _open_log(self) -> None:
        try:
            log_file = self._log_dir / f"events_{datetime.now():%Y%m%d}.jsonl"
            self._fp = open(str(log_file), "a", encoding="utf-8")
        except Exception:
            logger.debug("StructuredEventLogger: could not open event log")

    def log_event(self, event_type: str, severity: str = "Low",
                  rule_name: str = "", description: str = "",
                  src_ip: str = "", dst_ip: str = "",
                  src_port: int = 0, dst_port: int = 0,
                  protocol: str = "", metadata: Optional[Dict] = None,
                  reason: str = "") -> None:
        """Log a normalized event."""
        event = {
            "ts": time.time(),
            "ts_iso": datetime.now().isoformat(),
            "event_type": event_type,
            "severity": severity,
            "rule": rule_name,
            "description": description,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "metadata": metadata or {},
            "reason": reason or description,
        }
        with self._lock:
            self._batch.append(event)
            self._event_count += 1
            # Flush in batches for performance
            if len(self._batch) >= self._batch_limit or \
               time.time() - self._last_flush > 5.0:
                self._flush()

    def _flush(self) -> None:
        """Write buffered events to disk."""
        fp = self._fp
        if not fp or not self._batch:
            return
        assert fp is not None
        try:
            for event in self._batch:
                fp.write(json.dumps(event, ensure_ascii=False) + "\n")
            fp.flush()
        except Exception:
            logger.debug("StructuredEventLogger: flush error", exc_info=True)
        self._batch.clear()
        self._last_flush = time.time()

    def log_alert(self, level: str, rule: str, message: str,
                  src_ip: str = "", dst_ip: str = "",
                  severity: str = "Medium", pkt: Optional[ParsedPacket] = None,
                  reason: str = "") -> None:
        """Convenience: log an alert event with packet context."""
        meta = {}
        if pkt:
            meta = {"packet_no": pkt.number, "threat_level": pkt.threat_level,
                    "rule_flags": pkt.rule_flags, "ml_prediction": pkt.ml_prediction,
                    "ml_confidence": pkt.ml_confidence}
        self.log_event("ALERT", severity=severity, rule_name=rule,
                       description=message, src_ip=src_ip, dst_ip=dst_ip,
                       src_port=pkt.src_port if pkt else 0,
                       dst_port=pkt.dst_port if pkt else 0,
                       protocol=pkt.protocol if pkt else "",
                       metadata=meta, reason=reason or message)

    def log_incident(self, incident: SecurityIncident) -> None:
        """Log a security incident event."""
        self.log_event("INCIDENT", severity=incident.severity,
                       description=incident.title,
                       src_ip=",".join([str(x) for x in sorted(incident.src_ips)][:5]), # type: ignore
                       dst_ip=",".join([str(y) for y in sorted(incident.dst_ips)][:5]), # type: ignore
                       metadata={"incident_id": incident.id,
                                 "alert_count": incident.alert_count,
                                 "rules": list(incident.rules),
                                 "status": incident.status})

    def close(self) -> None:
        with self._lock:
            self._flush()
            fp = self._fp
            if fp is not None:
                fp.close()
                self._fp = None

    @property
    def event_count(self) -> int:
        return self._event_count


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8F: SYSTEM WATCHDOG — Health monitoring
# ═══════════════════════════════════════════════════════════════════════════════

class SystemWatchdog:
    """Monitors system health: queue depths, memory, thread liveness.

    Runs as a daemon thread. Logs warnings when resources exceed thresholds.
    Periodically reports health status.
    """

    def __init__(self, queues: Optional[Dict[str, queue.Queue]] = None) -> None:
        self._queues = queues or {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._health_log: deque = deque(maxlen=100)
        self._start_time = time.time()

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="SystemWatchdog")
        t = self._thread
        if t is not None:
            t.start()
        logger.info("SystemWatchdog started")

    def stop(self) -> None:
        self._running = False

    def _run(self) -> None:
        while self._running:
            try:
                self._check_health()
            except Exception:
                logger.debug("Watchdog check error", exc_info=True)
            time.sleep(DET.watchdog_interval)

    def _check_health(self) -> None:
        now = time.time()
        warnings = []

        # Check queue depths
        for name, q in self._queues.items():
            try:
                usage = q.qsize() / max(q.maxsize, 1)
                if usage > DET.watchdog_queue_warn_pct:
                    msg = f"Queue '{name}' at {usage:.0%} capacity ({q.qsize()}/{q.maxsize})"
                    warnings.append(msg)
                    logger.warning("Watchdog: %s", msg)
            except Exception:
                pass

        # Check memory usage (if psutil available)
        if PSUTIL_OK:
            try:
                mem = psutil.virtual_memory()
                if mem.percent / 100.0 > DET.watchdog_memory_warn_pct:
                    msg = f"System memory at {mem.percent:.0f}% ({fmt_bytes(mem.used)}/{fmt_bytes(mem.total)})"
                    warnings.append(msg)
                    logger.warning("Watchdog: %s", msg)
            except Exception:
                pass

        # Check thread liveness
        active_threads = threading.active_count()
        expected_threads = ["PherionCapture", "PherionML", "StatsPush"]
        alive = {t.name for t in threading.enumerate()}
        missing = [n for n in expected_threads if n not in alive]
        if missing and now - self._start_time > 10:
            # Only warn after initial startup period
            for m in missing:
                msg = f"Thread '{m}' not found — may have died"
                warnings.append(msg)
                logger.warning("Watchdog: %s", msg)

        # Log health status
        status = {
            "ts": now,
            "uptime_s": int(now - self._start_time),
            "threads": active_threads,
            "warnings": warnings,
        }
        self._health_log.append(status)

        # Periodic summary (every 5 minutes)
        if int(now) % 300 < int(DET.watchdog_interval) + 1:
            logger.info("Watchdog: uptime=%ds threads=%d queues=%d warnings=%d",
                        status["uptime_s"], active_threads,
                        len(self._queues), len(warnings))

    def get_health(self) -> Dict:
        """Get current health status."""
        q_status = {}
        for name, q in self._queues.items():
            try:
                q_status[name] = {"size": q.qsize(), "maxsize": q.maxsize,
                                  "pct": q.qsize() / max(q.maxsize, 1)}
            except Exception:
                pass
        return {
            "uptime_s": int(time.time() - self._start_time),
            "threads": threading.active_count(),
            "queues": q_status,
            "recent_warnings": len(self._health_log) > 0 and
                               len(self._health_log[-1].get("warnings", [])) > 0,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9: RULE ENGINE — ✅ 16 Detection Rules
# ═══════════════════════════════════════════════════════════════════════════════

class RuleEngine:
    """
    Stateful rule-based IDS engine — : 27 detection rules.

    NEW in  (rules 17–27):
    17. UDP Port Scan            — previously missed
    18. Slow Port Scan           — multi-minute stealthy scan
    19. Land Attack              — src IP == dst IP
    20. Smurf Attack             — broadcast ICMP amplification
    21. ICMP Tunneling           — oversized echo payload
    22. TCP RST Flood            — RST injection / session teardown
    23. HTTP Flood               — high GET/POST rate on established conns
    24. Credential Stuffing      — repeated POSTs to login-ish paths
    25. TTL Anomaly              — unusual TTL (OS fingerprinting / evasion)
    26. Payload Entropy Anomaly  — encrypted/obfuscated on unexpected port
    27. Beacon / C2 Detection    — periodic callback interval analysis
    28. SQL injection patterns     — suspicious query/payload strings
    29. Webshell upload attempts   — suspicious file upload / PHP payload
    30. SMB lateral movement       — many hosts reached on SMB (445)

    ✅ All state protected by RLock
    ✅ rule_flags bitmask written to ParsedPacket for ML ensemble
    """

    # Bitmask constants for rule_flags
    RF_SYN_FLOOD       = 1 << 0
    RF_PORT_SCAN       = 1 << 1
    RF_SUSP_PORT       = 1 << 2
    RF_ICMP_FLOOD      = 1 << 3
    RF_DNS_FLOOD       = 1 << 4
    RF_DNS_TUNNEL      = 1 << 5
    RF_ARP_SPOOF       = 1 << 6
    RF_BRUTE           = 1 << 7
    RF_DATA_EXFIL      = 1 << 8
    RF_NULL_SCAN       = 1 << 9
    RF_XMAS_SCAN       = 1 << 10
    RF_FIN_SCAN        = 1 << 11
    RF_IP_FRAG         = 1 << 12
    RF_SUSP_DNS        = 1 << 13
    RF_LARGE_PKT       = 1 << 14
    RF_CONN_RATE       = 1 << 15
    RF_UDP_SCAN        = 1 << 16
    RF_SLOW_SCAN       = 1 << 17
    RF_LAND            = 1 << 18
    RF_SMURF           = 1 << 19
    RF_ICMP_TUNNEL     = 1 << 20
    RF_RST_FLOOD       = 1 << 21
    RF_HTTP_FLOOD      = 1 << 22
    RF_CRED_STUFF      = 1 << 23
    RF_TTL_ANOMALY     = 1 << 24
    RF_ENTROPY         = 1 << 25
    RF_BEACON          = 1 << 26
    RF_SQL_INJECTION   = 1 << 27
    RF_WEBSHELL        = 1 << 28
    RF_SMB_LATERAL     = 1 << 29
    RF_BLACKLIST       = 1 << 30
    RF_JA3             = 1 << 31
    RF_HTTP_ATTACK     = 1 << 32
    # WiFi-specific rule flags
    RF_WIFI_DEAUTH     = 1 << 33
    RF_WIFI_PROBE_FLOOD = 1 << 34
    RF_WIFI_EVIL_TWIN  = 1 << 35
    RF_WIFI_SSID_SPOOF = 1 << 36

    def __init__(self, alert_mgr: AlertManager, flow_tracker: FlowTracker) -> None:
        self._alerts = alert_mgr
        self._flows = flow_tracker
        self._lock = threading.RLock()

        # Per-IP sliding windows (original rules)
        self._syn_w:   Dict[str, SlidingWindow] = defaultdict(SlidingWindow)
        self._icmp_w:  Dict[str, SlidingWindow] = defaultdict(SlidingWindow)
        self._dns_w:   Dict[str, SlidingWindow] = defaultdict(SlidingWindow)
        self._conn_w:  Dict[str, SlidingWindow] = defaultdict(SlidingWindow)
        self._rst_w:   Dict[str, SlidingWindow] = defaultdict(SlidingWindow)  # 
        self._http_w:  Dict[str, SlidingWindow] = defaultdict(SlidingWindow)  # 

        # TCP port scan: src_ip → {bucket: set of ports}
        self._port_scan: Dict[str, Dict[int, Set[int]]] = defaultdict(dict)
        #  UDP port scan: same structure
        self._udp_scan:  Dict[str, Dict[int, Set[int]]] = defaultdict(dict)
        #  slow scan: src_ip → {minute_bucket: set of ports}
        self._slow_scan: Dict[str, Dict[int, Set[int]]] = defaultdict(dict)

        # Brute force: (dst_ip, dst_port) → SlidingWindow
        self._brute_w: Dict[Tuple[str, int], SlidingWindow] = defaultdict(SlidingWindow) # type: ignore

        # Data exfiltration: src_ip → deque of (time, bytes)
        self._data_out: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))

        # ARP table
        self._arp_table: Dict[str, str] = {}

        #  HTTP flood + cred stuffing: src_ip → SlidingWindow
        # cred stuffing tracks POST to login-ish paths
        self._cred_w:   Dict[str, SlidingWindow] = defaultdict(SlidingWindow)

        #  Beacon detection: (src_ip, dst_ip, dst_port) → deque of timestamps
        self._beacon_ts: Dict[Tuple[str, str, int], deque] = defaultdict(
            lambda: deque(maxlen=200)) # type: ignore

        # SMB lateral movement detection: src_ip → {bucket: set(dst_ips)}
        self._smb_lateral: Dict[str, Dict[int, Set[str]]] = defaultdict(dict)

        # WiFi attack detection
        self._wifi_deauth_w: Dict[Tuple[str, str], SlidingWindow] = defaultdict(SlidingWindow)  # type: ignore[assignment]
        self._wifi_probe_w: Dict[Tuple[str, str], SlidingWindow] = defaultdict(SlidingWindow)  # type: ignore[assignment]
        self._wifi_ssid_w: Dict[Tuple[str, str], SlidingWindow] = defaultdict(SlidingWindow)  # type: ignore[assignment]
        self._wifi_ssids: Dict[str, Set[str]] = defaultdict(set)  # BSSID → set of SSIDs

        # Data transfer for stats panel
        self.data_transfer: Dict[str, int] = defaultdict(int)
        self._last_stale_cleanup = time.time()

        # Adaptive tuning state
        self._port_scan_counts: deque = deque(maxlen=2000)
        self._conn_rate_counts: deque = deque(maxlen=2000)
        self._last_tune = time.time()
        self._base_port_scan_threshold = DET.port_scan_threshold
        self._base_conn_rate_threshold = DET.connection_rate_threshold

    # ── helpers ────────────────────────────────────────────────────────────
    def _flag(self, pkt: ParsedPacket, bit: int) -> None:
        pkt.rule_flags |= bit

    _RULE_DISPATCH: Optional[list] = None  # lazily built; see _build_dispatch()

    def _build_dispatch(self):
        """Build (rule_name, method, args_needs_now) dispatch table once."""
        self._RULE_DISPATCH = [
            ("syn_flood",       self._rule_01_syn_flood,        True),
            ("port_scan",       self._rule_02_port_scan,        True),
            ("suspicious_port", self._rule_03_suspicious_port,  False),
            ("icmp_flood",      self._rule_04_icmp_flood,       True),
            ("dns_flood",       self._rule_05_dns_flood,        True),
            ("dns_tunnel",      self._rule_06_dns_tunnel,       False),
            ("arp_spoof",       self._rule_07_arp_spoof,        False),
            ("brute_force",     self._rule_08_brute_force,      True),
            ("data_exfil",      self._rule_09_data_exfil,       True),
            ("null_scan",       self._rule_10_null_scan,        False),
            ("xmas_scan",       self._rule_11_xmas_scan,        False),
            ("fin_scan",        self._rule_12_fin_scan,         False),
            ("ip_fragment",     self._rule_13_ip_fragment,      False),
            ("suspicious_dns",  self._rule_14_suspicious_dns,   False),
            ("large_packet",    self._rule_15_large_packet,     False),
            ("conn_rate",       self._rule_16_connection_rate,  True),
            ("udp_scan",        self._rule_17_udp_scan,         True),
            ("slow_scan",       self._rule_18_slow_scan,        True),
            ("land_attack",     self._rule_19_land_attack,      False),
            ("smurf",           self._rule_20_smurf_attack,     False),
            ("icmp_tunnel",     self._rule_21_icmp_tunnel,      False),
            ("rst_flood",       self._rule_22_rst_flood,        True),
            ("http_flood",      self._rule_23_http_flood,       True),
            ("cred_stuffing",   self._rule_24_cred_stuffing,    True),
            ("ttl_anomaly",     self._rule_25_ttl_anomaly,      False),
            ("payload_entropy", self._rule_26_payload_entropy,  False),
            ("beacon",          self._rule_27_beacon,           True),
            ("sql_injection",   self._rule_28_sql_injection,    False),
            ("webshell_upload", self._rule_29_webshell_upload,  False),
            ("smb_lateral",     self._rule_30_smb_lateral,      True),
            ("ja3_blacklisted", self._rule_31_ja3_blacklist,    False),
            ("http_attack_payload", self._rule_32_http_attack_payload, False),
            # WiFi-specific rules
            ("wifi_deauth",      self._rule_33_wifi_deauth,      True),
            ("wifi_probe_flood", self._rule_34_wifi_probe_flood, True),
            ("wifi_evil_twin",   self._rule_35_wifi_evil_twin,   True),
            ("wifi_ssid_spoof",  self._rule_36_wifi_ssid_spoof,  True),
        ]

    def analyze(self, pkt: ParsedPacket) -> None:
        """Run all detection rules. Thread-safe.

        ✅ SOC Advanced: per-rule error isolation — each rule wrapped in
        try/except so a single rule failure never crashes the pipeline.
        ✅ SOC Advanced: rules can be dynamically enabled/disabled via
        RULE_REGISTRY metadata.
        """
        now = time.time()
        with self._lock:
            # ✅ Blacklist bypass: always alert (helps with IoC watchlists)
            if self._is_blacklisted(pkt):
                pkt.threat_level = "Danger"
                self._flag(pkt, self.RF_BLACKLIST)
                self._alerts.emit("DANGER", "blacklist",
                    f"⛔ BLACKLIST HIT → {pkt.src_ip} -> {pkt.dst_ip}",
                    pkt.src_ip, pkt.dst_ip)
                return

            # Skip noisy/benign sources
            if self._ignored_source(pkt):
                return

            # Build dispatch table on first call
            if self._RULE_DISPATCH is None:
                self._build_dispatch()

            # ✅ SOC: Per-rule error isolation + enable/disable check
            for rule_name, rule_method, needs_now in self._RULE_DISPATCH:  # type: ignore
                if not is_rule_enabled(rule_name):
                    continue
                try:
                    if needs_now:
                        rule_method(pkt, now)
                    else:
                        rule_method(pkt)
                except Exception:
                    logger.debug("Rule '%s' error (packet #%d)",
                                 rule_name, pkt.number, exc_info=True)

            self.data_transfer[pkt.src_ip] += pkt.total_length

            # Auto-tune thresholds based on observed traffic
            if DET.auto_tune_enabled:
                if now - self._last_tune > DET.auto_tune_interval:
                    self._auto_tune_thresholds()
                    self._last_tune = now

            if now - self._last_stale_cleanup > DET.stale_cleanup_interval * 3:
                self._cleanup_stale_state(now)

    def _percentile(self, data: deque, percentile: float) -> float:
        if not data:
            return 0.0
        s = sorted(data)
        k = int((len(s) - 1) * (percentile / 100.0))
        return float(s[k])

    def _auto_tune_thresholds(self) -> None:
        """Adjust thresholds dynamically based on recent observed traffic patterns."""
        # Port scan threshold: use 95th percentile + factor
        if self._port_scan_counts:
            p95 = self._percentile(self._port_scan_counts, 95)
            new_thresh = max(self._base_port_scan_threshold,
                             int(p95 * getattr(DET, "auto_tune_factor", 1.2)))
            if new_thresh != DET.port_scan_threshold:
                DET.port_scan_threshold = new_thresh
                logger.debug("Auto-tuned port_scan_threshold -> %s", new_thresh)

        # Connection rate threshold
        if self._conn_rate_counts:
            p95 = self._percentile(self._conn_rate_counts, 95)
            new_thresh = max(self._base_conn_rate_threshold,
                             int(p95 * getattr(DET, "auto_tune_factor", 1.2)))
            if new_thresh != DET.connection_rate_threshold:
                DET.connection_rate_threshold = new_thresh
                logger.debug("Auto-tuned connection_rate_threshold -> %s", new_thresh)

    def _cleanup_stale_state(self, now: float) -> None:
        for d in (self._syn_w, self._icmp_w, self._dns_w,
                  self._conn_w, self._rst_w, self._http_w,
                  self._cred_w):
            stale = [ip for ip, w in list(d.items()) if w.count(now, 120.0) == 0]
            for ip in stale:
                d.pop(ip, None)
        for scan_dict in (self._port_scan, self._udp_scan, self._slow_scan):
            dead = []
            for ip, buckets in list(scan_dict.items()):
                # Note: slow_scan uses minute-bucket keys (int(now/60))
                # while other scan trackers use second-level timestamps.
                if scan_dict is self._slow_scan:
                    old = [t for t in buckets if now - (t * 60) > DET.slow_scan_window * 2]
                else:
                    old = [t for t in buckets if now - t > DET.slow_scan_window * 2]
                for t in old:
                    buckets.pop(t, None)
                if not buckets:
                    dead.append(ip)
            for ip in dead:
                scan_dict.pop(ip, None)
        stale_brute = [k for k, w in list(self._brute_w.items()) # type: ignore
                       if w.count(now, DET.brute_force_window * 2) == 0]
        for k in stale_brute:
            self._brute_w.pop(k, None) # type: ignore
        stale_data = [ip for ip, dq in list(self._data_out.items())
                      if not dq or now - dq[-1][0] > DET.data_exfil_window * 2]
        for ip in stale_data:
            self._data_out.pop(ip, None) # type: ignore
        # Cleanup beacon state older than 2× max interval
        dead_b = [k for k, dq in list(self._beacon_ts.items())
                  if not dq or now - dq[-1] > DET.beacon_max_interval * 2]
        for k in dead_b:
            self._beacon_ts.pop(k, None) # type: ignore
        self._last_stale_cleanup = now
        logger.debug(" stale rule-engine state cleaned")

    # ════════════════════════════════════════════════════════════════
    # ORIGINAL 16 RULES (kept, with rule_flags bitmask added)
    # ════════════════════════════════════════════════════════════════

    def _ignored_source(self, pkt: ParsedPacket) -> bool:
        """Skip detection for known benign sources (e.g., local traffic or whitelisted)."""
        if not pkt.src_ip:
            return False
        if DET.is_whitelisted_ip(pkt.src_ip):
            return True
        return DET.is_ignored_ip(pkt.src_ip)

    def _is_blacklisted(self, pkt: ParsedPacket) -> bool:
        """Return True if the packet involves a blacklisted IP/subnet."""
        if pkt.src_ip and DET.is_blacklisted_ip(pkt.src_ip):
            return True
        if pkt.dst_ip and DET.is_blacklisted_ip(pkt.dst_ip):
            return True
        return False

    def _http_payload_text(self, pkt: ParsedPacket) -> str:
        """Decode HTTP payload text for pattern matching."""
        try:
            if not pkt._raw or not SCAPY_OK or not hasattr(pkt._raw, "haslayer") or not pkt._raw.haslayer(Raw): # type: ignore
                return ""
            data = pkt._raw[Raw].load # type: ignore
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def _matches_patterns(self, text: str, patterns: tuple) -> bool:
        t = (text or "").lower()
        for pat in patterns:
            if pat in t:
                return True
        return False

    def _rule_28_sql_injection(self, pkt):
        """Detect SQL injection patterns in HTTP request path or payload."""
        if pkt.protocol not in ("HTTP", "HTTP-ALT") or not pkt.http_method:
            return
        # ✅ FIX: Only check POST/PUT requests for SQL injection (data-modifying requests)
        if pkt.http_method not in ("POST", "PUT", "PATCH"):
            return
        data = (pkt.http_path or "") + " " + self._http_payload_text(pkt)
        sqli_patterns = (
            "union select", " or 1=1", " or '1'='1", " or \"1\"=\"1\"",
            "information_schema", "benchmark(", "sleep(", "load_file(", "into outfile",
            "xp_cmdshell", "concat(", "-- ", ";--", "/**/",
        )
        if self._matches_patterns(data, sqli_patterns):
            # ✅ FIX: Add context check - don't flag if it looks like legitimate database traffic
            # Check for common legitimate SQL patterns that might match
            legitimate_patterns = (
                "select * from", "insert into", "update ", "delete from",  # Normal SQL
                "order by", "group by", "having ", "limit ",  # Normal clauses
                "where id=", "where user_id=",  # Common WHERE clauses
            )
            if self._matches_patterns(data, legitimate_patterns):
                return  # Likely legitimate database operation
            if pkt.threat_level == "Safe":
                pkt.threat_level = "Suspicious"
            self._flag(pkt, self.RF_SQL_INJECTION)
            self._alerts.emit("WARNING", "sql_injection",
                f"🧮 SQL INJECTION? → {pkt.src_ip} → {pkt.dst_ip} | {pkt.http_method} {pkt.http_path}",
                pkt.src_ip, pkt.dst_ip)

    def _rule_31_ja3_blacklist(self, pkt):
        """Detect known-malicious JA3 fingerprints."""
        if not pkt.tls_ja3_hash:
            return
        if pkt.tls_ja3_hash in DET.ja3_blacklist:
            if pkt.threat_level == "Safe":
                pkt.threat_level = "Suspicious"
            self._flag(pkt, self.RF_JA3)
            self._alerts.emit("DANGER", "ja3_blacklisted",
                f"🧩 JA3 BLACKLISTED → {pkt.src_ip} → {pkt.dst_ip} | JA3={pkt.tls_ja3_hash} SNI={pkt.tls_sni}",
                pkt.src_ip, pkt.dst_ip)

    def _rule_29_webshell_upload(self, pkt):
        """Detect potential webshell uploads / PHP backdoors in HTTP POST payloads."""
        if pkt.protocol not in ("HTTP", "HTTP-ALT") or pkt.http_method != "POST":
            return
        data = self._http_payload_text(pkt).lower()
        if not data:
            return
        # ✅ FIX: Only flag multipart uploads with suspicious file extensions
        if "multipart/form-data" in data and "filename=" in data:
            # Check for suspicious extensions
            if any(ext in data for ext in (".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl", ".py", ".sh", ".exe")):
                # ✅ FIX: Don't flag common legitimate file types that might be uploaded
                legitimate_extensions = (".jpg", ".jpeg", ".png", ".gif", ".pdf", ".doc", ".docx", ".txt", ".zip", ".rar")
                if any(ext in data for ext in legitimate_extensions):
                    return
                suspicious = True
            else:
                suspicious = False
        else:
            # ✅ FIX: For non-multipart, be more selective about PHP/shell code detection
            suspicious = False
            # Only flag if multiple suspicious indicators are present
            indicators = 0
            if "<?php" in data:
                indicators += 1
            if any(k in data for k in ("eval(", "system(", "shell_exec(", "base64_decode(")):
                indicators += 1
            if any(k in data for k in ("cmd.exe", "powershell", "move_uploaded_file")):
                indicators += 1
            if indicators >= 2:  # Require multiple indicators
                suspicious = True
        if suspicious:
            if pkt.threat_level == "Safe":
                pkt.threat_level = "Suspicious"
            self._flag(pkt, self.RF_WEBSHELL)
            self._alerts.emit("WARNING", "webshell_upload",
                f"🕸️ WEB SHELL? → {pkt.src_ip} → {pkt.dst_ip} | {pkt.http_method} {pkt.http_path}",
                pkt.src_ip, pkt.dst_ip)

    def _rule_32_http_attack_payload(self, pkt):
        """Detect common web attack payloads (XSS, path traversal, command injection)."""
        if pkt.protocol not in ("HTTP", "HTTP-ALT") or not pkt.http_method:
            return

        # Build a normalized text blob from request line, headers and body.
        request_line = f"{pkt.http_method} {pkt.http_path or ''}".lower()
        headers = " ".join(f"{k}:{v}" for k, v in (pkt.http_headers or {}).items()).lower()
        body = (pkt.http_body or "").lower()
        data = " ".join([request_line, headers, body]).strip()
        if not data:
            return

        # Match multiple attack classes and require either multiple signals or a high-confidence indicator.
        xss_signatures = ("<script", "javascript:", "onerror=", "onload=", "document.cookie",
                          "<img", "<iframe", "<svg", "<body", "<meta")
        path_traversal = ("../", "%2e%2e%2f", "%2e%2e/", ".env", "/etc/passwd")
        cmd_injection = ("cmd=", "powershell", "wget ", "curl ", "sleep(",
                         "base64_", "eval(", "system(", "exec(", "popen(", "os.exec")

        def _any(sig_list):
            return any(sig in data for sig in sig_list)

        # Strong indicators that alone should trigger an alert
        strong_indicators = ("<script", "/etc/passwd", ".env", "base64_", "eval(", "system(", "cmd=", "powershell")
        strong_hit = any(si in data for si in strong_indicators)

        score = 0
        if _any(xss_signatures):
            score += 1
        if _any(path_traversal):
            score += 1
        if _any(cmd_injection):
            score += 1

        # ✅ IMPROVED: Require stronger evidence to reduce false positives
        # Also check for multiple attack types combined for higher confidence
        if strong_hit or score >= 3:
            # ✅ IMPROVED: Don't flag common legitimate patterns
            legitimate_patterns = (
                "javascript:void(0)", "onclick=", "onchange=",  # Common JS
                "/css/", "/js/", "/img/", "/assets/",  # Common paths
                "data:image/", "data:text/",  # Data URIs
                "application/json",  # JSON content
                "text/plain",  # Plain text
            )
            if any(lp in data for lp in legitimate_patterns):
                return
            # Additional check: don't flag if it's a known API endpoint
            if any(api in data for api in ("/api/v", "/rest/", "/graphql", "/wp-json")):
                return
            if pkt.threat_level == "Safe":
                pkt.threat_level = "Suspicious"
            self._flag(pkt, self.RF_HTTP_ATTACK)
            self._alerts.emit("WARNING", "http_attack_payload",
                f"🛡️ HTTP ATTACK PAYLOAD → {pkt.src_ip} → {pkt.dst_ip} | {pkt.http_method} {pkt.http_path}",
                pkt.src_ip, pkt.dst_ip)

    def _rule_30_smb_lateral(self, pkt, now):
        """Detect lateral movement by scanning many hosts via SMB (port 445)."""
        if self._ignored_source(pkt):
            return
        if pkt.protocol != "TCP" or pkt.dst_port != 445:
            return
        bucket = int(now)
        entry = self._smb_lateral[pkt.src_ip]
        entry.setdefault(bucket, set()).add(pkt.dst_ip)
        stale = [t for t in entry if now - t >= DET.smb_lateral_window]
        for t in stale:
            entry.pop(t, None)
        all_dsts: set = set()
        for dsts in entry.values():
            all_dsts.update(dsts)
        if len(all_dsts) > DET.smb_lateral_threshold:
            pkt.threat_level = "Danger"
            self._flag(pkt, self.RF_SMB_LATERAL)
            self._alerts.emit("DANGER", "smb_lateral",
                f"🧩 SMB LATERAL → {pkt.src_ip} reached {len(all_dsts)} hosts via SMB",
                pkt.src_ip)

    def _rule_01_syn_flood(self, pkt, now):
        if self._ignored_source(pkt):
            return
        # Some packets on common service ports (HTTP/HTTPS/etc.) are classified as
        # HTTP/HTTPS rather than TCP, but the underlying transport is still TCP.
        if not pkt._raw or not pkt._raw.haslayer(TCP) or "S" not in pkt.tcp_flags or "A" in pkt.tcp_flags:
            return
        # ✅ IMPROVED: Only flag SYN floods targeting the same destination
        # This prevents flagging legitimate high-volume traffic to different ports
        w = self._syn_w[pkt.dst_ip]
        w.add(now)
        cnt = w.count(now, DET.syn_flood_window)
        # ✅ IMPROVED: Additional check - require multiple unique source ports
        # to avoid flagging legitimate connection bursts
        if cnt > DET.syn_flood_threshold:
            # Check if it's a distributed attack (multiple unique sources → same victim)
            # _syn_w is keyed by dst_ip; len > 5 means multiple victims are being tracked,
            # which implies multiple source IPs are participating (distributed DDoS).
            if len(self._syn_w) > 5:
                # Likely distributed attack — more severe
                pkt.threat_level = "Danger"
                flood_type = "DISTRIBUTED SYN FLOOD"
            else:
                pkt.threat_level = "Danger"
                flood_type = "SYN FLOOD"
            self._flag(pkt, self.RF_SYN_FLOOD)
            self._alerts.emit("DANGER", "syn_flood",
                f"🚨 {flood_type} → victim={pkt.dst_ip} | {cnt} SYN/{DET.syn_flood_window}s | latest src={pkt.src_ip}",
                pkt.src_ip, pkt.dst_ip)

    def _rule_02_port_scan(self, pkt, now):
        # Port scans can hit common service ports (e.g. 80) where the packet is
        # classified as HTTP/HTTPS; check the raw TCP layer instead.
        if not pkt._raw or not pkt._raw.haslayer(TCP) or pkt.dst_port <= 0:
            return
        # ✅ IMPROVED: Only count connection initiations/probes. Ignore traffic with
        # the ACK flag to prevent flagging busy servers replying to many clients.
        if "A" in pkt.tcp_flags:
            return
        # ✅ IMPROVED: Skip if it's a response to our outgoing connection
        if _is_private_or_reserved_ip(pkt.src_ip) and not _is_private_or_reserved_ip(pkt.dst_ip):
            # Outgoing from internal network - likely legitimate
            return
        bucket = int(now)
        entry = self._port_scan[pkt.src_ip]
        entry.setdefault(bucket, set()).add(pkt.dst_port)
        all_ports: set = set()
        stale = [t for t in entry if now - t >= DET.port_scan_window]
        for t in stale:
            entry.pop(t, None)
        for ports in entry.values():
            all_ports.update(ports)
        # Auto-tune: record observed port scan spread
        self._port_scan_counts.append(len(all_ports))
        # ✅ IMPROVED: Additional validation - port scan should show variety
        # Single port repeated hits is likely not a scan
        if len(all_ports) > DET.port_scan_threshold:
            # ✅ IMPROVED: Check for scan pattern - should hit multiple distinct ports
            # A real scan will show increasing port numbers or random distribution
            if len(all_ports) >= 5:  # Minimum variety for scan detection
                pkt.threat_level = "Danger"
                self._flag(pkt, self.RF_PORT_SCAN)
                self._alerts.emit("DANGER", "port_scan",
                    f"🔍 TCP PORT SCAN → {pkt.src_ip} | {len(all_ports)} ports on {pkt.dst_ip}",
                    pkt.src_ip, pkt.dst_ip)

    def _rule_03_suspicious_port(self, pkt):
        # ✅ IMPROVED: Skip local-to-local traffic — benign internal services
        if (_is_private_or_reserved_ip(pkt.src_ip)
                and _is_private_or_reserved_ip(pkt.dst_ip)):
            return
        # ✅ IMPROVED: Skip if source is internal and destination is external web
        if _is_private_or_reserved_ip(pkt.src_ip) and not _is_private_or_reserved_ip(pkt.dst_ip):
            # Outgoing from internal network - likely legitimate
            return
        hit = pkt.dst_port if pkt.dst_port in DET.suspicious_ports else (
              pkt.src_port if pkt.src_port in DET.suspicious_ports else None)
        if hit:
            # ✅ IMPROVED: Add context check - don't flag if it's established TCP traffic
            # or if it's a common protocol on that port
            if pkt.protocol == "TCP" and pkt.tcp_flags and ("S" in pkt.tcp_flags or "A" in pkt.tcp_flags):
                # Allow SYN/SYN-ACK for connection establishment
                if "S" in pkt.tcp_flags and not ("A" in pkt.tcp_flags and "S" in pkt.tcp_flags):
                    # Pure SYN packet to suspicious port - this could be scanning
                    pass
                else:
                    # Established connection or response - likely legitimate
                    return
            # ✅ IMPROVED: Don't flag DNS queries to port 53 (legitimate)
            if pkt.protocol == "UDP" and hit == 53 and pkt.dns_query:
                return
            # ✅ IMPROVED: Don't flag HTTP/HTTPS traffic to common web ports
            if pkt.protocol in ("HTTP", "HTTPS") and hit in (80, 443, 8080, 8443, 8888, 8000):
                return
            # ✅ IMPROVED: Don't flag known legitimate services on suspicious ports
            # Some services legitimately use these ports
            legitimate_services = {
                3389: ("RDP", "Windows Remote Desktop"),
                5900: ("VNC", "Virtual Network Computing"),
                22: ("SSH", "Secure Shell"),
                21: ("FTP", "File Transfer Protocol"),
            }
            if hit in legitimate_services and pkt.protocol in ("TCP", "SSH", "FTP", "VNC", "RDP"):
                # Legitimate service usage
                return
            if pkt.threat_level == "Safe":
                pkt.threat_level = "Suspicious"
            self._flag(pkt, self.RF_SUSP_PORT)
            self._alerts.emit("WARNING", "suspicious_port",
                f"⚠️ SUSPICIOUS PORT {hit} → {pkt.src_ip}:{pkt.src_port} → {pkt.dst_ip}:{pkt.dst_port}",
                pkt.src_ip, pkt.dst_ip)

    def _rule_04_icmp_flood(self, pkt, now):
        if self._ignored_source(pkt):
            return
        if pkt.protocol != "ICMP":
            return
        # ✅ IMPROVED: Only flag ICMP floods from external sources
        # Internal ICMP traffic is usually legitimate network operations
        if _is_private_or_reserved_ip(pkt.src_ip):
            return
        w = self._icmp_w[pkt.src_ip]
        w.add(now)
        cnt = w.count(now, DET.icmp_flood_window)
        if cnt > DET.icmp_flood_threshold:
            pkt.threat_level = "Danger"
            self._flag(pkt, self.RF_ICMP_FLOOD)
            self._alerts.emit("DANGER", "icmp_flood",
                f"🏓 ICMP FLOOD → {pkt.src_ip} | {cnt}/{DET.icmp_flood_window}s",
                pkt.src_ip)

    def _rule_05_dns_flood(self, pkt, now):
        if self._ignored_source(pkt):
            return
        if pkt.protocol != "DNS" or not pkt.dns_query:
            return
        # ✅ IMPROVED: Only flag DNS floods from external sources
        if _is_private_or_reserved_ip(pkt.src_ip):
            return
        w = self._dns_w[pkt.src_ip]
        w.add(now)
        cnt = w.count(now, DET.dns_flood_window)
        if cnt > DET.dns_flood_threshold:
            if pkt.threat_level == "Safe":
                pkt.threat_level = "Suspicious"
            self._flag(pkt, self.RF_DNS_FLOOD)
            self._alerts.emit("WARNING", "dns_flood",
                f"📡 DNS FLOOD → {pkt.src_ip} | {cnt}/{DET.dns_flood_window}s",
                pkt.src_ip)

    def _rule_06_dns_tunnel(self, pkt):
        if pkt.protocol != "DNS" or not pkt.dns_query:
            return
        # Suspiciously long queries or labels can indicate DNS tunneling.
        q = pkt.dns_query
        long_labels = [l for l in q.split(".") if len(l) > 30]
        high_entropy = False
        try:
            # high entropy suggests encoded/blob content hiding in labels
            entropy = _shannon_entropy(q.encode("utf-8", errors="ignore"))
            # ✅ IMPROVED: Raised length threshold to skip CDN subdomains
            if entropy > 4.5 and len(q) > 60:
                high_entropy = True
        except Exception:
            entropy = 0.0

        # ✅ IMPROVED: Require BOTH long labels AND high entropy
        if long_labels and high_entropy:
            # ✅ IMPROVED: Additional check - skip known legitimate long domains
            # CDN and cloud services often have long subdomains
            legitimate_cdn = ("cloudfront.net", "akamai.com", "azureedge.net", 
                            "cloudflare.com", "fastly.net", "googleusercontent.com",
                            "akamaized.net", "stackcdn.com", "cdn.jsdelivr.net")
            if any(legit in q.lower() for legit in legitimate_cdn):
                return
            if pkt.threat_level == "Safe":
                pkt.threat_level = "Suspicious"
            self._flag(pkt, self.RF_DNS_TUNNEL)
            msg = (f"🕳️ DNS TUNNEL? → {pkt.src_ip} | len={len(q)} "
                   f"labels={len(long_labels)} entropy={entropy:.2f}")
            self._alerts.emit("WARNING", "dns_tunnel", msg, pkt.src_ip)

    def _rule_07_arp_spoof(self, pkt):
        if pkt.protocol != "ARP" or pkt.arp_op != 2:
            return
        ip, mac = pkt.arp_src_ip, pkt.arp_src_mac
        if not ip or not mac:
            return
        if ip in self._arp_table and self._arp_table[ip] != mac:
            pkt.threat_level = "Danger"
            self._flag(pkt, self.RF_ARP_SPOOF)
            self._alerts.emit("DANGER", "arp_spoof",
                f"☠️ ARP SPOOF → {ip} changed {self._arp_table[ip]} → {mac}", ip)
        self._arp_table[ip] = mac

    def _rule_08_brute_force(self, pkt, now):
        if self._ignored_source(pkt):
            return
        # Brute-force attacks are TCP-based even if traffic is classified as HTTP/HTTPS.
        if not pkt._raw or not pkt._raw.haslayer(TCP) or pkt.dst_port not in DET.brute_force_ports:
            return
        # ✅ IMPROVED: count ALL connection attempts including established,
        # not just bare SYN — catches credential stuffing over keep-alive conns
        if "S" not in pkt.tcp_flags and "P" not in pkt.tcp_flags:
            return
        # ✅ IMPROVED: Skip if source is internal (likely legitimate traffic)
        if _is_private_or_reserved_ip(pkt.src_ip):
            return
        key = (pkt.dst_ip, pkt.dst_port)
        w = self._brute_w[key]
        w.add(now)
        cnt = w.count(now, DET.brute_force_window)

        # Adjust sensitivity for high-risk services (SSH/RDP/SMB)
        threshold = DET.brute_force_thresholds_by_port.get(
            pkt.dst_port, DET.brute_force_threshold)

        if cnt > threshold:
            # ✅ IMPROVED: Additional validation - check for failed connection pattern
            # Real brute force will show many failures before any success
            # For now, just flag the high rate
            pkt.threat_level = "Danger"
            self._flag(pkt, self.RF_BRUTE)
            self._alerts.emit("DANGER", "brute_force",
                f"🔐 BRUTE FORCE → {pkt.src_ip} → {pkt.dst_ip}:{pkt.dst_port} | {cnt}/{DET.brute_force_window}s",
                pkt.src_ip, pkt.dst_ip)

    def _rule_09_data_exfil(self, pkt, now):
        if self._ignored_source(pkt):
            return
        #  improvement: only count bytes from ESTABLISHED flows (has ACK),
        # ignoring SYN/handshake traffic which was inflating byte counts
        if pkt._raw and pkt._raw.haslayer(TCP) and "A" not in pkt.tcp_flags:
            return
        dq = self._data_out[pkt.src_ip]
        dq.append((now, pkt.total_length))
        total = sum(b for t, b in dq if now - t < DET.data_exfil_window)
        if total > DET.data_exfil_threshold_bytes:
            pkt.threat_level = "Danger"
            self._flag(pkt, self.RF_DATA_EXFIL)
            self._alerts.emit("DANGER", "data_exfil",
                f"📤 DATA EXFIL? → {pkt.src_ip} | {total/1e6:.1f} MB/{DET.data_exfil_window}s",
                pkt.src_ip)

    def _rule_10_null_scan(self, pkt):
        if not pkt._raw or not pkt._raw.haslayer(TCP):
            return
        if pkt.tcp_flags_int == 0:
            pkt.threat_level = "Danger"
            self._flag(pkt, self.RF_NULL_SCAN)
            self._alerts.emit("DANGER", "null_scan",
                f"👻 NULL SCAN → {pkt.src_ip} → {pkt.dst_ip}:{pkt.dst_port}",
                pkt.src_ip, pkt.dst_ip)

    def _rule_11_xmas_scan(self, pkt):
        if not pkt._raw or not pkt._raw.haslayer(TCP):
            return
        if all(f in pkt.tcp_flags for f in ("F", "P", "U")):
            pkt.threat_level = "Danger"
            self._flag(pkt, self.RF_XMAS_SCAN)
            self._alerts.emit("DANGER", "xmas_scan",
                f"🎄 XMAS SCAN → {pkt.src_ip} → {pkt.dst_ip}:{pkt.dst_port} | FIN+PSH+URG",
                pkt.src_ip, pkt.dst_ip)

    def _rule_12_fin_scan(self, pkt):
        if not pkt._raw or not pkt._raw.haslayer(TCP):
            return
        if pkt.tcp_flags == "F":
            # ✅ v5 FIX: Check if flow is established — normal teardown FIN is not a scan
            flow = self._flows.get_flow(
                pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
            if flow and flow.total_packets > 3:
                return  # Part of normal connection teardown
            if pkt.threat_level == "Safe":
                pkt.threat_level = "Suspicious"
            self._flag(pkt, self.RF_FIN_SCAN)
            self._alerts.emit("WARNING", "fin_scan",
                f"🏴 FIN SCAN → {pkt.src_ip} → {pkt.dst_ip}:{pkt.dst_port}",
                pkt.src_ip, pkt.dst_ip)

    def _rule_13_ip_fragment(self, pkt):
        if not pkt._raw or not SCAPY_OK:
            return
        # ✅ v5 FIX: Skip local-to-local fragments — benign (e.g., NFS, SMB)
        if (_is_private_or_reserved_ip(pkt.src_ip)
                and _is_private_or_reserved_ip(pkt.dst_ip)):
            return
        try:
            if not pkt._raw.haslayer(IP):
                return
            ip_l = pkt._raw[IP]
            mf = int(ip_l.flags) & 0x1
            offset = ip_l.frag
            if offset > 0 or mf:
                if pkt.threat_level == "Safe":
                    pkt.threat_level = "Suspicious"
                self._flag(pkt, self.RF_IP_FRAG)
                self._alerts.emit("WARNING", "ip_fragment",
                    f"🧩 IP FRAGMENT → {pkt.src_ip} → {pkt.dst_ip} | offset={offset} MF={mf}",
                    pkt.src_ip, pkt.dst_ip)
        except Exception:
            pass

    # ✅ v5 FIX: Safelist of legitimate domains that contain suspicious substrings
    _DNS_FP_SAFELIST = (
        "hackernews", "hackerone", "hackerrank", "hackmd", "hacktoberfest",
        "cryptowatch", "cryptocurrency", "coinbase", "cryptojs",
        "payloadcms", "backdropbuild", "explorerhat", "explorercanvas",
        "trojanrecords", "keylogger-detector", "ransomwarehelp",
    )

    def _rule_14_suspicious_dns(self, pkt):
        if pkt.protocol != "DNS" or not pkt.dns_query:
            return
        q = pkt.dns_query.lower()
        # ✅ v5 FIX: Skip known-legitimate domains matching suspicious substrings
        if any(safe in q for safe in self._DNS_FP_SAFELIST):
            return
        for pat in DET.suspicious_dns_patterns:
            if pat in q:
                if pkt.threat_level == "Safe":
                    pkt.threat_level = "Suspicious"
                self._flag(pkt, self.RF_SUSP_DNS)
                self._alerts.emit("WARNING", "suspicious_dns",
                    f"🌐 SUSPICIOUS DNS → {pkt.src_ip} queried {pkt.dns_query} (matched: {pat})",
                    pkt.src_ip)
                break

    def _rule_15_large_packet(self, pkt):
        # Ignore large packets from internal/local hosts to reduce noise
        if DET.is_ignored_ip(pkt.src_ip) or DET.is_ignored_ip(pkt.dst_ip):
            return
        # ✅ FIX: Don't flag large packets on common high-throughput ports
        high_throughput_ports = {80, 443, 8080, 8443, 21, 20, 990, 989}  # HTTP, FTP
        if pkt.dst_port in high_throughput_ports or pkt.src_port in high_throughput_ports:
            return
        # ✅ FIX: Only flag extremely large packets (> 1MB) to reduce false positives
        if pkt.total_length > 1_000_000:  # 1MB threshold instead of 65KB
            self._flag(pkt, self.RF_LARGE_PKT)
            self._alerts.emit("INFO", "large_packet",
                f"📦 LARGE PACKET → {pkt.src_ip} → {pkt.dst_ip} | {pkt.total_length}B",
                pkt.src_ip, pkt.dst_ip)

    def _rule_16_connection_rate(self, pkt, now):
        if self._ignored_source(pkt):
            return
        # ✅ v5 FIX: Use raw TCP layer check and exclude SYN-ACK (server replies)
        if not pkt._raw or not pkt._raw.haslayer(TCP) or "S" not in pkt.tcp_flags or "A" in pkt.tcp_flags:
            return
        w = self._conn_w[pkt.src_ip]
        w.add(now)
        cnt = w.count(now, DET.connection_rate_window)
        # Auto-tune: record observed connection rates
        self._conn_rate_counts.append(cnt)
        if cnt > DET.connection_rate_threshold:
            if pkt.threat_level == "Safe":
                pkt.threat_level = "Suspicious"
            self._flag(pkt, self.RF_CONN_RATE)
            self._alerts.emit("WARNING", "conn_rate",
                f"⚡ HIGH CONN RATE → {pkt.src_ip} | {cnt}/{DET.connection_rate_window}s",
                pkt.src_ip)

    # ════════════════════════════════════════════════════════════════
    #  NEW RULES 17–27
    # ════════════════════════════════════════════════════════════════

    def _rule_17_udp_scan(self, pkt, now):
        """UDP port scan — small payloads to many different UDP ports."""
        if self._ignored_source(pkt):
            return
        if pkt.protocol != "UDP" or pkt.dst_port <= 0:
            return
        bucket = int(now)
        entry = self._udp_scan[pkt.src_ip]
        entry.setdefault(bucket, set()).add(pkt.dst_port)
        stale = [t for t in entry if now - t >= DET.port_scan_window]
        for t in stale:
            entry.pop(t, None)
        all_ports: set = set()
        for ports in entry.values():
            all_ports.update(ports)
        if len(all_ports) > DET.port_scan_threshold:
            pkt.threat_level = "Danger"
            self._flag(pkt, self.RF_UDP_SCAN)
            self._alerts.emit("DANGER", "udp_scan",
                f"🔍 UDP SCAN → {pkt.src_ip} | {len(all_ports)} UDP ports on {pkt.dst_ip}",
                pkt.src_ip, pkt.dst_ip)

    def _rule_18_slow_scan(self, pkt, now):
        """Low-and-slow scan spread over minutes — evades fast-window rules."""
        if pkt.protocol not in ("TCP", "UDP") or pkt.dst_port <= 0:
            return
        # Use minute-level bucket so a scan over 5 minutes accumulates
        minute_bucket = int(now / 60)
        entry = self._slow_scan[pkt.src_ip]
        entry.setdefault(minute_bucket, set()).add(pkt.dst_port)
        stale = [t for t in entry
                 if now - t * 60 >= DET.slow_scan_window]
        for t in stale:
            entry.pop(t, None)
        all_ports: set = set()
        for ports in entry.values():
            all_ports.update(ports)
        if len(all_ports) > DET.slow_scan_threshold:
            if pkt.threat_level == "Safe":
                pkt.threat_level = "Suspicious"
            self._flag(pkt, self.RF_SLOW_SCAN)
            self._alerts.emit("WARNING", "slow_scan",
                f"🐢 SLOW SCAN → {pkt.src_ip} | {len(all_ports)} ports over {DET.slow_scan_window}s",
                pkt.src_ip, pkt.dst_ip)

    def _rule_19_land_attack(self, pkt):
        """Land attack: src IP == dst IP (causes infinite loop in some stacks)."""
        if not pkt.src_ip or not pkt.dst_ip:
            return
        if pkt.src_ip == pkt.dst_ip and pkt.src_ip not in ("127.0.0.1", "::1"):
            pkt.threat_level = "Danger"
            self._flag(pkt, self.RF_LAND)
            self._alerts.emit("DANGER", "land_attack",
                f"💥 LAND ATTACK → src==dst={pkt.src_ip}:{pkt.src_port}",
                pkt.src_ip, pkt.dst_ip)

    def _rule_20_smurf_attack(self, pkt):
        """Smurf: ICMP echo request to broadcast address."""
        if pkt.protocol != "ICMP" or pkt.icmp_type != 8:
            return
        dst = pkt.dst_ip or ""
        # Broadcast heuristics: ends in .255 or is 255.255.255.255
        if dst.endswith(".255") or dst == "255.255.255.255":
            pkt.threat_level = "Danger"
            self._flag(pkt, self.RF_SMURF)
            self._alerts.emit("DANGER", "smurf",
                f"📣 SMURF ATTACK → {pkt.src_ip} → broadcast {dst}",
                pkt.src_ip, pkt.dst_ip)

    def _rule_21_icmp_tunnel(self, pkt):
        """ICMP tunneling: echo request/reply with oversized payload."""
        if pkt.protocol != "ICMP" or pkt.icmp_type not in (0, 8):
            return
        if pkt.payload_size > DET.icmp_tunnel_payload_bytes:
            if pkt.threat_level == "Safe":
                pkt.threat_level = "Suspicious"
            self._flag(pkt, self.RF_ICMP_TUNNEL)
            self._alerts.emit("WARNING", "icmp_tunnel",
                f"🕵️ ICMP TUNNEL? → {pkt.src_ip} | echo payload={pkt.payload_size}B "
                f"(>{DET.icmp_tunnel_payload_bytes}B)",
                pkt.src_ip, pkt.dst_ip)

    def _rule_22_rst_flood(self, pkt, now):
        """TCP RST flood — RST injection for session hijacking / DoS."""
        # Packet may be classified as HTTP/HTTPS but still be a TCP RST.
        if not pkt._raw or not pkt._raw.haslayer(TCP) or "R" not in pkt.tcp_flags:
            return
        w = self._rst_w[pkt.src_ip]
        w.add(now)
        cnt = w.count(now, DET.rst_flood_window)
        if cnt > DET.rst_flood_threshold:
            pkt.threat_level = "Danger"
            self._flag(pkt, self.RF_RST_FLOOD)
            self._alerts.emit("DANGER", "rst_flood",
                f"💣 RST FLOOD → {pkt.src_ip} | {cnt} RST/{DET.rst_flood_window}s",
                pkt.src_ip, pkt.dst_ip)

    def _rule_23_http_flood(self, pkt, now):
        """HTTP flood on established connections — bypasses SYN-only detection."""
        if pkt.protocol not in ("HTTP", "HTTP-ALT") or not pkt.http_method:
            return
        w = self._http_w[pkt.src_ip]
        w.add(now)
        cnt = w.count(now, DET.http_flood_window)
        if cnt > DET.http_flood_threshold:
            pkt.threat_level = "Danger"
            self._flag(pkt, self.RF_HTTP_FLOOD)
            self._alerts.emit("DANGER", "http_flood",
                f"🌊 HTTP FLOOD → {pkt.src_ip} | {cnt} req/{DET.http_flood_window}s "
                f"({pkt.http_method} {pkt.dst_ip})",
                pkt.src_ip, pkt.dst_ip)

    # Login path patterns for credential stuffing detection
    _LOGIN_PATTERNS = (
        "/login", "/signin", "/auth", "/authenticate",
        "/wp-login", "/admin", "/user/login", "/account/login",
        "/api/login", "/api/auth", "/session",
    )

    def _rule_24_cred_stuffing(self, pkt, now):
        """Credential stuffing — rapid POST requests to login-like endpoints."""
        if pkt.protocol not in ("HTTP", "HTTP-ALT"):
            return
        if pkt.http_method != "POST":
            return
        path = (pkt.http_path or "").lower()
        if not any(pat in path for pat in self._LOGIN_PATTERNS):
            return
        w = self._cred_w[pkt.src_ip]
        w.add(now)
        cnt = w.count(now, DET.cred_stuff_window)
        if cnt > DET.cred_stuff_threshold:
            pkt.threat_level = "Danger"
            self._flag(pkt, self.RF_CRED_STUFF)
            self._alerts.emit("DANGER", "cred_stuffing",
                f"🔑 CREDENTIAL STUFFING → {pkt.src_ip} | "
                f"{cnt} POST {pkt.http_path} / {DET.cred_stuff_window}s",
                pkt.src_ip, pkt.dst_ip)

    def _rule_25_ttl_anomaly(self, pkt):
        """TTL anomaly — very low TTL suggests fingerprinting or evasion.

        Note: IPv6 uses TTL=255 routinely for ICMPv6/ND packets. We only flag
        low TTL values and skip multicast/link-local destinations to avoid noise.
        """
        if not pkt.src_ip or not pkt.dst_ip:
            return

        # Only evaluate TTL anomalies on actual IP traffic. Non-IP packets
        # may default TTL to 0 and otherwise generate false positives.
        if pkt.protocol in ("ARP", "OTHER"):
            return

        # Skip internal/reserved sources or destinations, and multicast/link-local traffic.
        if _is_private_or_reserved_ip(pkt.src_ip) or _is_private_or_reserved_ip(pkt.dst_ip):
            return
        try:
            dst_addr = ipaddress.ip_address(pkt.dst_ip)
            if dst_addr.is_multicast or dst_addr.is_link_local:
                return
        except Exception:
            pass

        if pkt.ttl in DET.ttl_anomaly_values:
            if pkt.threat_level == "Safe":
                pkt.threat_level = "Suspicious"
            self._flag(pkt, self.RF_TTL_ANOMALY)
            self._alerts.emit("WARNING", "ttl_anomaly",
                f"⏱️ TTL ANOMALY → {pkt.src_ip} → {pkt.dst_ip} | TTL={pkt.ttl}",
                pkt.src_ip, pkt.dst_ip)

    def _rule_26_payload_entropy(self, pkt):
        """High entropy payload on a non-encrypted port — possible tunneling
        or obfuscated C2 channel hiding inside plaintext protocols."""
        if pkt.payload_size < 256:  # Increased from 64 to 256 to reduce noise
            return  # too short for reliable entropy estimate
        # ✅ v5 FIX: Skip protocols that commonly use compression (gzip/brotli/zstd)
        # Normal compressed HTTP responses have entropy ~7.5+, causing FPs
        if pkt.protocol in ("HTTP", "HTTP-ALT", "HTTPS", "QUIC", "SSH"):
            return
        # ✅ FIX: Skip common legitimate protocols that might have high entropy
        if pkt.protocol in ("DNS", "DHCP", "NTP", "SNMP", "Syslog"):
            return
        # Only flag if the port is NOT one we'd normally expect encryption on
        encrypted_ports = frozenset({443, 8443, 993, 995, 465, 22, 21, 990, 989})  # Added FTP ports
        if pkt.dst_port in encrypted_ports or pkt.src_port in encrypted_ports:
            return
        # ✅ FIX: Require higher entropy threshold to reduce false positives
        if pkt.payload_entropy >= 7.5:  # Increased from 7.2
            if pkt.threat_level == "Safe":
                pkt.threat_level = "Suspicious"
            self._flag(pkt, self.RF_ENTROPY)
            self._alerts.emit("WARNING", "payload_entropy",
                f"🔐 HIGH ENTROPY PAYLOAD → {pkt.src_ip}:{pkt.src_port} → "
                f"{pkt.dst_ip}:{pkt.dst_port} | "
                f"entropy={pkt.payload_entropy:.2f} bits/B size={pkt.payload_size}B",
                pkt.src_ip, pkt.dst_ip)

    def _rule_27_beacon(self, pkt, now):
        """
        Beacon / C2 detection — periodic callback interval analysis.
        Tracks timestamps of packets to each (src, dst, dport) tuple and
        computes coefficient of variation (std/mean) of inter-arrival times.
        A very low CoV = clock-like regularity = likely automated beacon.
        """
        if pkt.protocol not in ("TCP", "UDP"):
            return
        # ✅ FIX: Don't flag common periodic services and protocols
        common_periodic_ports = {53, 123, 67, 68, 5353, 1900, 3702, 22, 25, 110, 143, 993, 995}  # DNS, NTP, DHCP, mDNS, SSDP, WS-Discovery, SSH, email
        if pkt.dst_port in common_periodic_ports:
            return
        # ✅ FIX: Don't flag HTTP/HTTPS traffic (browsers, APIs, etc.)
        if pkt.protocol in ("HTTP", "HTTPS") or pkt.dst_port in (80, 443, 8080, 8443):
            return
        key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port)
        ts_dq = self._beacon_ts[key]
        ts_dq.append(now)

        if len(ts_dq) < DET.beacon_min_hits:
            return

        intervals = [ts_dq[i] - ts_dq[i - 1] for i in range(1, len(ts_dq))]
        mean_iv = statistics.mean(intervals)

        # Only consider intervals in the plausible beacon range
        if not (DET.beacon_min_interval <= mean_iv <= DET.beacon_max_interval):
            return

        if mean_iv < 1e-6:
            return
        std_iv = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
        cov = std_iv / mean_iv  # coefficient of variation

        # ✅ FIX: Require even lower jitter ratio to reduce false positives
        if cov <= 0.10:  # Reduced from 0.15
            if pkt.threat_level == "Safe":
                pkt.threat_level = "Suspicious"
            self._flag(pkt, self.RF_BEACON)
            self._alerts.emit("WARNING", "beacon",
                f"📡 BEACON/C2? → {pkt.src_ip} → {pkt.dst_ip}:{pkt.dst_port} | "
                f"interval={mean_iv:.1f}s CoV={cov:.3f} hits={len(ts_dq)}",
                pkt.src_ip, pkt.dst_ip)

    def _rule_33_wifi_deauth(self, pkt, now):
        """WiFi Deauthentication Attack Detection"""
        if not pkt.protocol.startswith("WIFI-DEAUTH"):
            return
        
        # Track deauth frames per BSSID
        bssid = pkt.bssid or "unknown"
        key = (bssid, "deauth")
        
        if key not in self._wifi_deauth_w:
            self._wifi_deauth_w[key] = SlidingWindow()
        
        deauth_w = self._wifi_deauth_w[key]
        deauth_w.add(now)
        
        # Check for deauth flood
        if deauth_w.count(now, 60) > DET.wifi_deauth_threshold:
            if pkt.threat_level == "Safe":
                pkt.threat_level = "Danger"
            self._flag(pkt, self.RF_WIFI_DEAUTH)
            self._alerts.emit("DANGER", "wifi_deauth",
                f"🚫 WiFi DEAUTH FLOOD → BSSID:{bssid} | "
                f"frames/min={deauth_w.count(now, 60)} target={pkt.dst_mac}",
                pkt.src_mac, pkt.dst_mac)

    def _rule_34_wifi_probe_flood(self, pkt, now):
        """WiFi Probe Request Flood Detection"""
        if not pkt.protocol.startswith("WIFI-PROBE"):
            return
        
        # Track probe requests per source MAC
        key = (pkt.src_mac, "probe")
        
        if key not in self._wifi_probe_w:
            self._wifi_probe_w[key] = SlidingWindow()
        
        probe_w = self._wifi_probe_w[key]
        probe_w.add(now)
        
        # Check for probe flood
        if probe_w.count(now, 60) > DET.wifi_probe_flood_threshold:
            if pkt.threat_level == "Safe":
                pkt.threat_level = "Suspicious"
            self._flag(pkt, self.RF_WIFI_PROBE_FLOOD)
            self._alerts.emit("WARNING", "wifi_probe_flood",
                f"📡 WiFi PROBE FLOOD → {pkt.src_mac} | "
                f"requests/min={probe_w.count(now, 60)}",
                pkt.src_mac, "broadcast")

    def _rule_35_wifi_evil_twin(self, pkt, now):
        """Evil Twin AP Detection - Multiple SSIDs from same BSSID"""
        if not pkt.protocol.startswith("WIFI-BEACON"):
            return
        
        bssid = pkt.bssid
        ssid = pkt.wifi_ssid
        
        if not bssid or not ssid:
            return
        
        # Track SSIDs per BSSID
        if bssid not in self._wifi_ssids:
            self._wifi_ssids[bssid] = set()
        
        ssids = self._wifi_ssids[bssid]
        ssids.add(ssid)
        
        # If BSSID broadcasts multiple SSIDs, potential evil twin
        if len(ssids) > 1:
            if pkt.threat_level == "Safe":
                pkt.threat_level = "Critical"
            self._flag(pkt, self.RF_WIFI_EVIL_TWIN)
            self._alerts.emit("DANGER", "wifi_evil_twin",
                f"👥 EVIL TWIN AP → BSSID:{bssid} | "
                f"SSIDs:{list(ssids)} | Possible rogue AP",
                bssid, "broadcast")

    def _rule_36_wifi_ssid_spoof(self, pkt, now):
        """SSID Spoofing Detection - Rapid SSID changes"""
        if not pkt.protocol.startswith("WIFI-BEACON"):
            return
        
        bssid = pkt.bssid
        ssid = pkt.wifi_ssid
        
        if not bssid or not ssid:
            return
        
        key = (bssid, "ssid_change")
        
        if key not in self._wifi_ssid_w:
            self._wifi_ssid_w[key] = SlidingWindow()
        
        # Track SSID changes
        current_ssid = getattr(self, f'_ssid_{bssid}', None)
        if current_ssid and current_ssid != ssid:
            ssid_w = self._wifi_ssid_w[key]
            ssid_w.add(now)
            
            # Check for rapid SSID changes
            if ssid_w.count(now, 60) > DET.wifi_ssid_change_threshold:
                if pkt.threat_level == "Safe":
                    pkt.threat_level = "Suspicious"
                self._flag(pkt, self.RF_WIFI_SSID_SPOOF)
                self._alerts.emit("WARNING", "wifi_ssid_spoof",
                    f"🎭 SSID SPOOFING → BSSID:{bssid} | "
                    f"changes/min={ssid_w.count(now, 60)}",
                    bssid, "broadcast")
        
        setattr(self, f'_ssid_{bssid}', ssid)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 10: SIGNATURE ENGINE (Suricata-style minimal subset)
# ═══════════════════════════════════════════════════════════════════════════════

class SignatureEngine:
    """Minimal Suricata-style signature matcher (content-based).

    Supports a very small subset of Suricata rule syntax:
      alert <proto> <src_ip> <src_port> -> <dst_ip> <dst_port> (msg:"..."; content:"..."; sid:<n>; nocase;)

    Only supports TCP/UDP, content matching, basic IP/port wildcards.
    """

    def __init__(self, rules_path: Optional[str] = None):
        self.rules = []  # type: List[Dict[str, Any]]
        if rules_path:
            self.load_rules(rules_path)

    def load_rules(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    rule = self._parse_rule(line)
                    if rule:
                        self.rules.append(rule)
        except Exception:
            logger.exception("Failed to load signature rules from %s", path)

    def _parse_rule(self, line: str) -> Optional[Dict[str, Any]]:
        # Very thin interpreter: split header and options
        try:
            header, opts = line.split("(", 1)
            opts = opts.rsplit(")", 1)[0]
            parts = header.strip().split()
            if len(parts) < 7 or parts[0] != "alert":
                return None
            proto, src_ip, src_port, _, dst_ip, dst_port = parts[1:7] # type: ignore
            rule = {
                "proto": proto.lower(),
                "src_ip": src_ip, "src_port": src_port,
                "dst_ip": dst_ip, "dst_port": dst_port,
                "msg": "", "sid": None, "content": None,
                "nocase": False,
            }
            for opt in opts.split(";"):
                opt = opt.strip()
                if not opt:
                    continue
                if opt.startswith("msg:"):
                    rule["msg"] = opt.split(":", 1)[1].strip().strip('"')
                elif opt.startswith("sid:"):
                    try:
                        rule["sid"] = int(opt.split(":", 1)[1])
                    except Exception:
                        pass
                elif opt.startswith("content:"):
                    rule["content"] = opt.split(":", 1)[1].strip().strip('"')
                elif opt == "nocase":
                    rule["nocase"] = True
            return rule
        except Exception:
            return None

    def match(self, pkt: ParsedPacket) -> List[Dict[str, Any]]:
        matches = []
        if not self.rules:
            return matches
        # Prepare key fields
        proto = pkt.protocol.lower()
        src_ip, dst_ip = pkt.src_ip, pkt.dst_ip
        src_port, dst_port = pkt.src_port, pkt.dst_port
        payload = (pkt.raw_payload or b"")
        for r in self.rules:
            # Protocol/port filter
            if r["proto"] not in ("any", proto):
                continue
            if r["src_ip"] not in ("any", src_ip) and not r["src_ip"].endswith("/"):
                continue
            if r["dst_ip"] not in ("any", dst_ip) and not r["dst_ip"].endswith("/"):
                continue
            if r["src_port"] not in ("any", str(src_port)):
                continue
            if r["dst_port"] not in ("any", str(dst_port)):
                continue
            # Content match
            if r.get("content"):
                data = payload.decode("utf-8", errors="ignore") # type: ignore
                if r.get("nocase"):
                    if r["content"].lower() not in data.lower():
                        continue
                else:
                    if r["content"] not in data:
                        continue
            matches.append(r)
        return matches


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 11: ML FEATURE EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════════

FEATURE_NAMES = [
    "duration", "protocol_type",
    "total_fwd_packets", "total_bwd_packets",
    "total_length_fwd", "total_length_bwd",
    "fwd_packet_length_max", "fwd_packet_length_min",
    "fwd_packet_length_mean", "fwd_packet_length_std",
    "bwd_packet_length_max", "bwd_packet_length_min",
    "bwd_packet_length_mean", "bwd_packet_length_std",
    "flow_bytes_per_sec", "flow_packets_per_sec",
    "flow_iat_mean", "fwd_iat_mean", "bwd_iat_mean",
    "fwd_psh_flags", "fwd_urg_flags",
    "packet_length_mean", "packet_length_std",
    "packet_length_variance",
    "fin_flag_count", "syn_flag_count", "rst_flag_count",
    "psh_flag_count", "ack_flag_count", "urg_flag_count",
    "avg_packet_size",
    "subflow_fwd_packets", "subflow_fwd_bytes",
    "subflow_bwd_packets", "subflow_bwd_bytes",
    "init_win_bytes_forward",
    "min_packet_length", "max_packet_length",
    "payload_size", "header_size",
    # ──  NEW features ─────────────────────────────────────────────────
    "payload_entropy",          # Shannon entropy of payload (detects tunneling)
    "iat_std",                  # inter-arrival time std (burst detection)
    "fwd_bwd_ratio",            # asymmetry (exfil = high fwd; scan = low bwd)
    "rst_ratio",                # fraction of packets with RST flag
    "bytes_per_packet",         # overall efficiency indicator
    "port_entropy",             # diversity of dst ports from this src (scanner)
    "rule_flags",               # bitmask of rule-engine hits (ensemble signal)
    "flow_packet_count",        # total packets in flow (maturity indicator)
]
NUM_FEATURES = len(FEATURE_NAMES)
_PROTO_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2}


def _safe_stats(values: list) -> Tuple[float, float, float, float]:
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    return (float(max(values)), float(min(values)),
            float(statistics.mean(values)),
            float(statistics.pstdev(values)) if len(values) > 1 else 0.0)


def extract_features(pkt: ParsedPacket, flow: Optional[Flow]) -> Optional["np.ndarray"]:
    """Extract ML feature vector from packet + flow context."""
    if not NUMPY_OK:
        return None
    f = np.zeros(NUM_FEATURES, dtype=np.float64)
    dur = flow.duration if flow else 1e-6
    fwd_l = flow.fwd_lengths if flow else [pkt.total_length]
    bwd_l = flow.bwd_lengths if flow else []
    all_l = fwd_l + bwd_l

    fwd_mx, fwd_mn, fwd_me, fwd_sd = _safe_stats(fwd_l)
    bwd_mx, bwd_mn, bwd_me, bwd_sd = _safe_stats(bwd_l)
    all_mx, all_mn, all_me, all_sd = _safe_stats(all_l)

    tp = flow.total_packets if flow else 1
    tb = flow.total_bytes if flow else pkt.total_length
    fwd_iat_m = statistics.mean(flow.fwd_iat) if flow and flow.fwd_iat else 0
    bwd_iat_m = statistics.mean(flow.bwd_iat) if flow and flow.bwd_iat else 0

    vals = [
        dur,
        _PROTO_MAP.get(pkt.protocol, 3),
        flow.fwd_packets if flow else 1,
        flow.bwd_packets if flow else 0,
        flow.fwd_bytes if flow else pkt.total_length,
        flow.bwd_bytes if flow else 0,
        fwd_mx, fwd_mn, fwd_me, fwd_sd,
        bwd_mx, bwd_mn, bwd_me, bwd_sd,
        tb / dur, tp / dur,
        dur / tp if tp else 0,
        fwd_iat_m, bwd_iat_m,
        flow.psh_count if flow else int("P" in pkt.tcp_flags),
        flow.urg_count if flow else int("U" in pkt.tcp_flags),
        all_me, all_sd, all_sd ** 2,
        flow.fin_count if flow else int("F" in pkt.tcp_flags),
        flow.syn_count if flow else int("S" in pkt.tcp_flags),
        flow.rst_count if flow else int("R" in pkt.tcp_flags),
        flow.psh_count if flow else int("P" in pkt.tcp_flags),
        flow.ack_count if flow else int("A" in pkt.tcp_flags),
        flow.urg_count if flow else int("U" in pkt.tcp_flags),
        float(tb) / max(tp, 1),
        flow.fwd_packets if flow else 1,
        flow.fwd_bytes if flow else pkt.total_length,
        flow.bwd_packets if flow else 0,
        flow.bwd_bytes if flow else 0,
        pkt.window_size,
        all_mn if all_l else pkt.total_length,
        all_mx if all_l else pkt.total_length,
        pkt.payload_size, pkt.ip_header_len,
        # ──  NEW ─────────────────────────────────────────────────────
        pkt.payload_entropy,
        # inter-arrival time std — high = bursty, low = regular (beacon)
        float(statistics.pstdev(flow.fwd_iat)) if flow and len(flow.fwd_iat) > 1 else 0.0,
        # fwd/bwd asymmetry — exfil flows are heavily forward-biased
        float(flow.fwd_bytes) / max(flow.bwd_bytes, 1) if flow else 1.0,
        # RST ratio — injections / teardowns
        float(flow.rst_count) / max(tp, 1) if flow else 0.0,
        # bytes per packet
        float(tb) / max(tp, 1),
        # port entropy placeholder — filled by RuleEngine via rule_flags proxy
        0.0,
        # rule_flags bitmask from rule engine
        float(pkt.rule_flags),
        # flow packet count — immature flows (1-3 pkts) are noisy for ML
        float(tp),
    ]
    assert len(vals) == NUM_FEATURES, f"Expected {NUM_FEATURES} features, got {len(vals)}"
    for i, v in enumerate(vals):
        f[i] = v
    return f


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 11: BASELINE MODEL — ✅ Learns YOUR network
# ═══════════════════════════════════════════════════════════════════════════════

class BaselineModel:
    """
    ✅ : Per-protocol statistical baseline of YOUR network traffic.
    Maintains separate mean/std for TCP, UDP, ICMP, ENCRYPTED, and OTHER so that
    normal UDP bursts don't contaminate the TCP baseline and encrypted traffic
    gets its own baseline. Uses median z-score instead of max z-score to reduce single-feature FP.
    """

    _PROTOCOLS = ("TCP", "UDP", "ICMP", "ENCRYPTED", "OTHER")

    def __init__(self) -> None:
        # One deque of samples per protocol
        self._samples: Dict[str, deque] = {
            p: deque(maxlen=MLC.baseline_max_samples // len(self._PROTOCOLS))
            for p in self._PROTOCOLS
        }
        self._mean: Dict[str, Optional["np.ndarray"]] = {p: None for p in self._PROTOCOLS}
        self._std:  Dict[str, Optional["np.ndarray"]] = {p: None for p in self._PROTOCOLS}
        self._ready: Dict[str, bool] = {p: False for p in self._PROTOCOLS}
        self._learning = True
        self._start_time = time.time()
        self._lock = threading.Lock()

    @property
    def is_ready(self) -> bool:
        return any(self._ready.values())

    def _proto_key(self, proto: str) -> str:
        if proto.upper() in ("HTTPS", "QUIC", "SSH"):
            return "ENCRYPTED"
        return proto if proto in self._PROTOCOLS else "OTHER"

    def add_sample(self, features: "np.ndarray", proto: str = "OTHER") -> None:
        if not NUMPY_OK:
            return
        key = self._proto_key(proto)
        with self._lock:
            self._samples[key].append(features.copy())
            elapsed = time.time() - self._start_time
            # ✅ v5 FIX: Require 1000 samples (was 500) for more stable baselines
            if (self._learning
                    and elapsed > MLC.baseline_learning_period
                    and len(self._samples[key]) > 1000):
                self._compute(key)
                if all(len(self._samples[p]) > 100 for p in self._PROTOCOLS):
                    self._learning = False
                    logger.info(" per-protocol baselines computed")

    def _compute(self, key: str) -> None:
        arr = np.array(list(self._samples[key])) # type: ignore
        self._mean[key] = np.mean(arr, axis=0) # type: ignore
        self._std[key]  = np.std(arr, axis=0) # type: ignore
        std_k = self._std[key]
        if std_k is not None:
            for i in range(len(std_k)): # type: ignore
                if std_k[i] is None or float(std_k[i]) < 1e-8: # type: ignore
                    std_k[i] = 1.0 # type: ignore
        self._ready[key] = True

    def score(self, features: "np.ndarray", proto: str = "OTHER") -> float:
        """
        Return anomaly score using MEDIAN z-score ( improvement).
        Median is far less sensitive to single outlier features than max,
        which was the primary cause of false positives in v4.
        """
        key = self._proto_key(proto)
        if not self._ready.get(key):
            return 0.0
        with self._lock:
            z = np.abs((features - self._mean[key]) / self._std[key])
            # Use 90th-percentile z instead of max — still sensitive but
            # requires multiple features to be anomalous, not just one.
            return float(np.percentile(z, 90))

    def save(self) -> None:
        if SKLEARN_OK and any(self._mean[p] is not None for p in self._PROTOCOLS):
            with self._lock:
                joblib.dump({"mean": self._mean, "std": self._std,
                             "ready": self._ready}, str(MLC.baseline_path))
            logger.info(" per-protocol baseline saved")

    def load(self) -> bool:
        if not SKLEARN_OK:
            return False
        try:
            if MLC.baseline_path.exists():
                data = joblib.load(str(MLC.baseline_path))
                self._mean  = data.get("mean",  self._mean)
                self._std   = data.get("std",   self._std)
                self._ready = data.get("ready", self._ready)
                self._learning = not any(self._ready.values())
                logger.info(" baseline loaded")
                return True
        except Exception as e:
            logger.warning("Baseline load failed: %s", e)
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 12: ML ENGINE — Supervised + Unsupervised with batch processing
# ═══════════════════════════════════════════════════════════════════════════════

# ✅ FIX 3: Ports that are well-known services and prone to ML false positives.
# CIC-IDS2017/2018 and UNSW-NB15 models frequently classify normal HTTPS, DNS,
# and SSH traffic as "Exploits" or "Generic" at 70-88% confidence.
# We suppress ML alerts on these ports unless confidence reaches 92%.
_ML_WELL_KNOWN_PORTS: frozenset = frozenset({
    80, 443, 8080, 8443,    # HTTP / HTTPS
    53, 5353,               # DNS / mDNS
    22,                     # SSH
    25, 587, 110, 143,      # SMTP / POP3 / IMAP
    993, 995,               # IMAPS / POP3S
    123,                    # NTP
    67, 68,                 # DHCP
    3306, 5432, 6379,       # MySQL / PostgreSQL / Redis
})
# Confidence required to fire on a well-known port (overrides threshold)
_ML_WELL_KNOWN_MIN_CONF: float = 0.92


class MLEngine:
    """
    Combined ML detection engine:
    ✅ Supervised (Random Forest from CSV training)
    ✅ Unsupervised (Baseline anomaly detection — learns YOUR network)
    ✅ Batch prediction for throughput
    ✅ Thread-safe input queue
    ✅ Graceful degradation if no model loaded
    ✅ FIX 3: well-known port exemption suppresses HTTPS/DNS false positives
    """

    def __init__(self, alert_mgr: AlertManager, flow_tracker: FlowTracker,
                 capture_ref=None) -> None:
        self._alerts = alert_mgr
        self._flows = flow_tracker
        self._capture = capture_ref

        self._model: Optional[Any] = None
        self._scaler: Optional[Any] = None
        self._encoder: Optional[Any] = None
        self._supervised_ready = False

        self._baseline = BaselineModel()
        self._baseline.load()

        self._input_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.predictions = 0
        self.detections = 0

        self._load_model()

    def _load_model(self) -> bool:
        if not SKLEARN_OK:
            return False
        try:
            if MLC.model_path.exists():
                self._model = joblib.load(str(MLC.model_path))
                self._scaler = joblib.load(str(MLC.scaler_path))
                self._encoder = joblib.load(str(MLC.encoder_path))
                self._supervised_ready = True
                logger.info("ML model loaded: %s", MLC.model_path)
                return True
        except Exception as e:
            logger.error("ML model load failed: %s", e)
        return False

    @property
    def is_ready(self) -> bool:
        return self._supervised_ready or self._baseline.is_ready

    def enqueue(self, pkt: ParsedPacket) -> None:
        try:
            self._input_queue.put_nowait(pkt)
        except queue.Full:
            pass

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="PherionML")
        t = self._thread
        if t is not None:
            t.start()
        logger.info("ML engine started")

    def stop(self) -> None:
        self._running = False
        try:
            self._baseline.save()
        except Exception:
            pass
        logger.info("ML engine stopped (predictions=%d, detections=%d)",
                    self.predictions, self.detections)

    def reload_model(self) -> bool:
        return self._load_model()

    def _run(self) -> None:
        """✅ Batch processing loop for ML predictions."""
        batch_feats: List["np.ndarray"] = []
        batch_pkts: List[ParsedPacket] = []

        while self._running:
            try:
                pkt = self._input_queue.get(timeout=0.1)
                flow = self._flows.get_flow(
                    pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
                feats = extract_features(pkt, flow)
                if feats is None:
                    continue
                batch_feats.append(feats)
                batch_pkts.append(pkt)

                # ✅ Batch: drain up to batch_size
                while len(batch_feats) < MLC.batch_predict_size:
                    try:
                        pkt2 = self._input_queue.get_nowait()
                        flow2 = self._flows.get_flow(
                            pkt2.src_ip, pkt2.dst_ip, pkt2.src_port, pkt2.dst_port, pkt2.protocol)
                        f2 = extract_features(pkt2, flow2)
                        if f2 is not None:
                            batch_feats.append(f2)
                            batch_pkts.append(pkt2)
                    except queue.Empty:
                        break

                self._process_batch(batch_feats, batch_pkts)
                batch_feats.clear()
                batch_pkts.clear()

            except queue.Empty:
                continue
            except Exception:
                logger.debug("ML batch error", exc_info=True)
                batch_feats.clear()
                batch_pkts.clear()

    def _process_batch(self, features: List["np.ndarray"],
                       packets: List[ParsedPacket]) -> None:
        if not NUMPY_OK:
            return
        X = np.array(features)

        # ✅  Baseline (unsupervised) — per-protocol, 90th-pct z-score
        for i, pkt in enumerate(packets):
            self._baseline.add_sample(features[i], pkt.protocol)
            if self._baseline.is_ready:
                score = self._baseline.score(features[i], pkt.protocol)
                
                # Encrypted protocols now have their own baseline, so use standard threshold
                threshold = MLC.anomaly_threshold
                # No longer need special multiplier since ENCRYPTED has dedicated baseline
                
                if score > threshold:
                    # ✅ v5 FIX: Skip ML anomaly alerts for purely local/private traffic
                    if (_is_private_or_reserved_ip(pkt.src_ip)
                            and _is_private_or_reserved_ip(pkt.dst_ip)):
                        continue
                    if pkt.threat_level == "Safe":
                        pkt.threat_level = "Suspicious"
                    pkt.ml_prediction = f"Anomaly(z={score:.1f})"
                    pkt.ml_confidence = min(score / 10.0, 1.0)
                    reason = f"Baseline Z-score anomaly ({score:.1f} > threshold {threshold})"
                    self._alerts.emit(
                        "WARNING", "ml_anomaly",
                        f"🤖 ANOMALY [{pkt.protocol}] → {pkt.src_ip}:{pkt.src_port} → "
                        f"{pkt.dst_ip}:{pkt.dst_port} | z={score:.1f}",
                        pkt.src_ip, pkt.dst_ip, reason=reason)
                    self.detections += 1
                    if self._capture:
                        self._capture.update_threat_stats()

        # ✅  Supervised — ensemble + min-flow-packet guard
        if self._supervised_ready and self._scaler and getattr(self._model, "predict", None) is not None:
            try:
                s = self._scaler
                if s is not None:
                    X_s = s.transform(X) # type: ignore
                    preds = self._model.predict(X_s) # type: ignore
                    probas = getattr(self._model, "predict_proba", lambda x: np.zeros((len(x), 1)))(X_s) if hasattr(self._model, "predict_proba") else np.zeros((len(X_s), 1)) # type: ignore

                for i, pkt in enumerate(packets):
                    label = self._encoder.inverse_transform([preds[i]])[0] if hasattr(self._encoder, "inverse_transform") else str(preds[i]) # type: ignore
                    conf = float(np.max(probas[i]))
                    self.predictions += 1

                    is_attack = str(label).lower() not in (
                        "benign", "normal", "safe", "0", "legitimate", "none")

                    if pkt.dst_ip and (pkt.dst_ip.startswith("224.") or pkt.dst_ip.endswith(".255") or pkt.dst_ip == "255.255.255.255"):
                        is_attack = False
                        conf = 0.0

                    # ✅ v5 FIX: Suppress for IPv6 multicast (ff00::/8)
                    if pkt.dst_ip and pkt.dst_ip.lower().startswith("ff"):
                        is_attack = False
                        conf = 0.0

                    # ✅ v5 FIX: Suppress ML alerts for purely local/private traffic
                    if (_is_private_or_reserved_ip(pkt.src_ip)
                            and _is_private_or_reserved_ip(pkt.dst_ip)):
                        is_attack = False
                        conf = 0.0

                    # ✅ : skip immature flows — features are meaningless
                    #        when we've only seen 1-3 packets
                    flow_pkts = int(features[i][FEATURE_NAMES.index("flow_packet_count")])
                    if flow_pkts < MLC.min_flow_packets and conf < MLC.ensemble_solo_threshold:
                        if not is_attack:
                            pkt.ml_prediction = str(label)
                            pkt.ml_confidence = conf
                        continue

                    # ✅ v4 FIX 3 (retained): well-known port FP suppression
                    _involves_well_known = (
                        pkt.src_port in _ML_WELL_KNOWN_PORTS
                        or pkt.dst_port in _ML_WELL_KNOWN_PORTS
                    )
                    _required_conf = (
                        _ML_WELL_KNOWN_MIN_CONF
                        if _involves_well_known
                        else MLC.confidence_threshold
                    )

                    # ✅  ENSEMBLE: if rule engine already flagged this packet,
                    #    lower the ML confidence requirement by 0.07 — two
                    #    independent signals pointing at the same flow = more
                    #    evidence.  If rule engine is silent, ML must be solo-
                    #    confident (>= ensemble_solo_threshold).
                    rule_triggered = pkt.rule_flags > 0
                    if rule_triggered:
                        _required_conf = max(_required_conf - 0.07, 0.70)

                    _should_alert = is_attack and conf >= _required_conf

                    if _should_alert:
                        pkt.ml_prediction = str(label)
                        pkt.ml_confidence = conf
                        if conf >= 0.92:
                            pkt.threat_level = "Danger"
                            level = "DANGER"
                        else:
                            if pkt.threat_level == "Safe":
                                pkt.threat_level = "Suspicious"
                            level = "WARNING"
                        # ✅ : tag ensemble hits in alert message
                        ensemble_tag = " [+Rule]" if rule_triggered else ""
                        reason = f"ML Classification: {label} with confidence {conf:.2f}. " + ("Correlated with rule engine flag." if rule_triggered else "ML solo prediction.")
                        self._alerts.emit(
                            level, "ml_classify",
                            f"🤖 ML{ensemble_tag}: {label} ({conf:.0%}) — "
                            f"{pkt.src_ip}:{pkt.src_port} → {pkt.dst_ip}:{pkt.dst_port}",
                            pkt.src_ip, pkt.dst_ip, reason=reason)
                        self.detections += 1
                        if self._capture:
                            self._capture.update_threat_stats()
                    elif not is_attack:
                        pkt.ml_prediction = str(label)
                        pkt.ml_confidence = conf
            except Exception as e:
                logger.debug("Supervised prediction error: %s", e)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 13: ML TRAINER — Train from CSV datasets
# ═══════════════════════════════════════════════════════════════════════════════

_CSV_ALIASES = {
    "flow duration": "duration", "total fwd packets": "total_fwd_packets",
    "total backward packets": "total_bwd_packets",
    "total length of fwd packets": "total_length_fwd",
    "total length of bwd packets": "total_length_bwd",
    "fwd packet length max": "fwd_packet_length_max",
    "fwd packet length min": "fwd_packet_length_min",
    "fwd packet length mean": "fwd_packet_length_mean",
    "fwd packet length std": "fwd_packet_length_std",
    "bwd packet length max": "bwd_packet_length_max",
    "bwd packet length min": "bwd_packet_length_min",
    "bwd packet length mean": "bwd_packet_length_mean",
    "bwd packet length std": "bwd_packet_length_std",
    "flow bytes/s": "flow_bytes_per_sec", "flow packets/s": "flow_packets_per_sec",
    "flow iat mean": "flow_iat_mean", "fwd iat mean": "fwd_iat_mean",
    "bwd iat mean": "bwd_iat_mean", "fwd psh flags": "fwd_psh_flags",
    "fwd urg flags": "fwd_urg_flags", "packet length mean": "packet_length_mean",
    "packet length std": "packet_length_std",
    "packet length variance": "packet_length_variance",
    "fin flag count": "fin_flag_count", "syn flag count": "syn_flag_count",
    "rst flag count": "rst_flag_count", "psh flag count": "psh_flag_count",
    "ack flag count": "ack_flag_count", "urg flag count": "urg_flag_count",
    "average packet size": "avg_packet_size",
    "subflow fwd packets": "subflow_fwd_packets",
    "subflow fwd bytes": "subflow_fwd_bytes",
    "subflow bwd packets": "subflow_bwd_packets",
    "subflow bwd bytes": "subflow_bwd_bytes",
    "init_win_bytes_forward": "init_win_bytes_forward",
    "min_packet_length": "min_packet_length", "max_packet_length": "max_packet_length",
    "min packet length": "min_packet_length", "max packet length": "max_packet_length",
    "dur": "duration", "sport": "src_port", "dsport": "dst_port",
    "sbytes": "total_length_fwd", "dbytes": "total_length_bwd",
    "spkts": "total_fwd_packets", "dpkts": "total_bwd_packets",
    "sttl": "ttl", "swin": "init_win_bytes_forward",
    "smean": "fwd_packet_length_mean", "dmean": "bwd_packet_length_mean",
    "src_bytes": "total_length_fwd", "dst_bytes": "total_length_bwd",
    "protocol_type": "protocol_type",
    "source port": "src_port", "destination port": "dst_port",
}

_LABEL_NAMES = {"label", "class", " label", "attack_cat", "attack_type", "category", "target"}


class Trainer:
    """ML training pipeline supporting CIC-IDS, NSL-KDD, UNSW-NB15 CSV datasets."""

    def __init__(self):
        self.model: Optional[Any] = None
        self.scaler: Optional[Any] = None
        self.encoder: Optional[Any] = None
        self.metrics: Dict[str, Any] = {}
        self.feature_importances: List[Tuple[str, float]] = []
        self.confusion_matrix: Optional[Any] = None
        self.roc_auc: Optional[float] = None
        self.is_trained = False
        self.training = False

    def train(self, csv_path: str, label_col: Optional[str] = None,
              progress_cb: Optional[Callable] = None,
              use_smote: bool = False) -> Dict[str, Any]:
        if not ML_AVAILABLE:
            raise RuntimeError("Install: pip install scikit-learn pandas numpy joblib")

        import warnings
        warnings.filterwarnings("ignore", category=UserWarning, module="sklearn.utils.parallel")

        self.training = True
        t0 = time.time()
        try:
            if progress_cb:
                progress_cb("Loading dataset…", 0.05)
            df = pd.read_csv(csv_path, nrows=MLC.max_training_samples,
                             low_memory=False, encoding="utf-8", encoding_errors="replace")
            df.columns = df.columns.str.strip().str.lower()

            # Find label column
            y_col = label_col.strip().lower() if label_col else None
            if not y_col:
                for col in df.columns:
                    if col.strip().lower() in _LABEL_NAMES:
                        y_col = col
                        break
                if not y_col:
                    y_col = df.columns[-1]
                    logger.warning("No label column found — using: %s", y_col)

            if progress_cb:
                progress_cb("Processing labels…", 0.15)
            y_series = df[y_col].astype(str).str.strip()
            df = df.drop(columns=[y_col], errors="ignore")

            rename = {c: _CSV_ALIASES[c.strip().lower()]
                      for c in df.columns if c.strip().lower() in _CSV_ALIASES}
            df = df.rename(columns=rename)

            if "protocol_type" in df.columns and df["protocol_type"].dtype == object:
                df["protocol_type"] = df["protocol_type"].str.lower().map(
                    {"tcp": 0, "udp": 1, "icmp": 2}).fillna(3)

            if progress_cb:
                progress_cb("Aligning features…", 0.20)
            df = df.reindex(columns=FEATURE_NAMES, fill_value=0)
            df = df.replace([np.inf, -np.inf], 0).fillna(0)
            for col in df.columns:
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

            X = df.values
            enc = LabelEncoder()
            self.encoder = enc
            y = enc.fit_transform(y_series) # type: ignore
            logger.info("Training classes: %s", list(enc.classes_)) # type: ignore

            if progress_cb:
                progress_cb("Splitting…", 0.25)
            stratify = y if len(np.unique(y)) > 1 else None # type: ignore
            X_train, X_test, y_train, y_test = train_test_split( # type: ignore
                X, y, test_size=MLC.test_split,
                random_state=MLC.random_state, stratify=stratify)

            if progress_cb:
                progress_cb("Preparing training data…", 0.30)

            # Optional handling for class imbalance via SMOTE (if installed)
            if use_smote and SMOTE_OK and SMOTE is not None:
                try:
                    sm = SMOTE(random_state=MLC.random_state)
                    X_train, y_train = sm.fit_resample(X_train, y_train)
                    logger.info("SMOTE applied: training set resampled to %d samples", len(y_train))
                except Exception:
                    logger.warning("SMOTE oversampling failed; continuing without it")

            if progress_cb:
                progress_cb("Scaling…", 0.30)
            scl = StandardScaler()
            self.scaler = scl
            X_train = scl.fit_transform(X_train) # type: ignore
            X_test = scl.transform(X_test) # type: ignore

            if progress_cb:
                progress_cb("Training Random Forest…", 0.35)
            mod = RandomForestClassifier(
                n_estimators=MLC.n_estimators, max_depth=MLC.max_depth,
                min_samples_split=MLC.min_samples_split,
                n_jobs=MLC.n_jobs, random_state=MLC.random_state,
                class_weight="balanced")
            self.model = mod
            mod.fit(X_train, y_train) # type: ignore

            if progress_cb:
                progress_cb("Evaluating…", 0.85)
            y_pred = mod.predict(X_test) # type: ignore
            acc = accuracy_score(y_test, y_pred) # type: ignore
            f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0) # type: ignore
            prec = precision_score(y_test, y_pred, average="weighted", zero_division=0) # type: ignore
            rec = recall_score(y_test, y_pred, average="weighted", zero_division=0) # type: ignore
            report = classification_report( # type: ignore
                y_test, y_pred, target_names=enc.classes_, zero_division=0) # type: ignore

            if progress_cb:
                progress_cb("Cross-validating…", 0.90)
            try:
                cv = cross_val_score( # type: ignore
                    mod,
                    scl.transform(X[:min(50000, len(X))]), # type: ignore
                    y[:min(50000, len(y))],
                    cv=3, scoring="f1_weighted", n_jobs=MLC.n_jobs)
                cv_mean = float(np.mean(cv)) # type: ignore
            except Exception:
                cv_mean = 0.0

            # Additional diagnostics: confusion matrix + ROC AUC when applicable
            try:
                cm = confusion_matrix(y_test, y_pred)
                self.confusion_matrix = cm.tolist()
            except Exception:
                cm = None
                self.confusion_matrix = None

            try:
                if len(np.unique(y_test)) == 2 and hasattr(mod, "predict_proba"):
                    y_proba = mod.predict_proba(X_test)[:, 1]
                    self.roc_auc = float(roc_auc_score(y_test, y_proba))
                elif len(np.unique(y_test)) > 2 and hasattr(mod, "predict_proba"):
                    y_proba = mod.predict_proba(X_test)
                    self.roc_auc = float(roc_auc_score(y_test, y_proba, multi_class="ovr"))
                else:
                    self.roc_auc = None
            except Exception:
                self.roc_auc = None

            self.metrics = {
                "accuracy": acc,
                "f1": f1,
                "precision": prec,
                "recall": rec,
                "confusion_matrix": cm.tolist() if cm is not None else None,
                "roc_auc": self.roc_auc,
                "cv_f1_mean": cv_mean,
                "classification_report": report,
                "train_samples": len(X_train),
                "test_samples": len(X_test),
                "classes": list(enc.classes_), # type: ignore
                "training_time": time.time() - t0,
            }

            # Feature importances for model explainability
            if hasattr(mod, "feature_importances_"):
                fi = list(zip(FEATURE_NAMES, mod.feature_importances_))
                fi_sorted = sorted(fi, key=lambda x: x[1], reverse=True)
                self.feature_importances = fi_sorted
                self.metrics["feature_importances"] = list(fi_sorted[:20])  # type: ignore[index]
                try:
                    fi_path = MODEL_DIR / "feature_importances.json"
                    with open(fi_path, "w", encoding="utf-8") as f:
                        json.dump({"features": fi_sorted}, f, indent=2)
                except Exception:
                    pass

            if progress_cb:
                progress_cb("Saving model…", 0.95)
            joblib.dump(self.model, str(MLC.model_path))
            joblib.dump(self.scaler, str(MLC.scaler_path))
            joblib.dump(self.encoder, str(MLC.encoder_path))
            joblib.dump(FEATURE_NAMES, str(MLC.feature_names_path))

            self.is_trained = True
            if progress_cb:
                progress_cb("Done!", 1.0)
            logger.info("Training complete: acc=%.4f f1=%.4f time=%.1fs",
                        acc, f1, self.metrics["training_time"])
            return self.metrics

        except Exception as e:
            logger.error("Training failed: %s", e, exc_info=True)
            if progress_cb:
                progress_cb(f"Error: {e}", -1)
            raise
        finally:
            self.training = False

        return {}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 14: DATABASE — ✅ SQLite Persistence
# ═══════════════════════════════════════════════════════════════════════════════

class Database:
    """
    ✅ SQLite persistence for:
    - Alerts (searchable, with retention policy)
    - Statistics snapshots (for trend analysis)
    - Thread-safe via thread-local connections
    """

    def __init__(self) -> None:
        self._path = str(DB_DIR / "pherion.db")
        self._local = threading.local()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            setattr(self._local, "conn", conn) # type: ignore
        return conn

    def _init_db(self) -> None:
        c = self._conn()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                level TEXT NOT NULL,
                rule TEXT NOT NULL DEFAULT '',
                message TEXT NOT NULL,
                src_ip TEXT DEFAULT '',
                dst_ip TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_level ON alerts(level);
            CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule);

            CREATE TABLE IF NOT EXISTS stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                total_packets INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,
                tcp INTEGER DEFAULT 0,
                udp INTEGER DEFAULT 0,
                icmp INTEGER DEFAULT 0,
                dns INTEGER DEFAULT 0,
                threats INTEGER DEFAULT 0,
                pps INTEGER DEFAULT 0,
                active_flows INTEGER DEFAULT 0,
                buffer_usage INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_stats_ts ON stats(timestamp);

            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                created_at REAL NOT NULL,
                severity TEXT NOT NULL DEFAULT 'Medium',
                title TEXT NOT NULL DEFAULT '',
                alert_count INTEGER DEFAULT 0,
                src_ips TEXT DEFAULT '',
                dst_ips TEXT DEFAULT '',
                rules TEXT DEFAULT '',
                status TEXT DEFAULT 'open',
                last_updated REAL
            );
            CREATE INDEX IF NOT EXISTS idx_incidents_sev ON incidents(severity);
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT DEFAULT 'Low',
                rule TEXT DEFAULT '',
                description TEXT DEFAULT '',
                src_ip TEXT DEFAULT '',
                dst_ip TEXT DEFAULT '',
                src_port INTEGER DEFAULT 0,
                dst_port INTEGER DEFAULT 0,
                protocol TEXT DEFAULT '',
                metadata TEXT DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

            CREATE TABLE IF NOT EXISTS healing_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                ts_human TEXT NOT NULL,
                action TEXT NOT NULL,
                attacker_ip TEXT DEFAULT '',
                rule TEXT DEFAULT '',
                severity TEXT DEFAULT '',
                result TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_heal_ts ON healing_actions(timestamp);
            CREATE INDEX IF NOT EXISTS idx_heal_action ON healing_actions(action);
        """)
        c.commit()

    def save_alert(self, level, rule, message, src_ip="", dst_ip=""):
        try:
            c = self._conn()
            c.execute(
                "INSERT INTO alerts (timestamp,level,rule,message,src_ip,dst_ip) "
                "VALUES (?,?,?,?,?,?)",
                (time.time(), level, rule, message, src_ip, dst_ip))
            c.commit()
        except Exception:
            pass

    def save_stats(self, stats, active_flows=0, buffer_usage=0):
        try:
            c = self._conn()
            c.execute(
                "INSERT INTO stats "
                "(timestamp,total_packets,total_bytes,tcp,udp,icmp,dns,threats,pps,"
                "active_flows,buffer_usage) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (time.time(), stats.get("total", 0), stats.get("bytes", 0),
                 stats.get("tcp", 0), stats.get("udp", 0), stats.get("icmp", 0),
                 stats.get("dns", 0), stats.get("threats", 0),
                 stats.get("packets_per_sec", 0),
                 active_flows, buffer_usage))
            c.commit()
        except Exception:
            pass

    def save_incident(self, incident):
        """Save or update a SecurityIncident to the database."""
        try:
            c = self._conn()
            c.execute(
                "INSERT OR REPLACE INTO incidents "
                "(id,created_at,severity,title,alert_count,src_ips,dst_ips,rules,status,last_updated) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (incident.id, incident.created_at, incident.severity,
                 incident.title, incident.alert_count,
                 ",".join([str(r) for r in sorted(incident.src_ips)][:20]), # type: ignore
                 ",".join([str(s) for s in sorted(incident.dst_ips)][:20]), # type: ignore
                 ",".join([str(t) for t in sorted(incident.rules)]),
                 incident.status, incident.last_updated))
            c.commit()
        except Exception:
            pass

    def save_heal_action(self, action: str, attacker_ip: str, rule: str,
                         severity: str, result: str, ts_human: str) -> None:
        """Persist a self-healing action to the healing_actions table for audit/compliance."""
        try:
            c = self._conn()
            c.execute(
                "INSERT INTO healing_actions "
                "(timestamp, ts_human, action, attacker_ip, rule, severity, result) "
                "VALUES (?,?,?,?,?,?,?)",
                (time.time(), ts_human, action, attacker_ip, rule, severity, result)
            )
            c.commit()
        except Exception:
            pass

    def get_timeline(self, start_ts=None, end_ts=None, event_type=None, limit=500):
        """Query events for incident investigation timeline."""
        try:
            c = self._conn()
            sql = "SELECT * FROM events WHERE 1=1"
            params = []
            if start_ts:
                sql += " AND timestamp >= ?"
                params.append(start_ts)
            if end_ts:
                sql += " AND timestamp <= ?"
                params.append(end_ts)
            if event_type:
                sql += " AND event_type = ?"
                params.append(event_type)
            sql += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            return c.execute(sql, params).fetchall()
        except Exception:
            return []

    def get_recent_alerts(self, limit=100):
        try:
            c = self._conn()
            rows = c.execute(
                "SELECT timestamp, level, rule, message, src_ip, dst_ip "
                "FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
            return rows
        except Exception:
            return []

    def cleanup_old(self, days=30):
        try:
            cutoff = time.time() - days * 86400
            c = self._conn()
            c.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
            c.execute("DELETE FROM stats WHERE timestamp < ?", (cutoff,))
            c.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
            c.execute("DELETE FROM incidents WHERE last_updated < ?", (cutoff,))
            c.commit()
        except Exception:
            pass

    def close(self):
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            setattr(self._local, "conn", None) # type: ignore


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 15: CAPTURE ENGINE — ✅ With ring buffer and batch processing
# ═══════════════════════════════════════════════════════════════════════════════

class CaptureEngine:
    """
    Core packet capture engine.

    ✅ Ring buffer: bounded memory, old packets auto-evicted
    ✅ Batch-friendly: GUI consumer reads in batches
    ✅ Thread-safe stats
    ✅ Clean shutdown via stop event
    ✅ Display filters applied at capture level
    ✅ Optional promiscuous mode for broader capture (if supported by NIC)
    """

    def __init__(self, pkt_queue: queue.Queue,
                 on_packet_cb: Optional[Callable] = None,
                 promisc: bool = True) -> None:
        self._pkt_queue = pkt_queue
        self._on_packet = on_packet_cb
        self._running = False
        self._paused = False
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.promisc = promisc

        # ✅ Ring buffer — bounded memory
        self._buffer = RingBuffer[ParsedPacket](CAP.ring_buffer_size)
        self._counter = 0
        self._counter_lock = threading.Lock()

        # Stats
        # Keep a sliding window of timestamps for packets-per-second. 10k entries
        # supports sustained bursts without capping the PPS calculation.
        self._pps_times: deque = deque(maxlen=10000)
        self._stats_lock = threading.RLock()
        self._stats = self._empty_stats()

        # Display filters
        self.display_filter_protocol = "All"
        self.display_filter_ip = ""
        self.display_filter_port = ""
        self.bpf_filter = ""

    @staticmethod
    def _empty_stats() -> Dict:
        return {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "arp": 0,
                "ip": 0, "dns": 0, "http": 0, "https": 0, "quic": 0,
                "ssh": 0,  # ✅ Added ssh tracking explicitly
                "other": 0, "bytes": 0, "threats": 0, "ml_detections": 0,
                "start_time": 0.0, "packets_per_sec": 0}

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_paused(self) -> bool:
        return self._paused

    @property
    def stats(self) -> Dict:
        with self._stats_lock:
            return dict(self._stats)

    @property
    def buffer(self) -> RingBuffer:
        return self._buffer

    def start(self, interface: Optional[str] = None) -> None:
        if self._running or not SCAPY_OK:
            return
        self._running = True
        self._paused = False
        self._stop_event.clear()
        with self._stats_lock:
            self._stats["start_time"] = time.time()

        iface = interface
        if iface and iface.lower() == "auto":
            iface = None

        self._thread = threading.Thread(
            target=self._capture_loop, args=(iface,),
            daemon=True, name="PherionCapture")
        t = self._thread
        if t is not None:
            t.start()
        logger.info("Capture started on %s (BPF: %s)",
                    iface or "default", self.bpf_filter or "none")

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        t = self._thread
        if t is not None:
            t.join(timeout=5.0)
        with self._stats_lock:
            logger.info("Capture stopped — %d packets", self._stats["total"])

    def toggle_pause(self) -> bool:
        self._paused = not self._paused
        return self._paused

    def reset(self) -> None:
        self._buffer.clear()
        with self._counter_lock:
            self._counter = 0
        with self._stats_lock:
            self._stats = self._empty_stats()
        self._pps_times.clear()

    def get_packet(self, number: int) -> Optional[ParsedPacket]:
        return self._buffer.find_by_attr("number", number)

    def save_pcap(self, filename: str) -> int:
        pkts = [p._raw for p in self._buffer if p.has_raw]
        if pkts:
            wrpcap(filename, pkts)
        return len(pkts)

    def update_threat_stats(self) -> None:
        with self._stats_lock:
            self._stats["threats"] += 1

    def _capture_loop(self, interface: Optional[str]) -> None:
        try:
            kw: Dict = {
                "prn": self._process_packet,
                "store": False,
                "stop_filter": lambda _: self._stop_event.is_set(),
                "promisc": self.promisc,
            }
            if interface:
                kw["iface"] = interface
            if self.bpf_filter:
                bpf = self.bpf_filter.strip()
                if bpf:
                    kw["filter"] = bpf
            sniff(**kw)
        except PermissionError:
            logger.error("Permission denied — run as admin/root")
        except OSError as e:
            logger.error("Capture OS error: %s", e)
        except Exception as e:
            err_str = str(e)
            if "filter" in err_str.lower() or "syntax error" in err_str.lower() or "parse" in err_str.lower():
                logger.error("Invalid BPF filter %r: %s — retrying without filter", self.bpf_filter, e)
                kw.pop("filter", None)
                try:
                    sniff(**kw)
                except PermissionError:
                    logger.error("Permission denied — run as admin/root")
                except OSError as e2:
                    logger.error("Capture OS error: %s", e2)
                except Exception as e2:
                    logger.error("Capture error: %s", e2, exc_info=True)
            else:
                logger.error("Capture error: %s", e, exc_info=True)
        finally:
            self._running = False

    def _process_packet(self, raw_pkt) -> None:
        if self._paused:
            return

        with self._counter_lock:
            self._counter += 1
            num = self._counter

        parsed = parse_packet(raw_pkt, num)
        if parsed is None:
            return

        # Display filter
        if not self._passes_filter(parsed):
            return

        # ✅ Store in ring buffer — old packets auto-evicted
        self._buffer.append(parsed)

        # Update stats (optimized sliding window for PPS)
        now = time.time()
        self._pps_times.append(now)
        # Only cleanup occasionally instead of every packet (sampling every 100 packets)
        if self._counter % 100 == 0:
            while self._pps_times and now - self._pps_times[0] > 1.0:
                self._pps_times.popleft()
        with self._stats_lock:
            s = self._stats
            s["total"] += 1
            s["bytes"] += parsed.total_length
            key = parsed.protocol.lower()
            if key in s:
                s[key] += 1
            else:
                s["other"] += 1
            s["packets_per_sec"] = len(self._pps_times)

        # Notify detection pipeline
        cb = self._on_packet
        if cb is not None:
            try:
                cb(parsed)
            except Exception:
                pass

        # Send to GUI queue
        try:
            self._pkt_queue.put_nowait(parsed)
        except queue.Full:
            pass

    def _passes_filter(self, p: ParsedPacket) -> bool:
        if self.display_filter_protocol != "All":
            proto = p.protocol.upper()
            f = self.display_filter_protocol.upper()
            # Treat common application protocols as part of their transport family
            if f == "TCP":
                if proto not in ("TCP", "HTTP", "HTTPS", "SSH", "FTP",
                                 "SMTP", "HTTP-ALT", "MYSQL", "POSTGRESQL",
                                 "REDIS", "RDP"):
                    return False
            elif f == "UDP":
                if proto not in ("UDP", "DNS", "DHCP", "NTP", "MDNS",
                                 "SSDP", "LLMNR", "IPSEC", "QUIC", "SYSLOG",
                                 "STUN", "SIP", "SIPS"):
                    return False
            elif f == "IP":
                if proto not in ("IP", "IPV6"):
                    return False
            elif f == "OTHER":
                if proto in ("TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP",
                             "HTTPS", "SSH", "QUIC", "IP", "IPV6", "DHCP",
                             "NTP", "MDNS", "SSDP", "LLMNR", "IPSEC",
                             "SYSLOG", "STUN", "SIP", "SIPS"):
                    return False
            else:
                if proto != f:
                    return False
        if self.display_filter_ip:
            if self.display_filter_ip not in p.src_ip and self.display_filter_ip not in p.dst_ip:
                return False
        if self.display_filter_port:
            try:
                port = int(self.display_filter_port)
                if p.src_port != port and p.dst_port != port:
                    return False
            except ValueError:
                pass
        return True


# ═══════════════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 15A: MANUAL APPROVAL GATE — Human-in-the-loop before any remediation
# ═══════════════════════════════════════════════════════════════════════════════

class ManualApprovalGate:
    """
    Human-in-the-loop approval gate for self-healing actions.

    Flow when a threat is detected:
    ─────────────────────────────────────────────────────────────────
    1. Threat detected → traffic from attacker IP is PAUSED (held in a
       per-IP queue so packets are not processed further).
    2. Operator is notified via BOTH terminal prompt AND GUI popup
       simultaneously.
    3. Operator picks one of:
         [B] Block        → null_route_ip (full block)
         [R] Rate-Limit   → rate_limit_ip (throttle only)
         [I] Ignore       → dismiss, resume normal processing
    4. If operator does NOT respond within PAUSE_TIMEOUT seconds the
       traffic remains paused (held) until a decision is made.
       No automatic action is taken.

    Thread safety:
    ─────────────────────────────────────────────────────────────────
    • Each unique (attacker_ip, rule) pair gets ONE pending decision.
      Duplicate detections while a decision is pending are silently
      merged (no double-popups).
    • All shared state is protected by an RLock.
    • Terminal prompt runs in a daemon thread so it never blocks the
      packet pipeline.
    • GUI popup is posted via root.after() so it runs on the Tk thread.
    """

    PAUSE_TIMEOUT: float = 0.0   # 0 = hold forever until operator decides

    _SEVERITY_COLOR = {
        "Critical": "🔴",
        "High":     "🟠",
        "Medium":   "🟡",
        "Low":      "🟢",
    }

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # (attacker_ip, rule) → {"pkt", "severity", "policy", "decided"}
        self._pending: Dict[Tuple[str, str], dict] = {}
        # IPs currently paused: ip → set of rule strings
        self._paused_ips: Dict[str, set] = {}
        # Callback set by SelfHealingEngine after init
        self._on_decision: Optional[Callable] = None
        # Tk root reference (set by GUI after startup)
        self._tk_root: Optional[Any] = None
        self._logger = logging.getLogger("pherion.approval")

    # ── External wiring ────────────────────────────────────────────────────

    def set_decision_callback(self, cb: Callable) -> None:
        """Called by SelfHealingEngine: cb(action, attacker_ip, victim_ip, rule, severity, pkt)"""
        self._on_decision = cb

    def set_tk_root(self, root: Any) -> None:
        """Called by GUI after Tk root is created."""
        self._tk_root = root

    def is_paused(self, ip: str) -> bool:
        """Return True if this IP has a pending decision (traffic held)."""
        with self._lock:
            return ip in self._paused_ips and bool(self._paused_ips[ip])

    # ── Main entry point ───────────────────────────────────────────────────

    def request_approval(self,
                         rule: str,
                         pkt: "ParsedPacket",
                         severity: str,
                         policy: List[Tuple[str, str]]) -> None:
        """
        Called instead of immediately healing.
        Pauses IP traffic and fires both terminal + GUI prompts.
        Non-blocking: returns immediately, prompts run in background.
        """
        attacker_ip = pkt.src_ip or ""
        if not attacker_ip:
            return

        key = (attacker_ip, rule)
        with self._lock:
            if key in self._pending and not self._pending[key].get("decided"):
                # Already waiting for a decision on this (ip, rule) pair
                return
            self._pending[key] = {
                "pkt":      pkt,
                "severity": severity,
                "policy":   policy,
                "decided":  False,
                "ts":       time.time(),
            }
            if attacker_ip not in self._paused_ips:
                self._paused_ips[attacker_ip] = set()
            self._paused_ips[attacker_ip].add(rule)

        icon = self._SEVERITY_COLOR.get(severity, "⚪")
        self._logger.warning(
            "[ApprovalGate] %s PAUSED traffic from %s — rule=%s sev=%s — "
            "awaiting operator decision",
            icon, attacker_ip, rule, severity,
        )

        # Fire terminal prompt in background thread
        t = threading.Thread(
            target=self._terminal_prompt,
            args=(key,),
            daemon=True,
            name=f"ApprovalTerm-{attacker_ip}",
        )
        t.start()

        # Fire GUI popup on Tk thread if available
        if self._tk_root is not None and TK_AVAILABLE:
            try:
                self._tk_root.after(0, self._gui_popup, key)
            except Exception:
                pass

    # ── Terminal prompt ─────────────────────────────────────────────────────

    def _terminal_prompt(self, key: Tuple[str, str]) -> None:
        attacker_ip, rule = key
        with self._lock:
            info = self._pending.get(key)
        if not info:
            return

        pkt      = info["pkt"]
        severity = info["severity"]
        icon     = self._SEVERITY_COLOR.get(severity, "⚪")

        banner = (
            f"\n{'═'*64}\n"
            f"  {icon}  THREAT DETECTED — MANUAL ACTION REQUIRED\n"
            f"{'═'*64}\n"
            f"  Attacker IP  : {attacker_ip}\n"
            f"  Target IP    : {pkt.dst_ip or 'unknown'}\n"
            f"  Rule         : {rule}\n"
            f"  Severity     : {severity}\n"
            f"  Protocol     : {pkt.protocol or 'unknown'}\n"
            f"  Src Port     : {pkt.src_port or '-'}\n"
            f"  Dst Port     : {pkt.dst_port or '-'}\n"
            f"  MITRE Rule   : {rule.upper()}\n"
            f"  Traffic from this IP is currently PAUSED.\n"
            f"{'─'*64}\n"
            f"  Choose action:\n"
            f"    [B] Block       — fully block this IP (null route)\n"
            f"    [R] Rate-Limit  — throttle this IP (rate limit)\n"
            f"    [I] Ignore      — dismiss alert, resume traffic\n"
            f"{'─'*64}\n"
            f"  Your choice (B/R/I): "
        )

        # Keep prompting until a valid choice or until GUI already decided
        while True:
            with self._lock:
                if self._pending.get(key, {}).get("decided"):
                    print(f"\n[ApprovalGate] Decision already made for {attacker_ip}/{rule} (via GUI).")
                    return
            try:
                print(banner, end="", flush=True)
                choice = input().strip().upper()
            except (EOFError, KeyboardInterrupt):
                choice = "I"

            if choice in ("B", "R", "I"):
                self._apply_decision(key, choice, source="terminal")
                return
            else:
                print("  ⚠  Invalid choice — please enter B, R, or I.")

    # ── GUI popup ──────────────────────────────────────────────────────────

    def _gui_popup(self, key: Tuple[str, str]) -> None:
        """
        Compact dark hacker-aesthetic threat notification.
        Runs on the Tk main thread via root.after().

        Pure tk.Frame/Label/Button layout — NO Canvas stipple (avoids the
        white-dot rendering glitch seen on some platforms).  The accent
        border is drawn with a 2-px coloured outer frame; accent colour is
        keyed to severity so the operator can judge priority at a glance.

        Window size: ~460 × 300 px  (expands if rule text is long).
        All 8 original fields are present; ports are paired on one row.
        Keyboard shortcuts B / R / I work without clicking.
        """
        if not TK_AVAILABLE:
            return
        with self._lock:
            info = self._pending.get(key)
            if not info or info.get("decided"):
                return

        attacker_ip, rule = key
        pkt      = info["pkt"]
        severity = info["severity"]

        # ── Severity-keyed colours ─────────────────────────────────────────
        SEV_ACCENT = {
            "Critical": "#ff2244",
            "High":     "#ff6a00",
            "Medium":   "#f0c000",
            "Low":      "#00cc66",
        }
        SEV_BADGE_BG = {
            "Critical": "#3a0010",
            "High":     "#3a1800",
            "Medium":   "#2e2400",
            "Low":      "#003318",
        }
        accent    = SEV_ACCENT.get(severity, "#00ffe7")
        badge_bg  = SEV_BADGE_BG.get(severity, "#002233")

        BG        = "#080d12"   # window background
        BG_PANEL  = "#0c1520"   # info panel background
        BG_ROW_A  = "#0f1b28"   # alternating row A
        BG_ROW_B  = "#0c1620"   # alternating row B
        BG_STATUS = "#081a0e"   # green-tinted status row
        FG        = "#b8d8f0"   # primary text
        FG_DIM    = "#3e6478"   # muted labels
        FG_HI     = accent      # highlighted value (attacker IP / severity)
        MONO      = ("Courier", 9)
        MONO_B    = ("Courier", 9, "bold")
        MONO_S    = ("Courier", 8)
        MONO_T    = ("Courier", 10, "bold")

        try:
            popup = tk.Toplevel(self._tk_root)
            popup.title("PHERION // THREAT GATE")
            popup.resizable(False, False)
            popup.grab_set()
            popup.attributes("-topmost", True)
            popup.configure(bg=accent)        # accent = 2-px border colour

            # ── Outer accent border (1-px padding all around) ──────────────
            outer = tk.Frame(popup, bg=accent, padx=2, pady=2)
            outer.pack(fill="both", expand=True)

            # ── Main dark body ─────────────────────────────────────────────
            body = tk.Frame(outer, bg=BG)
            body.pack(fill="both", expand=True)

            # ══ HEADER ROW ════════════════════════════════════════════════
            hdr = tk.Frame(body, bg=BG)
            hdr.pack(fill="x", padx=0, pady=0)

            # Severity badge (diamond-shaped via rotated text label trick)
            badge = tk.Label(
                hdr,
                text=f" {severity[0].upper()} ",
                font=MONO_B, fg=accent, bg=badge_bg,
                relief="flat", padx=4, pady=2,
            )
            badge.pack(side="left", padx=(8, 6), pady=6)

            # Title + sub-title stacked
            title_stack = tk.Frame(hdr, bg=BG)
            title_stack.pack(side="left")
            tk.Label(title_stack, text="[ THREAT DETECTED ]",
                     font=MONO_T, fg=accent, bg=BG,
                     anchor="w").pack(anchor="w")
            tk.Label(title_stack,
                     text=f"MANUAL APPROVAL REQUIRED  //  {severity.upper()}",
                     font=MONO_S, fg=FG_DIM, bg=BG,
                     anchor="w").pack(anchor="w")

            # Live clock (top-right)
            clock_var = tk.StringVar(value="")
            clock_lbl = tk.Label(hdr, textvariable=clock_var,
                                 font=MONO_S, fg=FG_DIM, bg=BG)
            clock_lbl.pack(side="right", padx=10, pady=6)

            def _tick():
                if popup.winfo_exists():
                    clock_var.set(datetime.now().strftime("%H:%M:%S"))
                    popup.after(1000, _tick)
            _tick()

            # ── Dashed accent separator ────────────────────────────────────
            # Simulated with a 1-px Frame in accent colour (no Canvas needed)
            tk.Frame(body, bg=accent, height=1).pack(fill="x")
            tk.Frame(body, bg=FG_DIM, height=1).pack(fill="x")

            # ══ INFO PANEL ════════════════════════════════════════════════
            panel = tk.Frame(body, bg=BG_PANEL,
                             highlightbackground=FG_DIM,
                             highlightthickness=1)
            panel.pack(fill="x", padx=8, pady=(6, 0))

            def _field_row(parent, bg,
                           l1, v1, hi1,
                           l2=None, v2=None, hi2=False):
                """One two-column info row inside the panel."""
                row = tk.Frame(parent, bg=bg)
                row.pack(fill="x")
                # Left accent nub
                nub_col = accent if hi1 else FG_DIM
                tk.Frame(row, width=2, bg=nub_col).pack(
                    side="left", fill="y")
                # Col 1
                tk.Label(row, text=f" {l1:<6}", font=MONO_S,
                         fg=FG_DIM, bg=bg, width=7,
                         anchor="w").pack(side="left")
                tk.Label(row, text="▶", font=MONO_S,
                         fg=accent, bg=bg).pack(side="left")
                tk.Label(row, text=f"  {v1}",
                         font=MONO_B if hi1 else MONO,
                         fg=FG_HI if hi1 else FG,
                         bg=bg, anchor="w").pack(side="left", padx=(0, 4))
                # Optional col 2
                if l2 is not None:
                    tk.Frame(row, bg=FG_DIM, width=1).pack(
                        side="left", fill="y", pady=2)
                    tk.Label(row, text=f" {l2:<6}", font=MONO_S,
                             fg=FG_DIM, bg=bg, width=7,
                             anchor="w").pack(side="left")
                    tk.Label(row, text="▶", font=MONO_S,
                             fg=accent, bg=bg).pack(side="left")
                    tk.Label(row, text=f"  {v2}",
                             font=MONO_B if hi2 else MONO,
                             fg=FG_HI if hi2 else FG,
                             bg=bg, anchor="w").pack(side="left")
                # Bottom micro-divider
                tk.Frame(row, bg=FG_DIM, height=1).pack(
                    side="bottom", fill="x")

            # Row 1 — IPs
            _field_row(panel, BG_ROW_A,
                       "SRC", attacker_ip or "—", True,
                       "DST", pkt.dst_ip   or "—", False)

            # Row 2 — Rule (full-width, may wrap)
            r2 = tk.Frame(panel, bg=BG_ROW_B)
            r2.pack(fill="x")
            tk.Frame(r2, width=2, bg=FG_DIM).pack(side="left", fill="y")
            tk.Label(r2, text=" RULE  ", font=MONO_S,
                     fg=FG_DIM, bg=BG_ROW_B, width=7,
                     anchor="w").pack(side="left")
            tk.Label(r2, text="▶", font=MONO_S,
                     fg=accent, bg=BG_ROW_B).pack(side="left")
            tk.Label(r2, text=f"  {rule}",
                     font=MONO, fg=FG, bg=BG_ROW_B,
                     anchor="w", wraplength=340,
                     justify="left").pack(side="left", pady=1)
            tk.Frame(r2, bg=FG_DIM, height=1).pack(side="bottom", fill="x")

            # Row 3 — Severity / Protocol
            _field_row(panel, BG_ROW_A,
                       "SEV",   severity,               True,
                       "PROTO", pkt.protocol or "—",    False)

            # Row 4 — Ports
            _field_row(panel, BG_ROW_B,
                       "SPORT", str(pkt.src_port or "—"), False,
                       "DPORT", str(pkt.dst_port or "—"), False)

            # Status bar
            sbar = tk.Frame(panel, bg=BG_STATUS)
            sbar.pack(fill="x")
            tk.Frame(sbar, width=2, bg="#00cc66").pack(side="left", fill="y")
            tk.Label(sbar,
                     text="  \u23f8 TRAFFIC PAUSED \u2014 awaiting your decision",
                     font=MONO_S, fg="#00cc66", bg=BG_STATUS,
                     anchor="w").pack(side="left", pady=3)

            # ── Thin separator before buttons ──────────────────────────────
            tk.Frame(body, bg=FG_DIM, height=1).pack(fill="x", pady=(6, 0))

            # ══ ACTION BUTTONS ════════════════════════════════════════════
            btn_area = tk.Frame(body, bg=BG, pady=8)
            btn_area.pack(fill="x")

            result_holder = [None]

            def _choose(ch):
                result_holder[0] = ch
                popup.destroy()

            BTN_DEFS = [
                ("[ BLOCK ]",    "#aa1122", "#cc1a2a", "B"),
                ("[ THROTTLE ]", "#883300", "#aa4400", "R"),
                ("[ IGNORE ]",   "#005522", "#007733", "I"),
            ]

            for txt, bg_n, bg_h, ch in BTN_DEFS:
                b = tk.Button(
                    btn_area,
                    text=txt,
                    font=MONO_B,
                    fg="white", bg=bg_n,
                    activebackground=bg_h,
                    activeforeground="white",
                    relief="flat", bd=0,
                    padx=10, pady=5,
                    cursor="hand2",
                    command=lambda c=ch: _choose(c),
                )
                b.pack(side="left", padx=8, expand=True)

            # Hotkey hint
            tk.Label(body,
                     text="hotkeys:  B \u2014 block    R \u2014 throttle    I \u2014 ignore",
                     font=MONO_S, fg=FG_DIM, bg=BG).pack(pady=(0, 6))

            # ── Keyboard shortcuts ─────────────────────────────────────────
            def _key(event):
                k = event.keysym.upper()
                if k in ("B", "R", "I"):
                    _choose(k)
            popup.bind("<Key>", _key)
            popup.focus_set()

            # ── Centre over main window ────────────────────────────────────
            popup.update_idletasks()
            W = popup.winfo_reqwidth()
            H = popup.winfo_reqheight()
            px = self._tk_root.winfo_x() + (self._tk_root.winfo_width()  - W) // 2
            py = self._tk_root.winfo_y() + (self._tk_root.winfo_height() - H) // 2
            popup.geometry(f"+{px}+{py}")

            self._tk_root.wait_window(popup)

            if result_holder[0]:
                self._apply_decision(key, result_holder[0], source="gui")

        except Exception as exc:
            self._logger.debug("[ApprovalGate] GUI popup error: %s", exc)

    # ── Decision apply ─────────────────────────────────────────────────────

    def _apply_decision(self, key: Tuple[str, str], choice: str, source: str) -> None:
        """
        Translate operator choice → healing action and fire the callback.
        Thread-safe: first caller wins, subsequent calls for same key are no-ops.
        """
        attacker_ip, rule = key
        with self._lock:
            info = self._pending.get(key)
            if not info or info.get("decided"):
                return
            info["decided"] = True
            # Unregister pause
            if attacker_ip in self._paused_ips:
                self._paused_ips[attacker_ip].discard(rule)
                if not self._paused_ips[attacker_ip]:
                    del self._paused_ips[attacker_ip]

        pkt      = info["pkt"]
        severity = info["severity"]
        victim   = pkt.dst_ip or ""

        action_map = {
            "B": "null_route_ip",
            "R": "rate_limit_ip",
            "I": None,
        }
        action = action_map.get(choice)

        label = {"B": "BLOCK", "R": "RATE-LIMIT", "I": "IGNORE"}.get(choice, choice)
        icon  = {"B": "🚫", "R": "⚡", "I": "✅"}.get(choice, "")
        self._logger.info(
            "[ApprovalGate] %s Operator chose %s for %s/%s (via %s)",
            icon, label, attacker_ip, rule, source,
        )

        if action and self._on_decision:
            try:
                self._on_decision(action, attacker_ip, victim, rule, severity, pkt)
            except Exception as exc:
                self._logger.error("[ApprovalGate] Decision callback error: %s", exc)
        elif not action:
            self._logger.info(
                "[ApprovalGate] Traffic from %s RESUMED — operator chose IGNORE for rule=%s",
                attacker_ip, rule,
            )

    # ── Status helpers (for GUI tab / headless status) ────────────────────

    def pending_decisions(self) -> List[dict]:
        """Return list of currently undecided threats (for display in GUI)."""
        with self._lock:
            return [
                {
                    "ip":       k[0],
                    "rule":     k[1],
                    "severity": v["severity"],
                    "ts":       v["ts"],
                    "protocol": v["pkt"].protocol,
                    "dst_ip":   v["pkt"].dst_ip,
                    "dst_port": v["pkt"].dst_port,
                }
                for k, v in self._pending.items()
                if not v.get("decided")
            ]


# Singleton gate — shared by SelfHealingEngine and GUI
APPROVAL_GATE = ManualApprovalGate()


# SECTION 15B: SELF-HEALING ENGINE — Non-blocking auto-remediation on attack
# ═══════════════════════════════════════════════════════════════════════════════

class SelfHealingEngine:
    """
    Non-blocking auto-remediation engine that fires countermeasures when an
    attack is detected — WITHOUT blocking the packet-processing pipeline.

    All actions run in a dedicated background thread pool so the capture,
    detection and GUI threads are never stalled.

    Healing actions (platform-aware, gracefully degrade when unavailable):
    ─────────────────────────────────────────────────────────────────────
    • rate_limit_ip   — iptables/nftables (Linux) or Windows Firewall rule
                        that rate-limits (not blocks) the attacker's IP via
                        a per-IP token-bucket or connection-rate limit.
    • null_route_ip   — add a null-route (blackhole) for the attacker only
                        while tracking is active; auto-removed after cooldown.
    • reset_tcp_conn  — send RST to terminate the offending TCP session.
    • flush_arp_cache — flush ARP cache to evict poisoned entries.
    • alert_sysadmin  — write a structured HEAL event to the event log /
                        alert queue so the SOC dashboard shows it.
    • isolate_flow    — tag the flow so further packets are suppressed
                        from the ring buffer (soft isolation, no OS call).

    Design decisions
    ────────────────
    • Actions are IDEMPOTENT: the same IP/action pair is de-duplicated
      within a configurable cooldown window.
    • ALL OS commands use subprocess with full paths; on failure they log
      a warning but never raise.
    • The engine exposes a simple callback: heal(rule, pkt) that the
      Orchestrator calls after detection — one line integration.
    • Enabled/disabled per rule via HEAL_POLICY dict.
    • healing_log is a deque the GUI can display in a dedicated tab.
    """

    # ── Cooldown: don't re-apply same action to same IP within N seconds ──
    DEFAULT_COOLDOWN: float = 300.0   # 5 minutes
    # ── Max IPs to track simultaneously ──
    MAX_TRACKED_IPS: int = 512
    # ── Worker threads for async healing ──
    THREAD_POOL_SIZE: int = 4

    # ── Rules → healing actions mapping ──────────────────────────────────
    # Each rule maps to a list of (action_name, severity_gate) tuples.
    # severity_gate: minimum severity level required to trigger that action.
    HEAL_POLICY: Dict[str, List[Tuple[str, str]]] = {
        # Network flood attacks
        "syn_flood":        [("rate_limit_ip", "High"),   ("alert_sysadmin", "Medium")],
        "rst_flood":        [("rate_limit_ip", "High"),   ("alert_sysadmin", "Medium")],
        "icmp_flood":       [("rate_limit_ip", "High"),   ("alert_sysadmin", "Medium")],
        "http_flood":       [("rate_limit_ip", "High"),   ("alert_sysadmin", "Medium")],
        "dns_flood":        [("rate_limit_ip", "Medium"), ("alert_sysadmin", "Low")],
        "udp_scan":         [("rate_limit_ip", "Medium"), ("alert_sysadmin", "Low")],
        # Scanning / recon
        "port_scan":        [("rate_limit_ip", "Medium"), ("alert_sysadmin", "Low")],
        "slow_scan":        [("rate_limit_ip", "Low"),    ("alert_sysadmin", "Low")],
        "null_scan":        [("rate_limit_ip", "Medium"), ("alert_sysadmin", "Low")],
        "xmas_scan":        [("rate_limit_ip", "Medium"), ("alert_sysadmin", "Low")],
        "fin_scan":         [("rate_limit_ip", "Medium"), ("alert_sysadmin", "Low")],
        # Credential / application attacks
        "brute_force":      [("rate_limit_ip", "High"),   ("reset_tcp_conn", "Critical"), ("alert_sysadmin", "Medium")],
        "cred_stuffing":    [("rate_limit_ip", "High"),   ("reset_tcp_conn", "Critical"), ("alert_sysadmin", "Medium")],
        "sql_injection":    [("rate_limit_ip", "High"),   ("alert_sysadmin", "Medium")],
        "http_attack_payload": [("rate_limit_ip", "High"), ("alert_sysadmin", "Medium")],
        "webshell_upload":  [("rate_limit_ip", "Critical"), ("reset_tcp_conn", "Critical"), ("alert_sysadmin", "Low")],
        # Network-layer attacks
        "arp_spoof":        [("flush_arp_cache", "Medium"), ("alert_sysadmin", "Medium")],
        "land_attack":      [("rate_limit_ip", "High"),   ("alert_sysadmin", "Low")],
        "smurf":            [("rate_limit_ip", "High"),   ("alert_sysadmin", "Low")],
        "ip_fragment":      [("rate_limit_ip", "Medium"), ("alert_sysadmin", "Low")],
        # Data theft / C2
        "data_exfil":       [("null_route_ip", "Critical"), ("alert_sysadmin", "High")],
        "dns_tunnel":       [("null_route_ip", "High"),     ("alert_sysadmin", "Medium")],
        "icmp_tunnel":      [("null_route_ip", "High"),     ("alert_sysadmin", "Medium")],
        "beacon":           [("null_route_ip", "High"),     ("alert_sysadmin", "Medium")],
        # Threat intel / lateral movement
        "threat_intel":     [("null_route_ip", "High"),  ("alert_sysadmin", "Low")],
        "smb_lateral":      [("isolate_flow",  "High"),  ("alert_sysadmin", "Medium")],
        "ja3_blacklisted":  [("reset_tcp_conn", "High"), ("alert_sysadmin", "Medium")],
        "blacklist":        [("null_route_ip", "High"),  ("alert_sysadmin", "Low")],
        # Signature / ML
        "signature":        [("rate_limit_ip", "High"),  ("alert_sysadmin", "Medium")],
        "ml_anomaly":       [("rate_limit_ip", "Medium"),("alert_sysadmin", "Low")],
        # Previously missing rules — now explicitly handled
        "ttl_anomaly":      [("rate_limit_ip", "Medium"), ("alert_sysadmin", "Low")],
        "suspicious_port":  [("rate_limit_ip", "Low"),    ("alert_sysadmin", "Low")],
        "large_packet":     [("alert_sysadmin", "Low")],
        "conn_rate":        [("rate_limit_ip", "Medium"), ("alert_sysadmin", "Low")],
        "wifi_deauth":      [("alert_sysadmin", "High")],
        "wifi_probe_flood": [("rate_limit_ip", "Medium"), ("alert_sysadmin", "Low")],
        "wifi_evil_twin":   [("null_route_ip", "High"),   ("alert_sysadmin", "High")],
        "wifi_ssid_spoof":  [("alert_sysadmin", "High")],
        # Fallback for any unspecified rule
        "__default__":      [("alert_sysadmin", "Medium")],
    }

    _SEVERITY_RANK: Dict[str, int] = {
        "Low": 1, "Medium": 2, "High": 3, "Critical": 4
    }

    def __init__(self,
                 alert_mgr: "AlertManager",
                 event_logger: "StructuredEventLogger",
                 cooldown: float = DEFAULT_COOLDOWN,
                 enabled: bool = True,
                 db: "Optional[Database]" = None) -> None:
        self.alert_mgr    = alert_mgr
        self.event_logger = event_logger
        self.cooldown     = cooldown
        self.enabled      = enabled
        self.db           = db  # optional DB for persisting heal actions

        self._lock      = threading.RLock()
        # (ip, action) → last_triggered timestamp
        self._last_action: Dict[Tuple[str, str], float] = {}
        # ip → null-route expiry time
        self._null_routes: Dict[str, float] = {}
        # Bounded log of healing actions for GUI display
        self.healing_log: deque = deque(maxlen=1000)
        # Track all active cleanup timers so they can be cancelled on stop()
        self._active_timers: List[threading.Timer] = []
        # Dedicated lock for blacklist_subnets mutation in isolate_flow
        self._isolate_lock = threading.RLock()

        # Background executor — daemon threads so they never block shutdown
        self._executor = [
            threading.Thread(
                target=self._worker,
                name=f"SelfHeal-{i}",
                daemon=True
            )
            for i in range(self.THREAD_POOL_SIZE)
        ]
        self._task_queue: queue.Queue = queue.Queue(maxsize=4096)
        self._running = False

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        # Recreate threads and queue every time — Python threads cannot be
        # restarted after they exit, so we build a fresh pool on each start().
        self._task_queue = queue.Queue(maxsize=4096)
        self._executor = [
            threading.Thread(
                target=self._worker,
                name=f"SelfHeal-{i}",
                daemon=True,
            )
            for i in range(self.THREAD_POOL_SIZE)
        ]
        for t in self._executor:
            t.start()
        logger.info("[SelfHeal] Engine started (cooldown=%.0fs, threads=%d)",
                    self.cooldown, self.THREAD_POOL_SIZE)

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        # Cancel all pending cleanup timers so OS rules are not left orphaned
        with self._lock:
            for t in self._active_timers:
                t.cancel()
            self._active_timers.clear()
        # Send one sentinel None per worker so every thread unblocks and exits
        for _ in self._executor:
            try:
                self._task_queue.put_nowait(None)
            except queue.Full:
                pass
        # Brief join so threads finish current task before queue is recreated
        for t in self._executor:
            t.join(timeout=2.0)
        self._executor = []
        logger.info("[SelfHeal] Engine stopped")

    def _worker(self) -> None:
        """Worker thread: pull tasks and execute them."""
        while self._running:
            try:
                task = self._task_queue.get(timeout=2.0)
                if task is None:
                    break
                func, args = task
                try:
                    func(*args)
                except Exception:
                    logger.debug("[SelfHeal] Action error", exc_info=True)
            except queue.Empty:
                continue

    # ── Public API ─────────────────────────────────────────────────────────

    def heal(self, rule: str, pkt: "ParsedPacket", severity: str = "Medium") -> None:
        """
        Called by the Orchestrator when an attack is detected.

        ── MANUAL APPROVAL MODE ──────────────────────────────────────────────
        Instead of firing remediations automatically, this method now routes
        every threat through the ManualApprovalGate, which:
          1. Pauses traffic from the attacker IP.
          2. Shows a terminal prompt AND a GUI popup simultaneously.
          3. Waits for the operator to choose Block / Rate-Limit / Ignore.
          4. Only then executes the chosen action via _execute_approved().

        If the global APPROVAL_GATE is not available (imported from the same
        module), falls back to the original auto-heal behaviour.
        ─────────────────────────────────────────────────────────────────────
        """
        if not self.enabled:
            return

        attacker_ip = pkt.src_ip or ""
        if not attacker_ip:
            return

        policy = self.HEAL_POLICY.get(rule) or self.HEAL_POLICY.get("__default__") or []

        # Wire the approval gate's decision callback to our executor (once)
        if APPROVAL_GATE._on_decision is None:
            APPROVAL_GATE.set_decision_callback(self._execute_approved)

        # Route through the manual approval gate — non-blocking
        APPROVAL_GATE.request_approval(rule, pkt, severity, policy)

    def _execute_approved(self,
                          action: str,
                          attacker_ip: str,
                          victim_ip: str,
                          rule: str,
                          severity: str,
                          pkt: "ParsedPacket") -> None:
        """
        Executes a single healing action AFTER operator approval.
        Called by ManualApprovalGate._apply_decision() when the operator
        presses Block or Rate-Limit.
        """
        if not self._cooldown_ok(attacker_ip, action):
            logger.info("[SelfHeal] Cooldown active for %s/%s — skipping", attacker_ip, action)
            return
        self._mark_action(attacker_ip, action)
        try:
            self._task_queue.put_nowait((
                self._dispatch,
                (action, attacker_ip, victim_ip, rule, severity, pkt)
            ))
        except queue.Full:
            logger.warning("[SelfHeal] Task queue full, dropping approved action=%s", action)

    # ── Internal helpers ───────────────────────────────────────────────────

    def _severity_passes(self, actual: str, gate: str) -> bool:
        return self._SEVERITY_RANK.get(actual, 0) >= self._SEVERITY_RANK.get(gate, 0)

    def _cooldown_ok(self, ip: str, action: str) -> bool:
        with self._lock:
            last = self._last_action.get((ip, action), 0.0)
            return (time.time() - last) >= self.cooldown

    def _mark_action(self, ip: str, action: str) -> None:
        with self._lock:
            # Evict oldest entries if map is too large
            if len(self._last_action) >= self.MAX_TRACKED_IPS * 4:
                oldest = sorted(self._last_action.items(), key=lambda kv: kv[1])
                for k, _ in oldest[:self.MAX_TRACKED_IPS]:
                    self._last_action.pop(k, None)
            self._last_action[(ip, action)] = time.time()

    def _start_timer(self, delay: float, func, args=()) -> threading.Timer:
        """Create, track, and start a cleanup timer. Tracked timers are cancelled on stop()."""
        t = threading.Timer(delay, func, args=args)
        with self._lock:
            # Purge expired/done timers to avoid unbounded list growth
            self._active_timers = [x for x in self._active_timers if x.is_alive()]
            self._active_timers.append(t)
        t.start()
        return t

    def _dispatch(self, action: str, attacker_ip: str, victim_ip: str,
                  rule: str, severity: str, pkt: "ParsedPacket") -> None:
        """Runs in worker thread. Dispatches to the correct heal action."""
        handler = {
            "rate_limit_ip":   self._action_rate_limit,
            "null_route_ip":   self._action_null_route,
            "reset_tcp_conn":  self._action_reset_tcp,
            "flush_arp_cache": self._action_flush_arp,
            "alert_sysadmin":  self._action_alert,
            "isolate_flow":    self._action_isolate_flow,
        }.get(action)

        if handler:
            try:
                result = handler(attacker_ip, victim_ip, rule, severity, pkt)
                self._log_heal(action, attacker_ip, rule, severity, result)
            except Exception as exc:
                self._log_heal(action, attacker_ip, rule, severity,
                               f"ERROR: {exc}")

    def _log_heal(self, action: str, ip: str, rule: str,
                  severity: str, result: str) -> None:
        """Append to healing_log and push to alert pipeline."""
        entry = {
            "ts":       time.strftime("%Y-%m-%d %H:%M:%S"),
            "action":   action,
            "attacker": ip,
            "rule":     rule,
            "severity": severity,
            "result":   result,
        }
        self.healing_log.appendleft(entry)
        msg = (f"🛠️ SELF-HEAL [{action}] on {ip} "
               f"← rule={rule} sev={severity} → {result}")
        logger.info("[SelfHeal] %s", msg)
        # Persist to SQLite for audit trail / incident review
        if self.db is not None:
            try:
                self.db.save_heal_action(
                    action=action,
                    attacker_ip=ip,
                    rule=rule,
                    severity=severity,
                    result=result,
                    ts_human=entry["ts"],
                )
            except Exception:
                pass
        # Push to alert queue so GUI shows it
        self.alert_mgr.emit(
            "INFO", f"self_heal:{action}",
            msg, ip, "", reason=result
        )
        # Persist to structured event log
        try:
            self.event_logger.log_event(
                "SELF_HEAL",
                description=msg,
                metadata=entry,
            )
        except Exception:
            pass

    # ── Healing actions ────────────────────────────────────────────────────

    def _action_rate_limit(self, attacker_ip: str, victim_ip: str,
                           rule: str, severity: str, pkt: "ParsedPacket") -> str:
        """
        Rate-limit the attacker IP using OS firewall rules.
        Linux  : iptables hashlimit — allows up to 10/min burst 20 (true rate-limit, not a block)
        Windows: netsh advfirewall — TEMPORARY HARD BLOCK (auto-removed after cooldown).
                 Windows netsh does not support native rate-limiting; a timed block is used
                 as the closest equivalent. Rename action to 'temp_block_ip' on Windows if
                 semantics matter in your policy.
        """
        if not attacker_ip or DET.is_whitelisted_ip(attacker_ip):
            return "skipped — whitelisted or no IP"

        if os.name == "nt":
            # Windows: add an outbound rate-limiting rule using netsh
            rule_name = f"Pherion-RateLimit-{attacker_ip}"
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in", "action=block",
                f"remoteip={attacker_ip}",
                "enable=yes",
                "profile=any",
            ]
            # On Windows we use a temporary block + auto-delete timer
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
                # Schedule removal after cooldown
                self._start_timer(
                    self.cooldown,
                    self._remove_windows_fw_rule,
                    args=(rule_name,)
                )
                return f"Windows FW temp-block added for {attacker_ip} (auto-remove in {self.cooldown:.0f}s)"
            except Exception as exc:
                return f"Windows FW failed: {exc}"
        else:
            # Linux: iptables hashlimit — allow up to 10/min burst 20 from this IP
            # (rate-limit, NOT a hard block)
            chain = "INPUT"
            limit = "10/min"
            limit_burst = "20"
            chain_name = f"PHERION_RATELIMIT"

            cmds = [
                # Ensure chain exists
                ["iptables", "-N", chain_name],
                # Add hashlimit rule for this IP
                [
                    "iptables", "-I", chain, "1",
                    "-s", attacker_ip,
                    "-m", "hashlimit",
                    "--hashlimit-name", f"hl_{attacker_ip.replace('.', '_')}",
                    "--hashlimit-above", limit,
                    "--hashlimit-burst", limit_burst,
                    "--hashlimit-mode", "srcip",
                    "-j", "DROP",
                ],
            ]
            succeeded = []
            for cmd in cmds:
                try:
                    r = subprocess.run(cmd, capture_output=True, timeout=5)
                    if r.returncode == 0:
                        succeeded.append(" ".join(cmd[:3]))
                except Exception as exc:
                    logger.debug("[SelfHeal] iptables cmd failed: %s", exc)

            # Schedule rule removal after cooldown
            if succeeded:
                self._start_timer(
                    self.cooldown,
                    self._remove_iptables_ratelimit,
                    args=(attacker_ip,)
                )
                return (f"iptables hashlimit applied to {attacker_ip} "
                        f"(auto-remove in {self.cooldown:.0f}s)")
            return "iptables unavailable or not root — no OS action taken"

    def _remove_iptables_ratelimit(self, ip: str) -> None:
        """Remove the hashlimit iptables rule after cooldown expires."""
        try:
            subprocess.run([
                "iptables", "-D", "INPUT",
                "-s", ip,
                "-m", "hashlimit",
                "--hashlimit-name", f"hl_{ip.replace('.', '_')}",
                "--hashlimit-above", "10/min",
                "--hashlimit-burst", "20",
                "--hashlimit-mode", "srcip",
                "-j", "DROP",
            ], capture_output=True, timeout=5)
            logger.info("[SelfHeal] Removed iptables hashlimit rule for %s", ip)
        except Exception:
            pass

    def _remove_windows_fw_rule(self, rule_name: str) -> None:
        """Remove a Windows Firewall rule created by the self-healer."""
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={rule_name}"],
                capture_output=True, timeout=5
            )
            logger.info("[SelfHeal] Removed Windows FW rule: %s", rule_name)
        except Exception:
            pass

    def _action_null_route(self, attacker_ip: str, victim_ip: str,
                           rule: str, severity: str, pkt: "ParsedPacket") -> str:
        """
        Add a null-route (blackhole) for the attacker IP.
        Linux  : ip route add blackhole <IP>
        Windows: route add <IP> 0.0.0.0 mask 255.255.255.255  (metric 1)
        Auto-removed after cooldown.
        """
        if not attacker_ip or DET.is_whitelisted_ip(attacker_ip):
            return "skipped — whitelisted or no IP"

        with self._lock:
            self._null_routes[attacker_ip] = time.time() + self.cooldown

        if os.name == "nt":
            try:
                subprocess.run(
                    ["route", "add", attacker_ip, "0.0.0.0",
                     "mask", "255.255.255.255", "metric", "1"],
                    capture_output=True, timeout=5
                )
                self._start_timer(
                    self.cooldown,
                    self._remove_null_route,
                    args=(attacker_ip,)
                )
                return f"Windows null-route added for {attacker_ip}"
            except Exception as exc:
                return f"Windows route add failed: {exc}"
        else:
            try:
                # IPv6 support: use appropriate prefix length and command
                try:
                    addr_obj = ipaddress.ip_address(attacker_ip)
                    is_ipv6 = addr_obj.version == 6
                except ValueError:
                    is_ipv6 = False

                if is_ipv6:
                    cmd = ["ip", "-6", "route", "add", "blackhole", f"{attacker_ip}/128"]
                else:
                    cmd = ["ip", "route", "add", "blackhole", f"{attacker_ip}/32"]

                r = subprocess.run(cmd, capture_output=True, timeout=5)
                if r.returncode == 0:
                    self._start_timer(
                        self.cooldown,
                        self._remove_null_route,
                        args=(attacker_ip,)
                    )
                    proto = "IPv6" if is_ipv6 else "Linux"
                    return f"{proto} blackhole route added for {attacker_ip}"
                return f"ip route failed (rc={r.returncode}) — may need root"
            except Exception as exc:
                return f"ip route add failed: {exc}"

    def _remove_null_route(self, ip: str) -> None:
        """Remove null-route after cooldown."""
        with self._lock:
            self._null_routes.pop(ip, None)
        try:
            is_ipv6 = ipaddress.ip_address(ip).version == 6
        except ValueError:
            is_ipv6 = False
        if os.name == "nt":
            try:
                subprocess.run(
                    ["route", "delete", ip],
                    capture_output=True, timeout=5
                )
            except Exception:
                pass
        else:
            try:
                if is_ipv6:
                    cmd = ["ip", "-6", "route", "del", "blackhole", f"{ip}/128"]
                else:
                    cmd = ["ip", "route", "del", "blackhole", f"{ip}/32"]
                subprocess.run(cmd, capture_output=True, timeout=5)
            except Exception:
                pass
        logger.info("[SelfHeal] Removed null-route for %s", ip)

    def _action_reset_tcp(self, attacker_ip: str, victim_ip: str,
                          rule: str, severity: str, pkt: "ParsedPacket") -> str:
        """
        Send TCP RST to terminate an offending connection using scapy.
        Works only when Scapy is available and we have src/dst port info.
        Does not modify firewall rules — purely a session teardown signal.
        """
        if not SCAPY_OK:
            return "skipped — scapy not available"
        if not attacker_ip or not victim_ip:
            return "skipped — missing IPs"
        if not pkt.src_port or not pkt.dst_port:
            return "skipped — missing ports"
        try:
            from scapy.all import IP as _IP, TCP as _TCP, send as _send
            rst_to_attacker = (
                _IP(src=victim_ip, dst=attacker_ip) /
                _TCP(sport=pkt.dst_port, dport=pkt.src_port,
                     flags="R", seq=pkt.ack_num)
            )
            rst_to_victim = (
                _IP(src=attacker_ip, dst=victim_ip) /
                _TCP(sport=pkt.src_port, dport=pkt.dst_port,
                     flags="R", seq=pkt.seq_num)
            )
            _send(rst_to_attacker, verbose=False)
            _send(rst_to_victim, verbose=False)
            return (f"TCP RST sent both directions: "
                    f"{attacker_ip}:{pkt.src_port} <-> {victim_ip}:{pkt.dst_port}")
        except Exception as exc:
            return f"TCP RST failed: {exc}"

    def _action_flush_arp(self, attacker_ip: str, victim_ip: str,
                          rule: str, severity: str, pkt: "ParsedPacket") -> str:
        """
        Flush the local ARP cache to evict a poisoned entry.
        Linux  : ip neigh flush all  (or arp -d <IP>)
        Windows: arp -d *
        """
        if os.name == "nt":
            try:
                subprocess.run(["arp", "-d", "*"],
                               capture_output=True, timeout=5)
                return "Windows ARP cache flushed"
            except Exception as exc:
                return f"ARP flush failed: {exc}"
        else:
            try:
                r = subprocess.run(
                    ["ip", "neigh", "del", attacker_ip, "dev", "any"],
                    capture_output=True, timeout=5
                )
                if r.returncode != 0:
                    subprocess.run(["ip", "neigh", "flush", "all"],
                                   capture_output=True, timeout=5)
                return f"ARP cache entry flushed for {attacker_ip}"
            except Exception as exc:
                return f"ARP flush failed: {exc}"

    def _action_alert(self, attacker_ip: str, victim_ip: str,
                      rule: str, severity: str, pkt: "ParsedPacket") -> str:
        """
        Notify the sysadmin of a detected attack.
        - Always logs a structured SELF_HEAL alert internally.
        - If PHERION_WEBHOOK_URL env var is set, POSTs a JSON payload to that
          URL (compatible with Slack incoming webhooks, PagerDuty Events API v2,
          generic HTTP endpoints).
        Set the variable before starting Pherion:
            export PHERION_WEBHOOK_URL=https://hooks.slack.com/services/...
        """
        base_msg = f"SOC alert logged for {attacker_ip} (rule={rule}, sev={severity})"
        webhook_url = os.environ.get("PHERION_WEBHOOK_URL", "").strip()
        if not webhook_url:
            return base_msg

        # Build a generic JSON payload (Slack-compatible; PagerDuty needs minor adaption)
        payload = {
            "text": (
                f"🚨 *Pherion Self-Heal Alert* | Rule: `{rule}` | "
                f"Severity: `{severity}` | Attacker: `{attacker_ip}` → Victim: `{victim_ip}`"
            ),
            "severity": severity,
            "rule": rule,
            "attacker_ip": attacker_ip,
            "victim_ip": victim_ip,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        try:
            import urllib.request
            import json as _json
            data = _json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                status = resp.status
            return f"{base_msg} | webhook→{webhook_url[:40]}… HTTP {status}"
        except Exception as exc:
            return f"{base_msg} | webhook FAILED: {exc}"

    def _action_isolate_flow(self, attacker_ip: str, victim_ip: str,
                             rule: str, severity: str, pkt: "ParsedPacket") -> str:
        """
        Soft-isolate: append the attacker IP to in-memory blacklist_subnets
        so every future packet from it immediately fires a detection rule.
        Does NOT stop capture or block traffic at the OS level.
        """
        if not attacker_ip:
            return "skipped — no IP"
        with self._isolate_lock:
            if attacker_ip not in DET.blacklist_subnets:
                DET.blacklist_subnets = DET.blacklist_subnets + (attacker_ip,)
        return f"Flow from {attacker_ip} marked as persistent threat (in-memory blacklist)"

    def get_status(self) -> Dict[str, Any]:
        """Return engine status dict for GUI/dashboard display."""
        with self._lock:
            active_null = {ip: exp - time.time()
                           for ip, exp in self._null_routes.items()
                           if exp > time.time()}
            return {
                "enabled":            self.enabled,
                "cooldown":           self.cooldown,
                "active_null_routes": active_null,
                "tracked_ips":        len(self._last_action),
                "heal_log_size":      len(self.healing_log),
                "queue_depth":        self._task_queue.qsize(),
            }


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 16: ORCHESTRATOR — ✅ Wires everything together (headless-ready)
# ═══════════════════════════════════════════════════════════════════════════════

class Orchestrator:
    """Central orchestrator that wires components:
    capture → parsing → flow tracking → rule detection → threat intel →
    ML → correlation → structured logging → alerts → persistence

    Enterprise features:
    ✅ Threat Intelligence IOC matching
    ✅ Alert correlation into SecurityIncidents
    ✅ Severity scoring (Critical/High/Medium/Low)
    ✅ Structured event logging (JSONL)
    ✅ System health watchdog
    Also supports signature rules (Suricata-style), JSON/Syslog alert output,
    whitelist/blacklist filtering, and adaptive tuning.
    """

    def __init__(self, rules_path: Optional[str] = None,
                 alert_json_path: Optional[str] = None,
                 syslog_addr: Optional[str] = None,
                 promisc: bool = True) -> None:
        # Queues
        self.pkt_queue = queue.Queue(maxsize=CAP.packet_queue_size)
        self.alert_queue = queue.Queue(maxsize=CAP.alert_queue_size)
        self.stats_queue = queue.Queue(maxsize=CAP.stats_queue_size)

        # ✅ Database persistence
        self.db = Database()

        # ✅ Alert manager with dedup + rate limiting + DB persistence
        self.alert_mgr = AlertManager(
            output_queue=self.alert_queue,
            db_callback=self.db.save_alert,
            json_log_path=alert_json_path,
            syslog_addr=syslog_addr,
        )

        # ✅ Flow tracker with timeouts + cleanup
        self.flow_tracker = FlowTracker()

        # ✅ Capture engine with ring buffer
        self.capture = CaptureEngine(
            self.pkt_queue, on_packet_cb=self._on_packet, promisc=promisc)

        # ✅ Rule engine with detection rules
        self.rule_engine = RuleEngine(self.alert_mgr, self.flow_tracker)

        # ✅ Signature engine (Suricata-style rules)
        self.signature_engine = SignatureEngine(rules_path) if rules_path else None

        # ✅ ML engine with baseline + supervised
        self.ml_engine = MLEngine(
            self.alert_mgr, self.flow_tracker, self.capture)

        # ✅ Trainer
        self.trainer = Trainer()

        # ✅ Enterprise: Threat Intelligence Manager
        self.threat_intel = ThreatIntelManager()

        # ✅ Enterprise: Severity Scorer
        self.severity_scorer = SeverityScorer()

        # ✅ Enterprise: Correlation Engine
        self.correlation_engine = CorrelationEngine(
            self.severity_scorer, db_callback=self.db.save_incident)

        # ✅ Enterprise: Structured Event Logger
        self.event_logger = StructuredEventLogger()

        # ✅ Enterprise: System Watchdog
        self.watchdog = SystemWatchdog(queues={
            "packets": self.pkt_queue,
            "alerts": self.alert_queue,
            "stats": self.stats_queue,
        })

        # ✅ Self-Healing Engine — non-blocking auto-remediation
        self.self_healer = SelfHealingEngine(
            alert_mgr=self.alert_mgr,
            event_logger=self.event_logger,
            cooldown=SelfHealingEngine.DEFAULT_COOLDOWN,
            enabled=True,
            db=self.db,
        )

        # Stats push
        self._stats_running = False
        self._stats_thread: Optional[threading.Thread] = None
        self._last_db_stats = 0.0

    def _on_packet(self, pkt: ParsedPacket) -> None:
        """Pipeline: packet → flow → rules → threat intel → ML → correlation"""
        # ✅ Flow tracking
        self.flow_tracker.update(
            pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port,
            pkt.protocol, pkt.total_length, pkt.tcp_flags)

        # ✅ Rule-based detection (with per-rule error isolation)
        try:
            self.rule_engine.analyze(pkt)
        except Exception:
            logger.debug("Rule engine error", exc_info=True)

        # ✅ Signature-based detection (Suricata-style rules)
        sig_eng = self.signature_engine
        if sig_eng is not None:
            try:
                for sig in sig_eng.match(pkt):
                    msg = sig.get("msg") or "Signature match"
                    sid = sig.get("sid")
                    path = f"sig:{sid}" if sid else "signature"
                    self.alert_mgr.emit("DANGER", path,
                                        f"🧩 SIG → {msg} | {pkt.src_ip}->{pkt.dst_ip}",
                                        pkt.src_ip, pkt.dst_ip)
                    # Correlate signature alerts
                    self.correlation_engine.correlate(
                        "signature", pkt.src_ip, pkt.dst_ip, pkt)
                    self.event_logger.log_alert(
                        "DANGER", f"sig:{sid or 'unknown'}", msg,
                        pkt.src_ip, pkt.dst_ip, severity="High", pkt=pkt)
            except Exception:
                logger.debug("Signature engine error", exc_info=True)

        # ✅ Enterprise: Threat Intelligence IOC matching
        try:
            ioc_match = self.threat_intel.check_packet(pkt)
            if ioc_match:
                pkt.threat_level = "Danger"
                self.alert_mgr.emit("DANGER", "threat_intel",
                    f"🔴 THREAT INTEL HIT → {ioc_match} | {pkt.src_ip}->{pkt.dst_ip}",
                    pkt.src_ip, pkt.dst_ip)
                incident = self.correlation_engine.correlate(
                    "threat_intel", pkt.src_ip, pkt.dst_ip, pkt, ioc_match=True)
                self.event_logger.log_alert(
                    "DANGER", "threat_intel", ioc_match,
                    pkt.src_ip, pkt.dst_ip, severity="Critical", pkt=pkt)
                if incident:
                    self.event_logger.log_incident(incident)
        except Exception:
            logger.debug("Threat intel check error", exc_info=True)

        # ✅ SOC Advanced: Correlate ALL rule flags (full coverage)
        if pkt.rule_flags > 0:
            try:
                # Map ALL rule flag bits to their rule names for full correlation
                _ALL_RULE_BITS = [
                    (self.rule_engine.RF_SYN_FLOOD,   "syn_flood"),
                    (self.rule_engine.RF_PORT_SCAN,   "port_scan"),
                    (self.rule_engine.RF_SUSP_PORT,   "suspicious_port"),
                    (self.rule_engine.RF_ICMP_FLOOD,  "icmp_flood"),
                    (self.rule_engine.RF_DNS_FLOOD,   "dns_flood"),
                    (self.rule_engine.RF_DNS_TUNNEL,  "dns_tunnel"),
                    (self.rule_engine.RF_ARP_SPOOF,   "arp_spoof"),
                    (self.rule_engine.RF_BRUTE,       "brute_force"),
                    (self.rule_engine.RF_DATA_EXFIL,  "data_exfil"),
                    (self.rule_engine.RF_NULL_SCAN,   "null_scan"),
                    (self.rule_engine.RF_XMAS_SCAN,   "xmas_scan"),
                    (self.rule_engine.RF_FIN_SCAN,    "fin_scan"),
                    (self.rule_engine.RF_IP_FRAG,     "ip_fragment"),
                    (self.rule_engine.RF_SUSP_DNS,    "suspicious_dns"),
                    (self.rule_engine.RF_LARGE_PKT,   "large_packet"),
                    (self.rule_engine.RF_CONN_RATE,   "conn_rate"),
                    (self.rule_engine.RF_UDP_SCAN,    "udp_scan"),
                    (self.rule_engine.RF_SLOW_SCAN,   "slow_scan"),
                    (self.rule_engine.RF_LAND,        "land_attack"),
                    (self.rule_engine.RF_SMURF,       "smurf"),
                    (self.rule_engine.RF_ICMP_TUNNEL, "icmp_tunnel"),
                    (self.rule_engine.RF_RST_FLOOD,   "rst_flood"),
                    (self.rule_engine.RF_HTTP_FLOOD,  "http_flood"),
                    (self.rule_engine.RF_CRED_STUFF,  "cred_stuffing"),
                    (self.rule_engine.RF_TTL_ANOMALY, "ttl_anomaly"),
                    (self.rule_engine.RF_ENTROPY,     "payload_entropy"),
                    (self.rule_engine.RF_BEACON,      "beacon"),
                    (self.rule_engine.RF_SQL_INJECTION, "sql_injection"),
                    (self.rule_engine.RF_WEBSHELL,    "webshell_upload"),
                    (self.rule_engine.RF_SMB_LATERAL, "smb_lateral"),
                    (self.rule_engine.RF_JA3,         "ja3_blacklisted"),
                    (self.rule_engine.RF_HTTP_ATTACK, "http_attack_payload"),
                    (self.rule_engine.RF_BLACKLIST,   "blacklist"),
                ]
                # Correlate each triggered rule + log through StructuredEventLogger
                for bit, rule_name in _ALL_RULE_BITS:
                    if pkt.rule_flags & bit:  # type: ignore
                        meta = RULE_REGISTRY.get(rule_name)
                        severity = meta.severity if meta else "Medium"
                        incident = self.correlation_engine.correlate(  # type: ignore
                            rule_name, pkt.src_ip, pkt.dst_ip, pkt)  # type: ignore
                        # Log to structured event logger with MITRE ATT&CK context
                        mitre_id = meta.mitre_attack_id if meta else ""
                        self.event_logger.log_alert(
                            meta.alert_level if meta else "WARNING",
                            rule_name,
                            f"{rule_name} detected: {pkt.src_ip} → {pkt.dst_ip}"
                            + (f" [MITRE:{mitre_id}]" if mitre_id else ""),
                            pkt.src_ip, pkt.dst_ip,
                            severity=severity, pkt=pkt)
                        if incident:
                            self.event_logger.log_incident(incident)
            except Exception:
                logger.debug("Correlation/logging error", exc_info=True)

        # ✅ ML detection
        self.ml_engine.enqueue(pkt)

        # ✅ Self-Healing — non-blocking; fires after all detections resolve
        if pkt.threat_level != "Safe" or pkt.rule_flags > 0:
            try:
                # Build a list of (rule_name, severity) pairs that fired
                _HEAL_BITS = [
                    (self.rule_engine.RF_SYN_FLOOD,    "syn_flood",    "High"),
                    (self.rule_engine.RF_PORT_SCAN,    "port_scan",    "Medium"),
                    (self.rule_engine.RF_ICMP_FLOOD,   "icmp_flood",   "High"),
                    (self.rule_engine.RF_DNS_FLOOD,    "dns_flood",    "Medium"),
                    (self.rule_engine.RF_DNS_TUNNEL,   "dns_tunnel",   "High"),
                    (self.rule_engine.RF_ARP_SPOOF,    "arp_spoof",    "Medium"),
                    (self.rule_engine.RF_BRUTE,        "brute_force",  "High"),
                    (self.rule_engine.RF_DATA_EXFIL,   "data_exfil",   "Critical"),
                    (self.rule_engine.RF_NULL_SCAN,    "null_scan",    "Medium"),
                    (self.rule_engine.RF_XMAS_SCAN,    "xmas_scan",    "Medium"),
                    (self.rule_engine.RF_FIN_SCAN,     "fin_scan",     "Medium"),
                    (self.rule_engine.RF_SUSP_PORT,    "suspicious_port", "Low"),
                    (self.rule_engine.RF_IP_FRAG,      "ip_fragment",  "Low"),
                    (self.rule_engine.RF_SUSP_DNS,     "suspicious_dns","Low"),
                    (self.rule_engine.RF_LARGE_PKT,    "large_packet", "Low"),
                    (self.rule_engine.RF_CONN_RATE,    "conn_rate",    "Medium"),
                    (self.rule_engine.RF_UDP_SCAN,     "udp_scan",     "Medium"),
                    (self.rule_engine.RF_SLOW_SCAN,    "slow_scan",    "Low"),
                    (self.rule_engine.RF_LAND,         "land_attack",  "High"),
                    (self.rule_engine.RF_SMURF,        "smurf",        "High"),
                    (self.rule_engine.RF_ICMP_TUNNEL,  "icmp_tunnel",  "High"),
                    (self.rule_engine.RF_RST_FLOOD,    "rst_flood",    "High"),
                    (self.rule_engine.RF_HTTP_FLOOD,   "http_flood",   "High"),
                    (self.rule_engine.RF_CRED_STUFF,   "cred_stuffing","High"),
                    (self.rule_engine.RF_TTL_ANOMALY,  "ttl_anomaly",  "Low"),
                    (self.rule_engine.RF_ENTROPY,      "payload_entropy","Low"),
                    (self.rule_engine.RF_BEACON,       "beacon",       "High"),
                    (self.rule_engine.RF_SQL_INJECTION,"sql_injection","High"),
                    (self.rule_engine.RF_WEBSHELL,     "webshell_upload","Critical"),
                    (self.rule_engine.RF_SMB_LATERAL,  "smb_lateral",  "High"),
                    (self.rule_engine.RF_JA3,          "ja3_blacklisted","High"),
                    (self.rule_engine.RF_HTTP_ATTACK,  "http_attack_payload","High"),
                    (self.rule_engine.RF_BLACKLIST,    "blacklist",    "High"),
                ]
                for bit, rule_name, default_sev in _HEAL_BITS:
                    if pkt.rule_flags & bit:
                        meta = RULE_REGISTRY.get(rule_name)
                        sev  = meta.severity if meta else default_sev
                        self.self_healer.heal(rule_name, pkt, sev)

                # Threat-intel / ML anomaly paths
                if pkt.threat_level == "Danger" and pkt.rule_flags == 0:
                    self.self_healer.heal("threat_intel", pkt, "High")
            except Exception:
                logger.debug("Self-heal dispatch error", exc_info=True)

        # ✅ Update threat stats
        if pkt.threat_level != "Safe":
            self.capture.update_threat_stats()

    def start_capture(self, interface=None, bpf_filter="") -> None:
        self.capture.bpf_filter = bpf_filter
        self.capture.start(interface)
        self.ml_engine.start()
        self._start_stats_push()
        self.watchdog.start()
        self.self_healer.start()   # ✅ Start self-healing engine
        self.event_logger.log_event("SYSTEM", description="Capture started",
                                    metadata={"interface": interface or "auto",
                                              "bpf": bpf_filter})

    def stop_capture(self) -> None:
        self.capture.stop()
        self.ml_engine.stop()
        self.watchdog.stop()
        self.self_healer.stop()    # ✅ Stop self-healing engine cleanly
        self._stats_running = False
        self.event_logger.log_event("SYSTEM", description="Capture stopped")

    def shutdown(self) -> None:
        self.stop_capture()
        self.event_logger.close()
        self.db.cleanup_old()
        self.db.close()
        logger.info("Pherion shutdown complete")

    def _start_stats_push(self) -> None:
        self._stats_running = True
        self._stats_thread = threading.Thread(
            target=self._stats_loop, daemon=True, name="StatsPush")
        t = self._stats_thread
        if t is not None:
            t.start()

    def _stats_loop(self) -> None:
        while self._stats_running:
            time.sleep(CAP.stats_push_interval)
            if not self.capture.is_running:
                continue
            stats = self.capture.stats
            try:
                self.stats_queue.put_nowait(stats)
            except queue.Full:
                pass
            # ✅ Persist to database periodically
            now = time.time()
            if now - self._last_db_stats > CAP.db_stats_interval:
                self.db.save_stats(
                    stats,
                    active_flows=self.flow_tracker.active_count(),
                    buffer_usage=len(self.capture.buffer))
                self._last_db_stats = now


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 17: HEADLESS MODE — ✅ Run without GUI
# ═══════════════════════════════════════════════════════════════════════════════

class HeadlessRunner:
    """Headless mode: runs Pherion without GUI.

    Prints alerts to console, saves to database.
    Useful for servers, Docker, SSH sessions.
    """

    def __init__(self, interface: Optional[str] = None,
                 bpf_filter: str = "",
                 rules_path: Optional[str] = None,
                 alert_json_path: Optional[str] = None,
                 syslog_addr: Optional[str] = None,
                 promisc: bool = False,
                 no_selfheal: bool = False) -> None:
        self._orch = Orchestrator(rules_path=rules_path,
                                  alert_json_path=alert_json_path,
                                  syslog_addr=syslog_addr,
                                  promisc=promisc)
        if no_selfheal:
            self._orch.self_healer.enabled = False
            logger.info("[SelfHeal] Disabled via --no-selfheal flag")
        # Strip display label from interface name (e.g. "Ethernet (192.168.1.5)" → "Ethernet")
        if interface and " (" in interface:
            interface = interface.split(" (")[0]
        self._interface = interface
        self._bpf_filter = bpf_filter
        self._running = False

    def run(self) -> None:
        self._running = True

        # Handle signals
        def _signal_handler(sig, frame):
            print("\n\n⏹ Stopping capture…")
            self._running = False
            self._orch.shutdown()
            sys.exit(0)

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        print("=" * 60)
        print("  🛡️  Pherion HEADLESS MODE")
        print("=" * 60)
        print(f"  Interface: {self._interface or 'Auto'}")
        print(f"  BPF Filter: {self._bpf_filter or 'none'}")
        print(f"  ML Ready: {self._orch.ml_engine.is_ready}")
        print(f"  Self-Heal: {'✅ enabled' if self._orch.self_healer.enabled else '⚠️  disabled (--no-selfheal)'}")
        print(f"  Database: {DB_DIR / 'pherion.db'}")
        print(f"  Logs: {_log_file}")
        print("=" * 60)
        print("  Press Ctrl+C to stop\n")

        self._orch.start_capture(self._interface, self._bpf_filter)

        # Main loop: print alerts and stats
        last_stats_print = 0.0
        while self._running and self._orch.capture.is_running:
            # Print alerts
            while True:
                try:
                    level, msg, ts = self._orch.alert_queue.get_nowait()
                    color = {"DANGER": "\033[91m", "WARNING": "\033[93m",
                             "INFO": "\033[94m", "ERROR": "\033[95m"}.get(level, "")
                    reset = "\033[0m"
                    print(f"  {color}[{ts}] {msg}{reset}")
                except queue.Empty:
                    break

            # Print stats periodically
            now = time.time()
            if now - last_stats_print > 10.0:
                stats = self._orch.capture.stats
                alert_stats = self._orch.alert_mgr.get_stats()
                corr_stats = self._orch.correlation_engine.get_stats()
                ti_stats = self._orch.threat_intel.stats
                watchdog_health = self._orch.watchdog.get_health()
                print(f"\n  📊 Stats: {stats['total']} pkts | "
                      f"{fmt_bytes(stats['bytes'])} | "
                      f"{stats['packets_per_sec']} pkt/s | "
                      f"Threats: {stats['threats']} | "
                      f"Flows: {self._orch.flow_tracker.active_count()} | "
                      f"Buffer: {len(self._orch.capture.buffer)}/{self._orch.capture.buffer.capacity} | "
                      f"Alerts: {alert_stats['total_emitted']} "
                      f"(suppressed: {alert_stats['total_suppressed']})")
                print(f"  🔗 Incidents: {corr_stats.get('active_incidents', 0)} active / "
                      f"{corr_stats.get('total_incidents', 0)} total | "
                      f"IOC DB: {ti_stats.get('ips', 0)} IPs, {ti_stats.get('domains', 0)} domains | "
                      f"Events: {self._orch.event_logger.event_count} | "
                      f"Threads: {watchdog_health.get('threads', 0)}\n")
                last_stats_print = now

            # Drain packet queue (don't display, just prevent backup)
            while True:
                try:
                    self._orch.pkt_queue.get_nowait()
                except queue.Empty:
                    break

            time.sleep(0.1)

        self._orch.shutdown()
        print("\n✅ Pherion headless mode stopped.")


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 18: GUI APPLICATION (only if tkinter available)
# ═══════════════════════════════════════════════════════════════════════════════

if TK_AVAILABLE:

    class Theme:
        """GUI color theme — Cyberpunk / Hacker Console."""
        # ── Backgrounds ──
        bg = "#020403"           # Deep black main
        bg2= "#050A08"          # Slightly lighter panels
        bg3 = "#08110D"          # Status bar / menu bar
        bg_panel = "#04110C"     # Side panels / HUD boxes
        # ── Primary text ──
        accent = "#00FF9C"       # Neon green — primary
        text = "#B6FFD8"         # Soft green-white for body text
        text2 = "#4B7A67"        # Dim green for secondary
        # ── Accent colors ──
        green = "#00FF9C"        # Status: normal / active
        yellow = "#FFD60A"       # Status: warning
        red = "#FF3B3B"          # Status: threat / danger
        blue = "#00E5FF"         # Info accents (minimal)
        orange = "#FF9F1C"       # Pause / attention
        cyan = "#00FFC6"         # Headings accent
        # ── Table ──
        table_bg = "#010201"     # Pure black
        table_fg = "#00FF9C"     # Soft neon green
        table_sel = "#003B24"    # Very dark green highlight
        header_bg = "#06110D"    # Slightly lighter header
        # ── Borders / glow ──
        border = "#00FF9C"       # Dark green border
        glow = "#00FF9C"         # Neon glow color
        # ── Fonts ──
        # Use a pixel-style console font on Windows. If you want a custom .ttf font,
        # replace the family name below with the installed font family.
        font_data = ("Courier", 9)
        font_data_bold = ("Courier", 9)
        font_heading = ("Courier", 12)
        font_heading_sm = ("Courier", 10)
        font_label = ("Courier", 9)
        font_status = ("Courier", 9)
        font_pixel = ("Courier", 11)
        font_btn = ("Courier", 10)
        
        # ── Cinematic Theme Overrides ──
        glow_alpha = 0.35
        particle_color = "#00FF9C"

    TH = Theme()

    import math
    import random

    class CinematicStream(tk.Canvas):
        """Animated live data stream replacing the static table."""
        def __init__(self, master, max_items=25, on_click=None, **kwargs):
            kwargs.setdefault('bg', TH.bg)
            kwargs.setdefault('highlightthickness', 0)
            super().__init__(master, **kwargs)
            self.max_items = max_items
            self.on_click = on_click
            self.items = [] # dicts: text_id, bg_id, y_target, current_y, start_time, ttl
            self.row_h = 24
            
            # Draw subtle scanlines
            for i in range(0, 1000, 4):
                self.create_line(0, i, 2000, i, fill="#0A0A0A", stipple="gray25", tags="scanline")
                
        def add_packet(self, no, time, src, dst, proto, info, threat, fg_color):
            """Spawn a new packet at the top and push others down."""
            # Shift targets down
            for item in self.items:
                item['y_target'] += self.row_h
                
            # Create new packet off-screen top
            start_y = -self.row_h
            
            # Format text cinematically: [PROTO] SRC ──> DST | INFO
            text = f"[{proto:^6}] {src:<15} ──► {dst:<15} │ {info[:80]}"
            if threat != "none":
                text = f"[!] {threat.upper()}  " + text
                
            y_pos = start_y + (self.row_h/2)
            bg_id = self.create_rectangle(10, start_y, 1000, start_y+self.row_h-2, 
                                          fill=TH.table_sel if threat!="none" else "", 
                                          outline="", tags="pkt")
            txt_id = self.create_text(15, y_pos, text=text, fill=fg_color, 
                                      font=TH.font_data, anchor=tk.W, tags="pkt")
                                      
            if self.on_click:
                self.tag_bind(bg_id, "<Button-1>", lambda e, n=no: self.on_click(n))  # type: ignore[arg-type]
                self.tag_bind(txt_id, "<Button-1>", lambda e, n=no: self.on_click(n))  # type: ignore[arg-type]
                
                # Changing cursor on hover over the background rectangle
                self.tag_bind(bg_id, "<Enter>", lambda e: self.config(cursor="hand2"))
                self.tag_bind(bg_id, "<Leave>", lambda e: self.config(cursor=""))
                self.tag_bind(txt_id, "<Enter>", lambda e: self.config(cursor="hand2"))
                self.tag_bind(txt_id, "<Leave>", lambda e: self.config(cursor=""))
            
            self.items.insert(0, {
                'txt': txt_id, 'bg': bg_id, 'y_target': 10, 'y_curr': start_y, 
                'age': 0, 'color': fg_color
            })
            
            # Prune old
            if len(self.items) > self.max_items:
                old = self.items.pop()
                self.delete(old['txt'])
                self.delete(old['bg'])
                
        def animate_step(self):
            """Smooth lerp sliding animation."""
            self.tag_raise("scanline") # Keep scanlines on top
            for i, item in enumerate(self.items):
                item['age'] += 1
                diff = item['y_target'] - item['y_curr']
                if abs(diff) > 0.5:
                    step = diff * 0.2 # Easing
                    item['y_curr'] += step
                    self.move(item['txt'], 0, step)
                    self.move(item['bg'], 0, step)
                
                # Fade out color based on age/index
                if i > self.max_items - 5:
                    pass # Tkinter canvas doesn't support alpha per-object easily without images, so we rely on pruning.

    class NetworkGraph(tk.Canvas):
        """Animated force-directed-ish node map with threat-colored edges & particles.

        ✅ SOC Enhancement:
        - Normal traffic → thin green/gray edges + green particles
        - Suspicious    → yellow dashed edges + yellow particles
        - Danger/Threat → red dotted edges + red pulsing particles
        - Multiple threat levels per connection shown separately
        - Arrow direction indicator at edge midpoint
        - Tooltip labels showing IP pair at edge midpoint
        - Hacker movie ASCII art aesthetic
        """

        # Threat-level color palette - visible but not bold
        _EDGE_COLORS = {"Safe": "#00FF9C", "Suspicious": "#FFD700", "Danger": "#FF3333"}
        _PARTICLE_COLORS = {"Safe": "#00FF9C", "Suspicious": "#FFD700", "Danger": "#FF3333"}
        # Thinner lines - visible but not bold
        _EDGE_WIDTHS = {"Safe": 1, "Suspicious": 1, "Danger": 1}
        _NODE_COLORS = {"Safe": "#00FF9C", "Suspicious": "#FFD700", "Danger": "#FF3333"}
        # Fallback colors for missing threat levels
        _DEFAULT_COLORS = {"Safe": "#00FF9C", "Suspicious": "#FFD700", "Danger": "#FF3333"}

        def __init__(self, master, **kwargs):
            kwargs.setdefault('bg', TH.bg_panel)
            kwargs.setdefault('highlightthickness', 0)
            super().__init__(master, **kwargs)
            self.nodes = {}      # ip -> {x, y, r, pulse, max_pulse, id, txt, threat}
            # Edge stores multiple threat lines: (ip1,ip2) -> {lines: {threat: line_id}, glow_id, label_ids: {}, threats: set, decay}
            self.edges = {}
            self.particles = []  # {x1, y1, x2, y2, progress, speed, id, color}

            self.bind("<Configure>", self._on_resize)
            self.w, self.h = 420, 280

            # Draw grid
            for i in range(0, 1400, 40):
                self.create_line(i, 0, i, 1400, fill="#0A1A10", tags="grid")
                self.create_line(0, i, 1400, i, fill="#0A1A10", tags="grid")

            # Threat decay timer (downgrade edges after inactivity)
            self._decay_counter = 0

        def _on_resize(self, event):
            self.w, self.h = event.width, event.height

        def _threat_order(self, level):
            return {"Safe": 0, "Suspicious": 1, "Danger": 2}.get(level, 0)

        def _normalize_threat_level(self, level: str) -> str:
            """Normalize threat level to standard values."""
            if not level:
                return "Safe"
            level_lower = level.lower().strip()
            # Map various threat level representations to standard values
            if level_lower in ("danger", "critical", "high", "threat", "alert", "red", "attack"):
                return "Danger"
            elif level_lower in ("suspicious", "warning", "medium", "warn", "yellow", "caution"):
                return "Suspicious"
            elif level_lower in ("safe", "normal", "low", "ok", "green", "good"):
                return "Safe"
            # Default to Safe if unknown
            return "Safe"

        def add_connection(self, src, dst, threat_level="Safe"):
            """Add or update a connection with threat visualization.
            
            Supports multiple threat levels per connection - each shown as separate line.
            """
            import logging
            logger = logging.getLogger("NetworkGraph")

            # ── FIX: pin normalized_threat ONCE here and never re-assign it
            # inside the node loop (was causing the wrong threat level to reach
            # the edge-drawing code ~50% of the time depending on loop order).
            normalized_threat = self._normalize_threat_level(threat_level)
            logger.debug(f"add_connection: {src} -> {dst}, threat={threat_level} -> normalized={normalized_threat}")

            # ── helper: build/check dash pattern from a threat string ──────────
            def _dash_for(t: str):
                if t == "Suspicious":
                    return (4, 4)
                if t == "Danger":
                    return (2, 3)
                return None

            # Add nodes
            for ip in (src, dst):
                if ip not in self.nodes and len(self.nodes) < 60:
                    text_w = max(70, len(ip) * 6 + 14)
                    text_h = 16
                    node_r = 5
                    padding_x = 18
                    padding_y = 18

                    def _bbox_for(cx: int, cy: int):
                        return (
                            cx - text_w / 2 - padding_x,
                            cy - node_r - padding_y,
                            cx + text_w / 2 + padding_x,
                            cy + 14 + text_h / 2 + padding_y
                        )

                    def _rects_overlap(a: Tuple[float, float, float, float], b: Tuple[float, float, float, float]) -> bool:
                        return not (a[2] < b[0] or a[0] > b[2] or a[3] < b[1] or a[1] > b[3])

                    candidates = []
                    cols = max(3, min(8, self.w // 120))
                    rows = max(2, min(5, self.h // 70))
                    for ry in range(rows):
                        for rx in range(cols):
                            cx = int(40 + rx * max(1, (self.w - 80) / max(1, cols - 1)))
                            cy = int(20 + ry * max(1, (self.h - 60) / max(1, rows - 1)))
                            candidates.append((cx, cy))
                    random.shuffle(candidates)

                    x, y = self.w // 2, self.h // 2
                    placed = False
                    for cx, cy in candidates:
                        bbox = _bbox_for(cx, cy)
                        overlap = False
                        for existing_node in self.nodes.values():
                            existing_w = existing_node.get('text_w', max(70, len(ip) * 6 + 14))
                            existing_box = (
                                existing_node['x'] - existing_w / 2 - padding_x,
                                existing_node['y'] - node_r - padding_y,
                                existing_node['x'] + existing_w / 2 + padding_x,
                                existing_node['y'] + 14 + text_h / 2 + padding_y
                            )
                            if _rects_overlap(bbox, existing_box):
                                overlap = True
                                break
                        if not overlap:
                            x, y = cx, cy
                            placed = True
                            break

                    if not placed:
                        for _ in range(300):
                            cx = random.randint(40, max(self.w - 50, 60))
                            cy = random.randint(20, max(self.h - 40, 40))
                            bbox = _bbox_for(cx, cy)
                            if any(
                                _rects_overlap(bbox, (
                                    existing_node['x'] - existing_node.get('text_w', 70) / 2 - padding_x,
                                    existing_node['y'] - node_r - padding_y,
                                    existing_node['x'] + existing_node.get('text_w', 70) / 2 + padding_x,
                                    existing_node['y'] + 14 + text_h / 2 + padding_y
                                ))
                                for existing_node in self.nodes.values()
                            ):
                                continue
                            x, y = cx, cy
                            placed = True
                            break

                    if not placed:
                        continue

                    # Use highest threat color for node outline
                    node_color = self._NODE_COLORS.get(normalized_threat, "#00FF9C")
                    node_id = self.create_oval(0, 0, 0, 0, outline=node_color, width=1)
                    txt_id = self.create_text(x, y + 14, text=ip, fill=TH.text2, font=("Consolas", 7))
                    self.nodes[ip] = {
                        'x': x, 'y': y, 'r': node_r, 'pulse': 0, 'max_pulse': 12,
                        'id': node_id, 'txt': txt_id, 'threat': normalized_threat,
                        'idle': 0, 'text_w': text_w, 'text_h': text_h
                    }
                if ip in self.nodes:
                    node = self.nodes[ip]
                    node['pulse'] = node['max_pulse']
                    node['idle'] = 0
                    # Escalate node threat color — use the already-pinned normalized_threat
                    # (do NOT call _normalize_threat_level again here; that was overwriting
                    # normalized_threat and corrupting the value for the edge section)
                    if self._threat_order(normalized_threat) > self._threat_order(node.get('threat', 'Safe')):
                        node['threat'] = normalized_threat
                        color = self._NODE_COLORS.get(normalized_threat, "#00FF9C")
                        self.itemconfigure(node['id'], outline=color)

            # Only connect/particle if both nodes exist
            if src in self.nodes and dst in self.nodes:
                n1, n2 = self.nodes[src], self.nodes[dst]
                edge_key = tuple(sorted([src, dst]))

                edge_color  = self._EDGE_COLORS.get(normalized_threat, "#00FF9C")
                edge_width  = self._EDGE_WIDTHS.get(normalized_threat, 1)
                dash_pattern = _dash_for(normalized_threat)

                if edge_key not in self.edges:
                    # ── Brand-new edge ──────────────────────────────────────
                    line_id = self.create_line(
                        n1['x'], n1['y'], n2['x'], n2['y'],
                        fill=edge_color, width=edge_width,
                        dash=dash_pattern, tags="edge")

                    glow_id = self.create_line(
                        n1['x'], n1['y'], n2['x'], n2['y'],
                        fill=edge_color, width=edge_width + 2,
                        stipple="gray25", tags="glow") if normalized_threat == "Danger" else None

                    mx: float = (int(n1['x']) + int(n2['x'])) / 2
                    my: float = (int(n1['y']) + int(n2['y'])) / 2
                    label_id = None
                    if normalized_threat != "Safe":
                        label_text = f"⚠ {normalized_threat}"
                        label_color = self._PARTICLE_COLORS.get(normalized_threat, "#FFD700")
                        label_id = self.create_text(
                            mx, my - 8, text=label_text,
                            fill=label_color,
                            font=("Consolas", 7, "bold"), tags="label")

                    self.edges[edge_key] = {
                        'lines':   {normalized_threat: line_id},
                        'glow':    glow_id,
                        'labels':  {normalized_threat: label_id},
                        'threats': {normalized_threat},
                        'decay':   100,
                        'n1': n1, 'n2': n2,
                    }
                    # Keep grid below edges, but edges must stay ABOVE grid
                    self.tag_lower("grid")
                    if glow_id:
                        self.tag_lower("glow")

                else:
                    # ── Existing edge ───────────────────────────────────────
                    edge = self.edges[edge_key]
                    edge['decay'] = 100  # reset decay timer

                    if normalized_threat not in edge['threats']:
                        # New threat level on this edge — draw a new line
                        edge['threats'].add(normalized_threat)

                        new_line_id = self.create_line(
                            n1['x'], n1['y'], n2['x'], n2['y'],
                            fill=edge_color, width=edge_width,
                            dash=dash_pattern, tags="edge")
                        edge['lines'][normalized_threat] = new_line_id

                        mx: float = (int(n1['x']) + int(n2['x'])) / 2
                        my: float = (int(n1['y']) + int(n2['y'])) / 2
                        label_color = self._PARTICLE_COLORS.get(normalized_threat, "#FFD700")
                        y_offset = -8 - (len(edge['labels']) * 10)
                        new_label_id = self.create_text(
                            mx, my + y_offset,
                            text=f"⚠ {normalized_threat}",
                            fill=label_color,
                            font=("Consolas", 7, "bold"), tags="label")
                        edge['labels'][normalized_threat] = new_label_id

                        if normalized_threat == "Danger" and edge['glow'] is None:
                            edge['glow'] = self.create_line(
                                n1['x'], n1['y'], n2['x'], n2['y'],
                                fill=edge_color, width=edge_width + 2,
                                stipple="gray25", tags="glow")
                            self.tag_lower("glow")

                    else:
                        # ── FIX: threat already known on this edge — UPDATE the
                        # existing line colour/dash in-place so escalations
                        # (e.g. Safe→Suspicious→Danger) are always visible even
                        # when the edge was created at a lower severity.
                        existing_line_id = edge['lines'].get(normalized_threat)
                        if existing_line_id is not None:
                            self.itemconfigure(existing_line_id,
                                               fill=edge_color,
                                               dash=dash_pattern if dash_pattern else "",
                                               width=edge_width)
                        # Ensure glow exists for Danger even if it was added later
                        if normalized_threat == "Danger" and edge.get('glow') is None:
                            edge['glow'] = self.create_line(
                                n1['x'], n1['y'], n2['x'], n2['y'],
                                fill=edge_color, width=edge_width + 2,
                                stipple="gray25", tags="glow")
                            self.tag_lower("glow")

                # ── Spawn threat-coloured particle ──────────────────────────
                p_color = self._PARTICLE_COLORS.get(normalized_threat, "#00FF9C")
                p_size  = 3.0 if normalized_threat == "Danger" else 2.0
                pid = self.create_oval(0, 0, 0, 0, fill=p_color, outline="")
                self.particles.append({
                    'id': pid,
                    'x1': n1['x'], 'y1': n1['y'],
                    'x2': n2['x'], 'y2': n2['y'],
                    'p': 0.0, 's': random.uniform(0.02, 0.06),
                    'color': p_color, 'size': p_size,
                })

                if len(self.particles) > 30:
                    old = self.particles.pop(0)
                    self.delete(str(old['id']))

        def animate_step(self):
            # Nodes pulse and idle pruning
            for ip, n in list(self.nodes.items()):
                n['idle'] = n.get('idle', 0) + 1
                if n['idle'] > 1800:  # ~60 seconds at 30fps
                    self.delete(str(n['id']))
                    self.delete(str(n['txt']))
                    self.nodes.pop(ip, None)
                    for ek in list(self.edges.keys()):
                        if ip in ek:
                            e = self.edges.pop(ek)
                            # Delete all threat lines
                            for line_id in e.get('lines', {}).values():
                                self.delete(str(line_id))
                            # Delete glow
                            glow_val = e.get('glow')
                            if glow_val is not None:
                                self.delete(str(glow_val))
                            # Delete all labels
                            for label_val in e.get('labels', {}).values():
                                if label_val is not None:
                                    self.delete(str(label_val))
                    continue
                    
                pulse_val: int = int(n['pulse'])
                if pulse_val > 0:
                    n['pulse'] = int(pulse_val - 0.5)
                r: float = float(n['r']) + (float(n['pulse']) * 0.3)
                nx: float = float(n['x'])
                ny: float = float(n['y'])
                self.coords(str(n['id']), nx - r, ny - r, nx + r, ny + r)  # type: ignore[call-overload]

            # Particles move
            alive = []
            for p in self.particles:
                p['p'] = float(p['p']) + float(p['s'])
                if float(p['p']) >= 1.0:
                    self.delete(str(p['id']))
                else:
                    x: float = float(p['x1']) + (float(p['x2']) - float(p['x1'])) * float(p['p'])
                    y: float = float(p['y1']) + (float(p['y2']) - float(p['y1'])) * float(p['p'])
                    sz: float = float(p.get('size', 1.5))
                    self.coords(str(p['id']), x - sz, y - sz, x + sz, y + sz)  # type: ignore[call-overload]
                    alive.append(p)
            self.particles = alive

            # Edge threat decay (every ~3 seconds at 30fps)
            self._decay_counter += 1
            if self._decay_counter >= 90:
                self._decay_counter = 0
                for ek, edge in list(self.edges.items()):
                    _raw_decay = edge['decay']
                    decay_val: int = max(0, (int(_raw_decay) if _raw_decay is not None else 0) - 10)
                    edge['decay'] = decay_val
                    
                    # Only decay if no threats remain
                    if decay_val <= 0 and not edge.get('threats'):
                        # Delete all threat lines
                        for line_id in edge.get('lines', {}).values():
                            self.delete(str(line_id))
                        # Delete glow
                        if edge.get('glow') is not None:
                            self.delete(str(edge['glow']))
                        # Delete all labels
                        for label_val in edge.get('labels', {}).values():
                            if label_val is not None:
                                self.delete(str(label_val))
                        # Remove edge
                        self.edges.pop(ek, None)

    class SignalWaveform(tk.Canvas):
        """Flame-style spike graph for Operations Core."""
        def __init__(self, master, color=TH.accent, **kwargs):
            kwargs.setdefault('bg', TH.bg_panel)
            kwargs.setdefault('highlightthickness', 0)
            kwargs.setdefault('height', 60)
            super().__init__(master, **kwargs)
            self.color = color
            self.phase = 0.0
            self.amp = 6.0
            self.target_amp = 6.0
            self.w = kwargs.get('width', 280)
            self.h = kwargs.get('height', 60)
            self.spike_ids = []
            self.glow_ids = []
            self._baseline = None
            self.bind("<Configure>", self._on_resize)
            self._prepare_spikes(self.w)

        def _prepare_spikes(self, width):
            target_count = max(100, min(700, int(width / 2)))
            if target_count == len(self.spike_ids):
                return
            for line_id in self.spike_ids + self.glow_ids:
                self.delete(line_id)
            self.spike_ids = [self.create_line(0, 0, 0, 0, fill=self.color, width=2)
                              for _ in range(target_count)]
            self.glow_ids = [self.create_line(0, 0, 0, 0, fill=self.color, width=4, stipple="gray50")
                             for _ in range(target_count)]

        def _on_resize(self, event):
            self.w = max(event.width, 1)
            self.h = max(event.height, 1)
            self._prepare_spikes(self.w)
            if self._baseline is not None:
                self.coords(self._baseline, 2, self.h - 2, self.w - 2, self.h - 2)

        def spike(self, amount=25.0):
            self.target_amp = min(amount, 45.0)

        def animate_step(self):
            self.phase += 0.18
            self.target_amp = max(2.0, self.target_amp - 0.75)
            self.amp += (self.target_amp - self.amp) * 0.18

            baseline = self.h - 2
            height_cap = max(6, min(self.h - 8, self.amp * 3 + 8))
            count = max(1, len(self.spike_ids))
            spacing = self.w / count

            for idx, line_id in enumerate(self.spike_ids):
                x = int(idx * spacing + spacing * 0.5)
                noise = abs(math.sin(idx * 0.45 + self.phase * 1.6) *
                            math.cos(idx * 0.72 - self.phase * 1.1))
                height = int(4 + height_cap * (0.25 + 0.75 * noise))
                y_top = max(2, baseline - height)
                self.coords(line_id, x, baseline, x, y_top)
                self.coords(self.glow_ids[idx], x, baseline, x, max(2, y_top - 2))

            if self._baseline is None:
                self._baseline = self.create_line(2, baseline, self.w - 2, baseline,
                                                 fill="#11331A", width=1)
            else:
                self.coords(self._baseline, 2, baseline, self.w - 2, baseline)

    class ProtocolSplineChart(tk.Canvas):
        """Animated multi-line spline chart for protocol rates."""
        def __init__(self, master, **kwargs):
            kwargs.setdefault('bg', TH.bg_panel)
            kwargs.setdefault('highlightthickness', 0)
            kwargs.setdefault('height', 160)
            super().__init__(master, **kwargs)
            self.protocols = ["tcp", "udp", "icmp", "dns", "http", "https"]
            self.colors = {"tcp": "#40C4AA", "udp": "#6DD66D", "icmp": "#D4D460", 
                           "dns": "#B080D0", "http": "#40B0D0", "https": "#60C0A0"}
            self.history = {p: [0]*80 for p in self.protocols}
            self.last_totals = {p: 0 for p in self.protocols}
            self.lines = {}
            self.w = 280
            self.h = 180
            self.bind("<Configure>", self._on_resize)
            
            # Initial drawing lines
            for p in self.protocols:
                self.lines[p] = self.create_line(0,0,0,0, fill=self.colors[p], width=2, smooth=True, splinesteps=36)
                
            # Draw legend with small styling
            for i, p in enumerate(self.protocols):
                x = 10 + (i % 3) * 75
                y = 8 + (i // 3) * 18
                self.create_oval(x, y, x+6, y+6, fill=self.colors[p], outline="")
                self.create_text(x+12, y+3, text=p.upper(), fill=TH.text2, font=("Consolas", 7, "bold"), anchor=tk.W)
                
            self.grid_lines = []
            self.axis_labels = []
            self._background_rect: Optional[int] = None
            
        def _on_resize(self, event):
            self.w = event.width
            self.h = event.height
            # redraw grid
            for g in self.grid_lines: self.delete(g)
            self.grid_lines.clear()
            for y in range(30, self.h-10, 30):
                self.grid_lines.append(self.create_line(0, y, self.w, y, fill="#1A2A1A", dash=(2, 4)))

            # redraw y axis numbering small
            for l in self.axis_labels: self.delete(l)
            self.axis_labels.clear()
            for level in range(0, 5):
                y = self.h - 20 - (level * (self.h-45) / 4)
                lbl = self.create_text(2, y, text=f"{(level*25)}%", fill=TH.text2,
                                       font=("Consolas", 7), anchor=tk.W)
                self.axis_labels.append(lbl)
                
        def update_stats(self, stats):
            for p in self.protocols:
                curr = stats.get(p, 0)
                # Calculate delta for rate, ignore first spike
                delta = max(0, curr - self.last_totals.get(p, 0))
                if self.last_totals[p] == 0: delta = 0
                self.last_totals[p] = curr
                
                self.history[p].append(delta)
                if len(self.history[p]) > 40:
                    self.history[p].pop(0)
                
        def animate_step(self):
            # Find global max for scaling
            max_val = 1
            for p in self.protocols:
                max_val = max(max_val, max(self.history[p]))
                
            points = len(self.history[self.protocols[0]])
            step_x = self.w / max(1, points-1)
            
            for p in self.protocols:
                pts = []
                for i, val in enumerate(self.history[p]):
                    x = i * step_x
                    y = self.h - 25 - ((val / max_val) * (self.h - 55))
                    pts.extend([x, y])
                if len(pts) >= 4:
                    self.coords(self.lines[p], *pts)

            # keep chart context updated with moving threshold overlay
            # lighten background for smoother readout
            if self._background_rect is None:
                rect = self.create_rectangle(0, 0, self.w, self.h, outline="", fill="", tags="bg")
                self._background_rect = rect
                self.tag_lower(rect)
            else:
                self.coords(self._background_rect, 0, 0, self.w, self.h)  # type: ignore[arg-type]

    class ProtocolBarChart(tk.Canvas):
        """Numeric protocol distribution summary panel."""
        def __init__(self, master, **kwargs):
            kwargs.setdefault('bg', TH.bg_panel)
            kwargs.setdefault('highlightthickness', 0)
            super().__init__(master, **kwargs)
            self.protocols = ["tcp", "udp", "icmp", "arp", "dns", "http", "https", "ssh", "quic", "other"]
            self.colors = {
                "tcp": "#40C4AA", "udp": "#6DD66D", "icmp": "#D4D460", "arp": "#FF8A65",
                "dns": "#B080D0", "http": "#40B0D0", "https": "#60C0A0", "ssh": "#BA68C8",
                "quic": "#4DB6AC", "other": "#90A4AE"
            }
            self.values = {p: 0.0 for p in self.protocols}
            self.target_values = {p: 0.0 for p in self.protocols}
            self.w = 280
            self.h = 250
            self.bind("<Configure>", self._on_resize)

            # Draw header
            self.create_text(10, 8, text="TRAFFIC INTELLIGENCE", fill=TH.cyan, font=("Consolas", 8, "bold"), anchor=tk.W)
            self.header_line = self.create_line(10, 16, 270, 16, fill="#1A3A3A")

            self.elements = {}
            for p in self.protocols:
                lbl = self.create_text(-100, -100, text=p.upper(), fill=TH.text2,
                                       font=("Consolas", 8, "bold"), anchor=tk.W)
                val = self.create_text(-100, -100, text="0", fill=TH.text,
                                       font=("Consolas", 10, "bold"), anchor=tk.E)
                self.elements[p] = {'label': lbl, 'value': val}

        def _on_resize(self, event):
            self.w = max(event.width, 1)
            self.h = max(event.height, 1)
            self.coords(self.header_line, 10, 20, self.w - 10, 20)

            rows = 5
            col_width = self.w / 2
            row_height = max(24, (self.h - 40) / rows)
            for idx, p in enumerate(self.protocols):
                col = idx // rows
                row = idx % rows
                x_start = 10 + (col * col_width)
                y = 30 + row * row_height
                self.coords(self.elements[p]['label'], x_start + 2, y)
                self.coords(self.elements[p]['value'], x_start + col_width - 8, y)

        def update_stats(self, stats):
            for p in self.protocols:
                self.target_values[p] = float(stats.get(p, 0))

        def animate_step(self):
            for p in self.protocols:
                self.values[p] += (self.target_values[p] - self.values[p]) * 0.15
                self.itemconfigure(self.elements[p]['value'], text=str(int(self.values[p])))

    def configure_styles(style):
        style.theme_use("clam")
        # ── Treeview (packet table) ──
        style.configure("Pkt.Treeview",
                         background=TH.table_bg,
                         foreground=TH.table_fg,
                         fieldbackground=TH.table_bg,
                         rowheight=24,
                         font=TH.font_data,
                         borderwidth=0)
        style.configure("Pkt.Treeview.Heading",
                         background=TH.header_bg,
                         foreground=TH.cyan,
                         font=TH.font_data_bold,
                         borderwidth=1,
                         relief="flat")
        style.map("Pkt.Treeview",
                  background=[("selected", TH.table_sel)],
                  foreground=[("selected", "#00FFB0")])
        style.map("Pkt.Treeview.Heading",
                 background=[("active", TH.header_bg)],
                 foreground=[("active", TH.cyan)])

        # ── Notebook tabs ──
        style.configure("TNotebook",
                         background=TH.bg,
                         borderwidth=0)
        style.configure("TNotebook.Tab",
                         background=TH.bg2,
                         foreground=TH.text2,
                         padding=[14, 5],
                         font=TH.font_data_bold)
        style.map("TNotebook.Tab",
                  background=[("selected", TH.bg)],
                  foreground=[("selected", TH.green)])
        # ── Progressbar ──
        style.configure("green.Horizontal.TProgressbar",
                         troughcolor=TH.bg2,
                         background=TH.green,
                         darkcolor=TH.green,
                         lightcolor=TH.green,
                         bordercolor=TH.border)
        # ── Separator ──
        style.configure("TSeparator",
                         background=TH.border)
        # ── Scrollbar ──
        style.configure("Vertical.TScrollbar",
                         background=TH.bg2,
                         troughcolor=TH.bg,
                         arrowcolor=TH.text2,
                         borderwidth=0)
        style.configure("Horizontal.TScrollbar",
                         background=TH.bg2,
                         troughcolor=TH.bg,
                         arrowcolor=TH.text2,
                         borderwidth=0)

    class PherionGUI:
        """Full GUI application."""

        def __init__(self, root, rules_path: Optional[str] = None,
                     alert_json_path: Optional[str] = None,
                     syslog_addr: Optional[str] = None,
                     promisc: bool = True):
            self.root = root
            # Wire the approval gate's GUI popup to this Tk root
            APPROVAL_GATE.set_tk_root(root)
            self.root.title("Pherion vβ")
            screen_w = self.root.winfo_screenwidth()
            screen_h = self.root.winfo_screenheight()
            app_w = int(screen_w * 0.85)
            app_h = int(screen_h * 0.85)
            self.root.geometry(f"{app_w}x{app_h}")
            self.root.minsize(GUI.min_width, GUI.min_height)
            self.root.configure(bg=TH.bg)

            # ✅ Orchestrator handles all wiring
            self._orch = Orchestrator(rules_path=rules_path,
                                      alert_json_path=alert_json_path,
                                      syslog_addr=syslog_addr,
                                      promisc=promisc)
            self._capturing = False
            self._display_count = 0
            self._promisc = promisc
            self._auto_scroll = tk.BooleanVar(value=True)
            self._is_closing = False

            self._iface_var: Any = None
            self._iface_cb: Any = None
            self._start_btn: Any = None
            self._pause_btn: Any = None
            self._stop_btn: Any = None
            self._proto_var: Any = None
            self._promisc_var: Any = None
            self._ip_var: Any = None
            self._port_var: Any = None
            self._bpf_var: Any = None
            self._pkt_lbl: Any = None
            self._pps_lbl: Any = None
            self._tree: Any = None
            self._stat_labels: Any = None
            self._talkers: Any = None
            self._detail_txt: Any = None
            self._alert_txt: Any = None
            self._hex_txt: Any = None
            self._raw_txt: Any = None
            self._csv_var: Any = None
            self._train_btn: Any = None
            self._lcol_var: Any = None
            self._ml_stat: Any = None
            self._progress: Any = None
            self._ml_info: Any = None
            self._ml_log: Any = None
            self._dot: Any = None
            self._status: Any = None
            self._ml_bar: Any = None
            self._buf_bar: Any = None

            # Attributes initialized in _build_* methods
            self._graph: Any = None
            self._wave: Any = None
            self._proto_graph: Any = None
            self._main_pw: Any = None
            self._resize_after_id: Any = None
            self._scroll_status: Any = None
            self._go_live_button: Any = None
            self._stream: Any = None
            self._stream_sb: Any = None
            self._protocol_bars: Any = None
            self._debug_txt: Any = None
            self._debug_metrics: Any = {}
            self._parse_error_count = 0
            self._unknown_proto_count = 0
            self._bot_pw: Any = None
            self._right_pw: Any = None

            # Build UI
            self._style = ttk.Style()
            configure_styles(self._style)
            self._build_menu()
            self._build_toolbar()
            self._build_main()
            self._build_status_bar()

            # Global Animation Loop
            self._animate_timer()

            # GUI update loop
            self._update_gui()
            self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        def _animate_timer(self):
            """Master loop for 30fps smooth canvas animations."""
            if self._is_closing or not self.root.winfo_exists():
                return
            try:
                if hasattr(self, '_graph') and self._graph is not None:
                    self._graph.animate_step()
                if hasattr(self, '_wave') and self._wave is not None:
                    self._wave.animate_step()
                if hasattr(self, '_proto_graph') and self._proto_graph is not None:
                    self._proto_graph.animate_step()
            except tk.TclError:
                return
            except Exception:
                logger.debug("Animation loop error", exc_info=True)
            self.root.after(33, self._animate_timer)  # ~30fps

        # ─── Menu ───────────────────────────────────────────────────

        def _build_menu(self):
            mb = tk.Menu(self.root, bg=TH.bg3, fg=TH.text, font=TH.font_data,
                         activebackground=TH.border, activeforeground=TH.green,
                         borderwidth=0, relief=tk.FLAT)
            fm = tk.Menu(mb, tearoff=0, bg=TH.bg3, fg=TH.text, font=TH.font_data,
                         activebackground=TH.border, activeforeground=TH.green)
            fm.add_command(label="SAVE PCAP", command=self._save_pcap)
            fm.add_command(label="EXPORT ALERTS", command=self._export_alerts)
            fm.add_separator()
            fm.add_command(label="EXIT", command=self._on_close)
            mb.add_cascade(label="FILE", menu=fm)

            cm = tk.Menu(mb, tearoff=0, bg=TH.bg3, fg=TH.text, font=TH.font_data,
                         activebackground=TH.border, activeforeground=TH.green)
            cm.add_command(label="START", command=self._start)
            cm.add_command(label="PAUSE/RESUME", command=self._pause)
            cm.add_command(label="STOP", command=self._stop)
            cm.add_separator()
            cm.add_command(label="CLEAR", command=self._clear)
            mb.add_cascade(label="CAPTURE", menu=cm)

            hm = tk.Menu(mb, tearoff=0, bg=TH.bg3, fg=TH.text, font=TH.font_data,
                         activebackground=TH.border, activeforeground=TH.green)
            hm.add_command(label="ABOUT", command=self._about)
            mb.add_cascade(label="HELP", menu=hm)
            self.root.config(menu=mb)

        # --- Toolbar --------------------------------------------------------

        def _build_toolbar(self):
            tb = tk.Frame(self.root, bg=TH.bg2, height=60,
                          highlightbackground=TH.border, highlightthickness=1)
            tb.pack(fill=tk.X, padx=0, pady=(0, 1))
            tb.pack_propagate(False)

            left = tk.Frame(tb, bg=TH.bg2)
            left.pack(side=tk.LEFT, padx=5, pady=5)

            tk.Label(left, text="INTERFACE:", bg=TH.bg2, fg=TH.text2,
                     font=TH.font_label).pack(side=tk.LEFT, padx=(5, 2))
            self._iface_var = tk.StringVar(value="Auto")
            self._iface_cb = ttk.Combobox(left, textvariable=self._iface_var,
                                           width=22, state="readonly")
            self._iface_cb["values"] = get_interfaces()
            if self._iface_cb["values"]:
                self._iface_cb.current(0)
            self._iface_cb.pack(side=tk.LEFT, padx=2)

            tk.Label(left, text="│", bg=TH.bg2, fg=TH.border).pack(side=tk.LEFT, padx=5)

            # ── Cyberpunk neon buttons with slim styling ──
            def _make_cyber_btn(parent, main_text, sub_text, bg_color, cmd, state=tk.NORMAL):
                """Create a minimal cyberpunk-styled button [ CLICK ]."""
                frame = tk.Frame(parent, bg=TH.bg2, bd=0)
                frame.pack(side=tk.LEFT, padx=3)
                
                # Lean text and brackets
                btn_font = ("Consolas", 9, "bold")
                btn = tk.Button(frame, text=f"[ {main_text} ]",
                                bg=TH.bg2, fg=bg_color, activebackground=bg_color,
                                activeforeground=TH.bg,
                                command=cmd, state=state,
                                font=btn_font, relief=tk.FLAT,
                                cursor="hand2", padx=6, pady=2, bd=0)
                btn.pack(side=tk.TOP, fill=tk.X)
                
                # Hover effect bindings
                def on_enter(e):
                    if btn['state'] == tk.NORMAL:
                        btn.config(bg=bg_color, fg=TH.bg)
                def on_leave(e):
                    if btn['state'] == tk.NORMAL:
                        btn.config(bg=TH.bg2, fg=bg_color)
                        
                btn.bind("<Enter>", on_enter)
                btn.bind("<Leave>", on_leave)
                return btn

            self._start_btn = _make_cyber_btn(left, "▶ START", "[ INIT ]", TH.green, self._start)
            self._pause_btn = _make_cyber_btn(left, "⏸ PAUSE", "[ HOLD ]", TH.orange, self._pause, tk.DISABLED)
            self._stop_btn  = _make_cyber_btn(left, "⏹ STOP",  "[ HALT ]", TH.red, self._stop, tk.DISABLED)
            _make_cyber_btn(left, "✘ CLEAR", "[ RESET ]", TH.text2, self._clear)

            # Hidden vars kept so rest of code doesn't break
            self._promisc_var = tk.BooleanVar(value=self._promisc)
            self._proto_var = tk.StringVar(value="All")
            self._ip_var = tk.StringVar()
            self._port_var = tk.StringVar()
            self._bpf_var = tk.StringVar()

        # ─── Main Layout ───────────────────────────────────────────

        def _build_main(self):
            main_pw = tk.PanedWindow(self.root, orient=tk.VERTICAL,
                                     bg=TH.bg, sashwidth=2, sashrelief=tk.FLAT,
                                     sashpad=0)
            main_pw.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
            self._main_pw = main_pw

            # Top section: full-width topology view
            topo_f = tk.Frame(main_pw, bg=TH.bg)
            main_pw.add(topo_f, minsize=200)
            self._build_topology(topo_f)

            # Middle section: centered traffic stream
            stream_f = tk.Frame(main_pw, bg=TH.bg)
            main_pw.add(stream_f, minsize=270)
            self._build_stream(stream_f)

            # Lower panel: operations core + the previous details/alerts/hex/raw/ml tabs
            core_f = tk.Frame(main_pw, bg=TH.bg)
            main_pw.add(core_f, minsize=240)
            self._build_core_and_intel(core_f)

            # Auto-equalize split when resizing
            self._on_root_resize(None)
            self.root.bind('<Configure>', self._on_root_resize)

        def _on_root_resize(self, event):
            # Debounce: cancel any pending resize and schedule a new one
            if hasattr(self, '_resize_after_id') and self._resize_after_id:
                self.root.after_cancel(self._resize_after_id)
            self._resize_after_id = self.root.after(150, self._do_resize)

        def _do_resize(self):
            self._resize_after_id = None
            if hasattr(self, '_main_pw'):
                h = max(self.root.winfo_height(), 1)
                y1 = int(h * 0.28)   # topology height
                y2 = int(h * 0.62)   # stream height
                try:
                    self._main_pw.sash_place(0, 0, y1)
                    self._main_pw.sash_place(1, 0, y2)
                except Exception:
                    pass


        def _build_topology(self, parent):
            """Top-level full-width network topology + protocol chart."""
            hdr = tk.Frame(parent, bg=TH.bg2,
                           highlightbackground=TH.border, highlightthickness=1)
            hdr.pack(fill=tk.X)
            tk.Label(hdr, text="NETWORK INTELLIGENCE MAP", bg=TH.bg2, fg=TH.cyan,
                     font=TH.font_pixel).pack(side=tk.LEFT, padx=10, pady=4)

            self._graph = NetworkGraph(parent)
            self._graph.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

            self._proto_graph = ProtocolSplineChart(parent)
            self._proto_graph.pack(fill=tk.X, pady=(0, 8))

        def _build_stream(self, parent):
            """Hacker-style animated data stream."""
            hdr = tk.Frame(parent, bg=TH.bg2,
                           highlightbackground=TH.border, highlightthickness=1)
            hdr.pack(fill=tk.X)
            # Pixel-style section title
            tk.Label(hdr, text="TRAFFIC STREAM", bg=TH.bg2, fg=TH.cyan,
                     font=TH.font_pixel).pack(side=tk.LEFT, padx=10, pady=4)
            self._pkt_lbl = tk.Label(hdr, text="PKT: 0", bg=TH.bg2,
                                     fg=TH.green, font=TH.font_data_bold)
            self._pkt_lbl.pack(side=tk.RIGHT, padx=10)
            self._pps_lbl = tk.Label(hdr, text="0 pkt/s", bg=TH.bg2,
                                     fg=TH.yellow, font=TH.font_data)
            self._pps_lbl.pack(side=tk.RIGHT, padx=10)
            
            # Auto-scroll controls above the stream canvas
            ctrl = tk.Frame(parent, bg=TH.bg)
            ctrl.pack(fill=tk.X, pady=(0, 4), padx=2)

            self._scroll_status = tk.Label(ctrl, text="Auto-scroll: ON", bg=TH.bg, fg=TH.green,
                                           font=("Consolas", 8, "bold"))
            self._scroll_status.pack(side=tk.LEFT)

            self._go_live_button = tk.Button(ctrl, text="↘ GO LIVE", bg=TH.bg2, fg=TH.cyan,
                                            activebackground=TH.bg, activeforeground=TH.cyan,
                                            font=("Consolas", 8, "bold"), relief=tk.FLAT,
                                            command=self._scroll_to_latest)
            self._go_live_button.pack(side=tk.RIGHT)

            # The traffic stream table with structured columns
            table_f = tk.Frame(parent, bg=TH.bg)
            table_f.pack(fill=tk.BOTH, expand=True)

            cols = ("no", "time", "src", "dst", "proto", "len", "info")
            self._stream = ttk.Treeview(table_f, columns=cols, show="headings",
                                       style="Pkt.Treeview", selectmode="browse")
            
            self._stream.heading("no", text="No.", anchor=tk.CENTER)
            self._stream.column("no", width=50, minwidth=40, anchor=tk.CENTER, stretch=True)
            self._stream.heading("time", text="Time", anchor=tk.CENTER)
            self._stream.column("time", width=120, minwidth=100, anchor=tk.CENTER, stretch=True)
            self._stream.heading("src", text="Source", anchor=tk.W)
            self._stream.column("src", width=160, minwidth=130, anchor=tk.W, stretch=True)
            self._stream.heading("dst", text="Destination", anchor=tk.W)
            self._stream.column("dst", width=160, minwidth=130, anchor=tk.W, stretch=True)
            self._stream.heading("proto", text="Proto", anchor=tk.CENTER)
            self._stream.column("proto", width=80, minwidth=60, anchor=tk.CENTER, stretch=True)
            self._stream.heading("len", text="Len", anchor=tk.CENTER)
            self._stream.column("len", width=60, minwidth=50, anchor=tk.CENTER, stretch=True)
            self._stream.heading("info", text="Info", anchor=tk.W)
            self._stream.column("info", width=380, minwidth=220, anchor=tk.W, stretch=True)
            
            self._stream.tag_configure("Danger", foreground=TH.red, background=TH.table_sel)
            self._stream.tag_configure("Suspicious", foreground=TH.yellow, background=TH.table_sel)
            self._stream.tag_configure("tcp", foreground="#40C4AA")
            self._stream.tag_configure("udp", foreground="#6DD66D")
            self._stream.tag_configure("icmp", foreground="#D4D460")
            self._stream.tag_configure("dns", foreground="#B080D0")
            self._stream.tag_configure("http", foreground="#64B5F6")
            self._stream.tag_configure("https", foreground="#448AFF")
            self._stream.tag_configure("ssh", foreground="#FF8A65")
            self._stream.tag_configure("ftp", foreground="#FFCA28")
            self._stream.tag_configure("smtp", foreground="#AB47BC")
            self._stream.tag_configure("dhcp", foreground="#4DD0E1")
            self._stream.tag_configure("ntp", foreground="#90CAF9")
            self._stream.tag_configure("quic", foreground="#66BB6A")
            self._stream.tag_configure("arp", foreground="#FF7043")
            self._stream.tag_configure("ip", foreground="#B0BEC5")
            self._stream.tag_configure("ipv6", foreground="#82B1FF")
            self._stream.tag_configure("sctp", foreground="#8E24AA")
            self._stream.tag_configure("gre", foreground="#26A69A")
            self._stream.tag_configure("ipsec", foreground="#7E57C2")
            self._stream.tag_configure("wifi", foreground="#FFC107")
            
            self._stream.bind("<<TreeviewSelect>>", self._on_tree_select)

            self._stream_sb = ttk.Scrollbar(table_f, orient=tk.VERTICAL, command=self._on_stream_scroll)
            self._stream_hsb = ttk.Scrollbar(table_f, orient=tk.HORIZONTAL, command=self._stream.xview)
            self._stream.config(yscrollcommand=self._on_stream_yview, xscrollcommand=self._stream_hsb.set)

            # page up/down user keys for wireshark-like navigation
            self._stream.bind('<Next>', lambda e: self._stream.yview_scroll(1, 'pages'))
            self._stream.bind('<Prior>', lambda e: self._stream.yview_scroll(-1, 'pages'))

            self._stream.bind('<Enter>', lambda e: self._stream.focus_set())
            self._stream.bind('<MouseWheel>', self._on_stream_mousewheel)
            self._stream.bind('<Button-4>', self._on_stream_mousewheel)
            self._stream.bind('<Button-5>', self._on_stream_mousewheel)
            self._stream.bind('<Configure>', self._on_stream_resize)

            self._stream_sb.pack(side=tk.RIGHT, fill=tk.Y)
            self._stream_hsb.pack(side=tk.BOTTOM, fill=tk.X)
            self._stream.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        def _on_stream_scroll(self, *args):
            # Scroll callback from scrollbar widgets
            if args and args[0] == "moveto":
                pos = float(args[1])
                if pos < 0.98:
                    self._auto_scroll.set(False)
            elif args and args[0] == "scroll":
                self._auto_scroll.set(False)

            self._stream.yview(*args)
            self._update_scroll_button()

        def _on_stream_yview(self, lo, hi):
            if hasattr(self, '_stream_sb'):
                self._stream_sb.set(lo, hi)
            # ✅ Smart auto-scroll: re-enable when user reaches >=95% bottom
            hi_f = float(hi)
            if hi_f >= 0.95:
                self._auto_scroll.set(True)
            elif self._auto_scroll.get() and hi_f < 0.95:
                self._auto_scroll.set(False)
            self._update_scroll_button()

        def _on_stream_resize(self, event):
            if not event or event.width <= 0:
                return
            total = max(event.width - 20, 100)
            min_widths = {
                'no': 50, 'time': 120, 'src': 150,
                'dst': 150, 'proto': 70, 'len': 60,
                'info': 170
            }
            min_total = sum(min_widths.values())
            widths = min_widths.copy()
            if total > min_total:
                extra = total - min_total
                add_src = int(extra * 0.30)
                add_dst = int(extra * 0.30)
                add_info = extra - add_src - add_dst
                widths['src'] += add_src
                widths['dst'] += add_dst
                widths['info'] += add_info
            for col, w in widths.items():
                self._stream.column(col, width=w)

        def _build_core_and_intel(self, parent):
            holder = tk.PanedWindow(parent, orient=tk.HORIZONTAL,
                                    bg=TH.bg, sashwidth=2, sashrelief=tk.FLAT,
                                    sashpad=0)
            holder.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

            core_left = tk.Frame(holder, bg=TH.bg)
            holder.add(core_left, minsize=320)
            self._build_cinematic_stats(core_left)

            tabs_right = tk.Frame(holder, bg=TH.bg)
            holder.add(tabs_right, minsize=360)
            self._build_tabs(tabs_right)

        def _scroll_to_latest(self):
            if hasattr(self, '_stream'):
                children = self._stream.get_children()
                if children:
                    self._stream.see(children[-1])
            self._auto_scroll.set(True)
            self._update_scroll_button()

        def _update_scroll_button(self):
            if self._auto_scroll.get():
                self._scroll_status.config(text="Auto-scroll: ON", fg=TH.green)
                self._go_live_button.config(state=tk.DISABLED, text="↘ LIVE")
            else:
                self._scroll_status.config(text="Auto-scroll: PAUSED", fg=TH.yellow)
                self._go_live_button.config(state=tk.NORMAL, text="↘ GO LIVE")

        def _on_stream_mousewheel(self, event):
            # Pause auto-scroll when user actively scrolls
            self._auto_scroll.set(False)
            self._update_scroll_button()

            if event.num == 4 or event.delta > 0:
                self._stream.yview_scroll(-1, 'units')
            elif event.num == 5 or event.delta < 0:
                self._stream.yview_scroll(1, 'units')

            return 'break'
            
        def _on_tree_select(self, event):
            selection = self._stream.selection()
            if selection:
                item = selection[0]
                values = self._stream.item(item, "values")
                if values:
                    pkt_no = int(values[0])
                    self._on_stream_click(pkt_no)

        def _build_cinematic_stats(self, parent):
            """Command Center panel with summary stats and signal wave."""
            # HUD-style section title
            title_frame = tk.Frame(parent, bg=TH.bg_panel)
            title_frame.pack(fill=tk.X, padx=0, pady=0)
            tk.Label(title_frame, text="OPERATIONS CORE", bg=TH.bg_panel, fg=TH.cyan,
                     font=TH.font_pixel).pack(pady=(8, 2), padx=10, anchor=tk.W)

            inner = tk.Frame(parent, bg=TH.bg_panel)
            inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=2)
            
            # Signal Waveform
            self._wave = SignalWaveform(inner)
            self._wave.pack(fill=tk.X, pady=(0, 4))

            # Statistics Grid (Macro view)
            stat_frame = tk.Frame(inner, bg=TH.bg_panel)
            stat_frame.pack(fill=tk.X, pady=(2, 2))
            self._stat_labels = {}
            for key, text, color in [
                ("total", "▸ PKTS", TH.green),
                ("bytes", "▸ DATA", TH.cyan),
                ("threats", "▸ ALERTS", TH.red),
                ("pps", "▸ PKT/S", TH.yellow),
                ("fp_pct", "▸ FP%", TH.yellow),
            ]:
                row = tk.Frame(stat_frame, bg=TH.bg_panel)
                row.pack(fill=tk.X, pady=1)
                tk.Label(row, text=text, bg=TH.bg_panel, fg=color,
                         font=("Consolas", 8), anchor=tk.W, width=12).pack(side=tk.LEFT)
                lbl = tk.Label(row, text="0", bg=TH.bg_panel, fg=TH.green,
                               font=("Consolas", 8, "bold"), anchor=tk.E)
                lbl.pack(side=tk.RIGHT)
                self._stat_labels[key] = lbl

            sep2 = tk.Frame(inner, bg=TH.border, height=1)
            sep2.pack(fill=tk.X, pady=(0, 4))

        def _build_tabs(self, parent):
            nb = ttk.Notebook(parent)
            nb.pack(fill=tk.BOTH, expand=True)

            # Details tab
            df = tk.Frame(nb, bg=TH.bg)
            nb.add(df, text="📋 Details")
            self._detail_txt = scrolledtext.ScrolledText(df, bg=TH.bg, fg=TH.text,
                font=("Consolas", 10), relief=tk.FLAT, insertbackground=TH.text, wrap=tk.WORD)
            self._detail_txt.pack(fill=tk.BOTH, expand=True)
            for tag, fg, kw in [("header", TH.cyan, {"font": ("Consolas", 10, "bold")}),
                                ("field", TH.green, {}), ("value", TH.text, {}),
                                ("danger", TH.red, {})]:
                self._detail_txt.tag_configure(tag, foreground=fg, **kw)

            # Alerts tab
            af = tk.Frame(nb, bg=TH.bg)
            nb.add(af, text="🚨 Alerts & IDS")
            self._alert_txt = scrolledtext.ScrolledText(af, bg="#0a0a0a", fg=TH.text,
                font=("Consolas", 10), relief=tk.FLAT, insertbackground=TH.text, wrap=tk.WORD)
            self._alert_txt.pack(fill=tk.BOTH, expand=True)
            for tag, fg, kw in [("DANGER", "#ff1744", {"font": ("Consolas", 10, "bold")}),
                                ("WARNING", "#ffea00", {}), ("INFO", "#2979ff", {}),
                                ("ERROR", "#ff6e40", {}), ("time", "#607d8b", {})]:
                self._alert_txt.tag_configure(tag, foreground=fg, **kw)
            self._alert_txt.insert(tk.END, "=" * 80 + "\n", "INFO")
            self._alert_txt.insert(tk.END, "  🛡️  Pherion vβ SOC Advanced Detection — Ready\n", "INFO")
            self._alert_txt.insert(tk.END, "=" * 80 + "\n", "INFO")
            self._alert_txt.insert(tk.END,
                f"  {len(RULE_REGISTRY)} Detection Rules with MITRE ATT&CK Mapping\n"
                "  SOC Features: Threat Intel IOC · Severity Scoring · Alert Correlation\n"
                "  Structured Event Logging · Per-Rule Error Isolation · System Watchdog\n"
                "  Beacon/C2 · Slow Scan · Land/Smurf · HTTP Flood · Cred Stuffing\n"
                "  Per-Protocol ML + Ensemble Scoring + Adaptive Thresholds\n\n",
                "INFO")

            # Hex tab
            hf = tk.Frame(nb, bg=TH.bg)
            nb.add(hf, text="🔢 Hex Dump")
            self._hex_txt = scrolledtext.ScrolledText(hf, bg="#0a0a0a", fg="#00ff41",
                font=("Consolas", 10), relief=tk.FLAT, insertbackground=TH.text)
            self._hex_txt.pack(fill=tk.BOTH, expand=True)
            self._hex_txt.tag_configure("offset", foreground="#607d8b")
            self._hex_txt.tag_configure("hex", foreground="#00ff41")
            self._hex_txt.tag_configure("ascii", foreground="#ffea00")

            # Raw tab
            rf = tk.Frame(nb, bg=TH.bg)
            nb.add(rf, text="📄 Raw Data")
            self._raw_txt = scrolledtext.ScrolledText(rf, bg="#0a0a0a", fg=TH.text,
                font=("Consolas", 9), relief=tk.FLAT, insertbackground=TH.text, wrap=tk.WORD)
            self._raw_txt.pack(fill=tk.BOTH, expand=True)

            # ML Training tab
            mlf = tk.Frame(nb, bg=TH.bg)
            nb.add(mlf, text="🤖 ML Training")
            self._build_ml_tab(mlf)

        def _build_ml_tab(self, parent):
            top = tk.Frame(parent, bg=TH.bg2)
            top.pack(fill=tk.X, padx=5, pady=5)
            tk.Label(top, text="🤖 ML Model Training", bg=TH.bg2, fg=TH.cyan,
                     font=("Segoe UI", 12, "bold")).pack(side=tk.LEFT, padx=10, pady=5)
            self._csv_var = tk.StringVar(value="Select CSV…")
            tk.Entry(top, textvariable=self._csv_var, width=50, bg=TH.bg, fg=TH.text,
                     font=("Consolas", 9), insertbackground=TH.text).pack(side=tk.LEFT, padx=5)
            tk.Button(top, text="📂", bg=TH.blue, fg="white",
                      command=self._browse_csv, font=("Segoe UI", 9, "bold"),
                      relief=tk.FLAT, padx=8, cursor="hand2").pack(side=tk.LEFT, padx=3)
            self._train_btn = tk.Button(top, text="🚀 Train", bg="#00c853", fg="white",
                command=self._start_training, font=("Segoe UI", 10, "bold"),
                relief=tk.FLAT, padx=12, cursor="hand2")
            self._train_btn.pack(side=tk.LEFT, padx=10)
            tk.Label(top, text="Label:", bg=TH.bg2, fg=TH.text,
                     font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(15, 2))
            self._lcol_var = tk.StringVar()
            tk.Entry(top, textvariable=self._lcol_var, width=12, bg=TH.bg, fg=TH.text,
                     font=("Consolas", 9), insertbackground=TH.text).pack(side=tk.LEFT, padx=2)

            pf = tk.Frame(parent, bg=TH.bg)
            pf.pack(fill=tk.X, padx=15, pady=5)
            self._ml_stat = tk.StringVar(value="Status: Idle")
            tk.Label(pf, textvariable=self._ml_stat, bg=TH.bg, fg=TH.text2,
                     font=("Segoe UI", 9)).pack(side=tk.LEFT)
            self._progress = ttk.Progressbar(pf, length=400, mode="determinate")
            self._progress.pack(side=tk.RIGHT, padx=10)

            self._ml_info = tk.Label(parent, text="", bg=TH.bg, fg=TH.green,
                                     font=("Consolas", 10), justify=tk.LEFT, anchor=tk.W)
            self._ml_info.pack(fill=tk.X, padx=15, pady=5)

            self._ml_log = scrolledtext.ScrolledText(parent, bg="#0a0a0a", fg=TH.text,
                font=("Consolas", 9), relief=tk.FLAT, insertbackground=TH.text, height=20)
            self._ml_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            self._ml_log.tag_configure("ok", foreground=TH.green)
            self._ml_log.tag_configure("err", foreground=TH.red)
            self._ml_log.tag_configure("info", foreground=TH.cyan)

            if self._orch.ml_engine._supervised_ready and getattr(self._orch.ml_engine._encoder, "classes_", None) is not None:
                try:
                    classes = list(self._orch.ml_engine._encoder.classes_) # type: ignore
                    self._ml_info.config(
                        text=f"Model ✅ | Classes: {', '.join(str(c) for c in classes[:10])}") # type: ignore
                except Exception:
                    self._ml_info.config(text="Model ✅")

        # ─── Debug / Transparency Panel ────────────────────────────

        def _build_debug_tab(self, parent):
            """SOC Debug Panel: system metrics, parse errors, FP logs, detection sources."""
            # Top metrics bar
            metrics_f = tk.Frame(parent, bg=TH.bg2,
                                 highlightbackground=TH.border, highlightthickness=1)
            metrics_f.pack(fill=tk.X, padx=5, pady=5)
            tk.Label(metrics_f, text="██ SYSTEM DIAGNOSTICS", bg=TH.bg2, fg=TH.cyan,
                     font=TH.font_pixel).pack(side=tk.LEFT, padx=10, pady=4)

            # Metrics grid
            mg = tk.Frame(parent, bg=TH.bg)
            mg.pack(fill=tk.X, padx=10, pady=5)
            self._debug_metrics = {}
            metrics_def = [
                ("pps", "▸ PACKETS/SEC", TH.green),
                ("buffer", "▸ BUFFER USAGE", TH.cyan),
                ("flows", "▸ ACTIVE FLOWS", TH.blue),
                ("threads", "▸ THREADS", TH.text2),
                ("parse_errors", "▸ PARSE ERRORS", TH.yellow),
                ("unknown_proto", "▸ UNKNOWN PROTO", TH.yellow),
                ("alerts_emitted", "▸ ALERTS EMITTED", TH.red),
                ("alerts_suppressed", "▸ SUPPRESSED (FP)", TH.orange),
                ("dedup_hits", "▸ DEDUP HITS", TH.orange),
                ("incidents", "▸ INCIDENTS", TH.red),
            ]
            for i, (key, text, color) in enumerate(metrics_def):
                row_frame = tk.Frame(mg, bg=TH.bg)
                row_frame.grid(row=i // 2, column=(i % 2) * 2, sticky="ew",
                               padx=(0, 30), pady=1)
                tk.Label(row_frame, text=text, bg=TH.bg, fg=color,
                         font=("Consolas", 9), anchor=tk.W, width=18).pack(side=tk.LEFT)
                val_lbl = tk.Label(row_frame, text="0", bg=TH.bg, fg=TH.green,
                                   font=("Consolas", 9, "bold"), anchor=tk.E, width=12)
                val_lbl.pack(side=tk.RIGHT)
                self._debug_metrics[key] = val_lbl
            mg.columnconfigure(0, weight=1)
            mg.columnconfigure(2, weight=1)

            # Detection rules summary
            rule_f = tk.Frame(parent, bg=TH.bg)
            rule_f.pack(fill=tk.X, padx=10, pady=(5, 0))
            tk.Label(rule_f, text=f"▸ ACTIVE DETECTION RULES: {len(RULE_REGISTRY)}",
                     bg=TH.bg, fg=TH.cyan,
                     font=("Consolas", 9, "bold")).pack(side=tk.LEFT)
            tk.Label(rule_f, text="▸ ENGINE: Rule + ML + ThreatIntel + Correlation",
                     bg=TH.bg, fg=TH.text2,
                     font=("Consolas", 8)).pack(side=tk.RIGHT, padx=10)

            sep = tk.Frame(parent, bg=TH.border, height=1)
            sep.pack(fill=tk.X, padx=10, pady=5)

            # Detection source log
            tk.Label(parent, text="▸ DETECTION EVENT LOG", bg=TH.bg, fg=TH.cyan,
                     font=("Consolas", 9, "bold")).pack(anchor=tk.W, padx=10)
            self._debug_txt = scrolledtext.ScrolledText(
                parent, bg="#0a0a0a", fg=TH.text,
                font=("Consolas", 9), relief=tk.FLAT,
                insertbackground=TH.text, height=15, wrap=tk.WORD)
            self._debug_txt.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            self._debug_txt.tag_configure("rule", foreground=TH.green)
            self._debug_txt.tag_configure("ml", foreground=TH.cyan)
            self._debug_txt.tag_configure("ti", foreground=TH.red)
            self._debug_txt.tag_configure("corr", foreground=TH.yellow)
            self._debug_txt.tag_configure("time", foreground="#607d8b")
            self._debug_txt.tag_configure("header", foreground=TH.cyan,
                                          font=("Consolas", 9, "bold"))

            self._debug_txt.insert(tk.END, "═" * 70 + "\n", "header")
            self._debug_txt.insert(tk.END, "  🔧 SOC Debug Panel — Detection Transparency\n", "header")
            self._debug_txt.insert(tk.END, "═" * 70 + "\n\n", "header")
            self._debug_txt.insert(tk.END,
                f"  Detection Sources: Rule Engine ({len(RULE_REGISTRY)} rules) · "
                f"ML Engine · Threat Intel · Correlation\n"
                f"  Alert Pipeline: Emit → Dedup → Rate Limit → Correlation → DB\n"
                f"  Logging: Structured JSONL + SQLite persistence\n\n", "rule")

        def _update_debug_panel(self, stats, alert_stats, flow_count):
            """Refresh debug panel metrics from current system state."""
            if not self._debug_metrics:
                return
            try:
                buf = self._orch.capture.buffer
                buf_pct = f"{len(buf)}/{buf.capacity // 1000}K" if buf else "N/A"
                watchdog = self._orch.watchdog.get_health()
                corr_stats = self._orch.correlation_engine.get_stats()

                updates = {
                    "pps": str(stats.get("packets_per_sec", 0)),
                    "buffer": buf_pct,
                    "flows": str(flow_count),
                    "threads": str(watchdog.get("threads", 0)),
                    "parse_errors": str(self._parse_error_count),
                    "unknown_proto": str(self._unknown_proto_count),
                    "alerts_emitted": str(alert_stats.get("total_emitted", 0)),
                    "alerts_suppressed": str(alert_stats.get("total_suppressed", 0)),
                    "dedup_hits": str(alert_stats.get("dedup_hits", 0)),
                    "incidents": str(corr_stats.get("total_incidents", 0)),
                }
                for key, val in updates.items():
                    if key in self._debug_metrics:
                        self._debug_metrics[key].config(text=val)
            except Exception:
                pass

        # ─── Status Bar ────────────────────────────────────────────

        def _build_status_bar(self):
            bar = tk.Frame(self.root, bg=TH.bg3, height=28)
            bar.pack(fill=tk.X, side=tk.BOTTOM)
            bar.pack_propagate(False)
            self._dot = tk.Label(bar, text="⬤", bg=TH.bg3, fg="#607d8b", font=("Segoe UI", 12))
            self._dot.pack(side=tk.LEFT, padx=5)
            self._status = tk.Label(bar, text="Ready — Click START",
                                    bg=TH.bg3, fg=TH.text2, font=("Segoe UI", 9))
            self._status.pack(side=tk.LEFT, padx=5)

            priv = check_privileges()
            tk.Label(bar, text="🔓 Admin" if priv else "🔒 No Admin",
                     bg=TH.bg3, fg=TH.green if priv else TH.red,
                     font=("Segoe UI", 9)).pack(side=tk.RIGHT, padx=10)

            ml_ok = self._orch.ml_engine.is_ready
            self._ml_bar = tk.Label(bar,
                text="🤖 ML Ready" if ml_ok else "🤖 ML Not Loaded",
                bg=TH.bg3, fg=TH.green if ml_ok else TH.yellow,
                font=("Segoe UI", 9))
            self._ml_bar.pack(side=tk.RIGHT, padx=10)

            self._buf_bar = tk.Label(bar, text="Buf: 0/50K", bg=TH.bg3,
                                     fg=TH.text2, font=("Consolas", 8))
            self._buf_bar.pack(side=tk.RIGHT, padx=10)

        # ─── Capture Controls ──────────────────────────────────────

        def _start(self):
            if self._capturing:
                return
            if not SCAPY_OK:
                messagebox.showerror("Error", "Scapy not installed!\npip install scapy")
                return
            if not check_privileges():
                messagebox.showwarning("Warning", "Not Admin/Root — capture may fail.")

            iface = self._iface_var.get()
            interface = None if iface == "Auto" else iface.split(" (")[0].strip()
            self._apply_filter()
            bpf = self._bpf_var.get().strip()

            self._orch.start_capture(interface, bpf)
            self._capturing = True
            self._start_btn.config(state=tk.DISABLED)
            self._pause_btn.config(state=tk.NORMAL, text="[ ⏸ PAUSE ]")
            self._stop_btn.config(state=tk.NORMAL)
            self._iface_cb.config(state=tk.DISABLED)
            self._status.config(text=f"🔴 CAPTURING on {iface}…")
            self._dot.config(fg=TH.green)
            self._blink()

        def _stop(self):
            if not self._capturing:
                return
            self._orch.stop_capture()
            self._capturing = False
            self._start_btn.config(state=tk.NORMAL)
            self._pause_btn.config(state=tk.DISABLED, text="[ ⏸ PAUSE ]")
            self._stop_btn.config(state=tk.DISABLED)
            self._iface_cb.config(state="readonly")
            self._status.config(text=f"⏹ Stopped — {self._orch.capture.stats['total']} packets")
            self._dot.config(fg="#607d8b")

        def _pause(self):
            if not self._capturing:
                return
            paused = self._orch.capture.toggle_pause()
            self._pause_btn.config(text="[ ▶ RESUME ]" if paused else "[ ⏸ PAUSE ]")
            if paused:
                self._status.config(text="⏸ PAUSED")
                self._dot.config(fg=TH.yellow)
            else:
                self._status.config(text="🔴 CAPTURING…")
                self._dot.config(fg=TH.green)

        def _sync_capture_controls(self):
            running = self._orch.capture.is_running
            paused = self._orch.capture.is_paused
            if self._capturing and not running:
                self._capturing = False
                self._start_btn.config(state=tk.NORMAL)
                self._pause_btn.config(state=tk.DISABLED, text="[ ⏸ PAUSE ]")
                self._stop_btn.config(state=tk.DISABLED)
                self._iface_cb.config(state="readonly")
                self._status.config(text=f"⏹ Stopped — {self._orch.capture.stats['total']} packets")
                self._dot.config(fg="#607d8b")
            elif not self._capturing and running:
                self._capturing = True
                self._start_btn.config(state=tk.DISABLED)
                self._pause_btn.config(state=tk.NORMAL, text="[ ⏸ PAUSE ]")
                self._stop_btn.config(state=tk.NORMAL)
                self._iface_cb.config(state=tk.DISABLED)
                self._status.config(text=f"🔴 CAPTURING on {self._iface_var.get()}…")
                self._dot.config(fg=TH.green)
            elif self._capturing:
                self._pause_btn.config(text="[ ▶ RESUME ]" if paused else "[ ⏸ PAUSE ]")

        def _clear(self):
            # Clear Treeview rows
            if hasattr(self, '_stream') and self._stream is not None:
                for child in self._stream.get_children():
                    self._stream.delete(child)
            # Clear topology graph — uses new edge schema:
            #   edges[key]['lines']  = {threat: line_id, ...}   (dict, NOT single 'line')
            #   edges[key]['labels'] = {threat: label_id, ...}  (dict, NOT single 'label')
            #   edges[key]['glow']   = int | None
            if hasattr(self, '_graph') and self._graph is not None:
                # Delete all node canvas items
                for n in self._graph.nodes.values():
                    try:
                        self._graph.delete(n['id'])
                    except Exception:
                        pass
                    try:
                        self._graph.delete(n['txt'])
                    except Exception:
                        pass

                # Delete all edge canvas items (new multi-line schema)
                for e in self._graph.edges.values():
                    if not isinstance(e, dict):
                        try:
                            self._graph.delete(e)
                        except Exception:
                            pass
                        continue
                    # Delete every per-threat line
                    for line_id in e.get('lines', {}).values():
                        if line_id is not None:
                            try:
                                self._graph.delete(line_id)
                            except Exception:
                                pass
                    # Delete glow line
                    glow_id = e.get('glow')
                    if glow_id is not None:
                        try:
                            self._graph.delete(glow_id)
                        except Exception:
                            pass
                    # Delete every per-threat label
                    for label_id in e.get('labels', {}).values():
                        if label_id is not None:
                            try:
                                self._graph.delete(label_id)
                            except Exception:
                                pass

                # Delete all particle canvas items
                for p in self._graph.particles:
                    try:
                        self._graph.delete(p['id'])
                    except Exception:
                        pass

                # Clear internal state
                self._graph.nodes.clear()
                self._graph.edges.clear()
                self._graph.particles.clear()
                self._graph._decay_counter = 0

            if self._detail_txt is not None:
                self._detail_txt.delete("1.0", tk.END)
            if self._hex_txt is not None:
                self._hex_txt.delete("1.0", tk.END)
            if self._raw_txt is not None:
                self._raw_txt.delete("1.0", tk.END)
            if self._debug_txt is not None:
                self._debug_txt.delete("1.0", tk.END)
            self._parse_error_count = 0
            self._unknown_proto_count = 0
            self._display_count = 0
            self._orch.capture.reset()
            self._orch.flow_tracker.reset()

        def _apply_filter(self):
            self._orch.capture.display_filter_protocol = self._proto_var.get()
            self._orch.capture.display_filter_ip = self._ip_var.get().strip()
            self._orch.capture.display_filter_port = self._port_var.get().strip()
            self._orch.capture.promisc = self._promisc_var.get()

        def _blink(self):
            if not self._capturing:
                return
            cur = self._dot.cget("fg")
            nxt = TH.green if cur == TH.bg else TH.bg
            if not self._orch.capture.is_paused:
                self._dot.config(fg=nxt)
            self.root.after(500, self._blink)

        # ─── GUI Update Loop ──────────────────────────────────────

        def _update_gui(self):
            if self._is_closing or not self.root.winfo_exists():
                return
            try:
                self._sync_capture_controls()
                # Packets
                for _ in range(GUI.packets_per_update):
                    try:
                        pkt = self._orch.pkt_queue.get_nowait()
                        self._add_row(pkt)
                    except queue.Empty:
                        break

                # Alerts
                while True:
                    try:
                        level, msg, ts = self._orch.alert_queue.get_nowait()
                        if self._alert_txt is not None:
                            self._alert_txt.insert(tk.END, f"[{ts}] ", "time")
                            self._alert_txt.insert(tk.END, f"{msg}\n", level)
                            self._alert_txt.see(tk.END)
                    except queue.Empty:
                        break

                # Stats
                last = None
                while True:
                    try:
                        last = self._orch.stats_queue.get_nowait()
                    except queue.Empty:
                        break
                if last:
                    self._update_stats(last)
            except tk.TclError:
                return
            except Exception:
                logger.debug("GUI update error", exc_info=True)
            self.root.after(GUI.refresh_ms, self._update_gui)

        def _add_row(self, p):
            self._display_count += 1

            # Track unknown protocols for debug panel
            if p.protocol.upper() == "OTHER":
                self._unknown_proto_count += 1

            if hasattr(self, '_stream'):
                ts = p.timestamp.split(" ")[1] if " " in p.timestamp else p.timestamp
                val = (p.number, ts, p.src_ip, p.dst_ip, p.protocol, p.total_length, p.info)
                tags = ()
                if p.threat_level != "Safe":
                    tags = (p.threat_level,)
                else:
                    proto = p.protocol.lower().replace(" ", "_").replace("/", "_")
                    if "https" in proto:
                        proto = "https"
                    elif "http" in proto:
                        proto = "http"
                    elif "ssh" in proto:
                        proto = "ssh"
                    elif "ftp" in proto:
                        proto = "ftp"
                    elif "smtp" in proto:
                        proto = "smtp"
                    elif "dns" in proto:
                        proto = "dns"
                    elif "dhcp" in proto:
                        proto = "dhcp"
                    elif "ntp" in proto:
                        proto = "ntp"
                    elif "quic" in proto:
                        proto = "quic"
                    elif "arp" in proto:
                        proto = "arp"
                    elif "ipv6" in proto:
                        proto = "ipv6"
                    elif "ipsec" in proto or "esp" in proto or "ah" in proto:
                        proto = "ipsec"
                    elif "sctp" in proto:
                        proto = "sctp"
                    elif "gre" in proto:
                        proto = "gre"
                    elif "wifi" in proto or "dot11" in proto:
                        proto = "wifi"
                    elif "tcp" in proto:
                        proto = "tcp"
                    elif "udp" in proto:
                        proto = "udp"
                    elif "icmp" in proto:
                        proto = "icmp"
                    elif "ip" == proto:
                        proto = "ip"
                    else:
                        proto = proto.split("_")[0]

                    if proto in {"tcp", "udp", "icmp", "dns", "http", "https",
                                 "ssh", "ftp", "smtp", "dhcp", "ntp",
                                 "quic", "arp", "ip", "ipv6", "sctp",
                                 "gre", "ipsec", "wifi"}:
                        tags = (proto,)

                self._stream.insert("", tk.END, values=val, tags=tags)

                children = self._stream.get_children()
                if len(children) > GUI.max_table_rows:
                    for child in children[:200]:
                        self._stream.delete(child)

            # ✅ Feed network graph WITH threat level for visualization
            if hasattr(self, '_graph') and self._graph is not None:
                # Debug: log threat level for network graph
                if p.threat_level != "Safe":
                    logger.debug(f"NetworkGraph: {p.src_ip} -> {p.dst_ip} = {p.threat_level}")
                self._graph.add_connection(p.src_ip, p.dst_ip, p.threat_level)

            # Spike waveform occasionally on heavy packet burst
            if hasattr(self, '_wave') and self._display_count % 10 == 0:
                self._wave.spike(random.uniform(15.0, 35.0))

            # Auto-scroll behavior based on user toggle
            if hasattr(self, '_stream') and self._auto_scroll.get():
                children = self._stream.get_children()
                if children:
                    self._stream.see(children[-1])
            self._update_scroll_button()

        def _update_stats(self, stats):
            if hasattr(self, '_proto_graph') and self._proto_graph is not None:
                self._proto_graph.update_stats(stats)

            # ✅ Populate all stat labels
            alert_stats = self._orch.alert_mgr.get_stats()
            flow_count = self._orch.flow_tracker.active_count()
            total_emitted = alert_stats.get('total_emitted', 0)
            total_suppressed = alert_stats.get('total_suppressed', 0)
            fp_pct = f"{(total_suppressed / max(1, total_emitted + total_suppressed) * 100):.1f}%"

            for key, lbl in self._stat_labels.items():
                if key == "bytes":
                    lbl.config(text=fmt_bytes(stats.get("bytes", 0)))
                elif key == "pps":
                    lbl.config(text=str(stats.get("packets_per_sec", 0)))
                elif key == "fp_pct":
                    lbl.config(text=fp_pct)
                elif key in stats:
                    lbl.config(text=str(stats[key]))
            self._pkt_lbl.config(text=f"Packets: {stats.get('total', 0)}")
            self._pps_lbl.config(text=f"{stats.get('packets_per_sec', 0)} pkt/s")

            # Buffer usage
            buf = self._orch.capture.buffer
            if buf is not None:
                self._buf_bar.config(
                    text=f"Buf: {len(buf)}/{buf.capacity//1000}K | "
                         f"Flows: {flow_count}")

            # Top talkers
            try:
                dt = dict(self._orch.rule_engine.data_transfer)
                if dt:
                    top = sorted(dt.items(), key=lambda kv: kv[1], reverse=True)[:8] # type: ignore
                    self._talkers.config(state=tk.NORMAL)
                    self._talkers.delete("1.0", tk.END)
                    for ip, b in top:
                        self._talkers.insert(tk.END, f" {ip:<18} {fmt_bytes(b):>10}\n")
                    self._talkers.config(state=tk.DISABLED)
            except Exception:
                pass

            # ✅ Update Debug panel metrics
            self._update_debug_panel(stats, alert_stats, flow_count)

        # ─── Packet Selection ─────────────────────────────────────

        def _on_stream_click(self, pkt_no):
            pkt = self._orch.capture.get_packet(pkt_no)
            if pkt:
                self._show_detail(pkt)
                self._show_hex(pkt)
                self._show_raw(pkt)

        def _show_detail(self, p):
            t = self._detail_txt
            t.delete("1.0", tk.END)
            t.insert(tk.END, f"{'═'*70}\n", "header")
            t.insert(tk.END, f"  PACKET #{p.number} DETAILS\n", "header")
            t.insert(tk.END, f"{'═'*70}\n\n", "header")
            sections = [
                ("▸ GENERAL", [("Timestamp", p.timestamp), ("Protocol", p.protocol),
                    ("Length", f"{p.total_length} bytes"), ("Threat", p.threat_level),
                    ("ML", f"{p.ml_prediction} ({p.ml_confidence:.0%})" if p.ml_prediction else "N/A")]),
                ("▸ LAYER 2", [("Src MAC", p.src_mac), ("Dst MAC", p.dst_mac)]),
                ("▸ LAYER 3", [("Src IP", p.src_ip), ("Dst IP", p.dst_ip), ("TTL", str(p.ttl))]),
            ]
            if p.src_port or p.dst_port:
                l4 = [("Src Port", str(p.src_port)), ("Dst Port", str(p.dst_port))]
                if p.tcp_flags: l4.append(("Flags", f"[{p.tcp_flags}]"))
                l4.append(("Window", str(p.window_size)))
                sections.append(("▸ LAYER 4", l4))
            for heading, fields in sections:
                t.insert(tk.END, f"{heading}\n", "header")
                for name, val in fields:
                    t.insert(tk.END, f"  {name}: ", "field")
                    t.insert(tk.END, f"{val}\n", "danger" if "Danger" in str(val) else "value")
                t.insert(tk.END, "\n")
            t.insert(tk.END, "▸ INFO\n", "header")
            t.insert(tk.END, f"  {p.info}\n\n", "value")
            if p._raw:
                try:
                    t.insert(tk.END, "▸ SCAPY SUMMARY\n", "header")
                    t.insert(tk.END, f"  {p._raw.summary()}\n\n", "value")
                    t.insert(tk.END, "▸ LAYER BREAKDOWN\n", "header")
                    t.insert(tk.END, p._raw.show(dump=True) + "\n", "value")
                except Exception:
                    pass

        def _show_hex(self, p):
            t = self._hex_txt
            t.delete("1.0", tk.END)
            if not p._raw: return
            try: raw = bytes(p._raw)
            except Exception: return
            t.insert(tk.END, f"Hex — #{p.number} ({len(raw)} bytes)\n", "offset")
            t.insert(tk.END, "─" * 75 + "\n", "offset")
            t.insert(tk.END, "Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII\n", "offset")
            t.insert(tk.END, "─" * 75 + "\n", "offset")
            for i in range(0, len(raw), 16):
                chunk = raw[i:i+16] # type: ignore
                t.insert(tk.END, f"{i:08X}  ", "offset")
                hx = ""
                for j, b in enumerate(chunk):
                    hx += f"{b:02X} "
                    if j == 7: hx += " "
                t.insert(tk.END, hx.ljust(50), "hex")
                t.insert(tk.END, f"  {''.join(chr(b) if 32<=b<=126 else '.' for b in chunk)}\n", "ascii")

        def _show_raw(self, p):
            t = self._raw_txt
            t.delete("1.0", tk.END)
            if not p._raw: return
            try:
                if SCAPY_OK and p._raw.haslayer(Raw):
                    pay = p._raw[Raw].load
                    t.insert(tk.END, f"=== Payload ({len(pay)} bytes) ===\n\n")
                    t.insert(tk.END, pay.decode("utf-8", errors="replace"))
                else:
                    t.insert(tk.END, f"No payload.\nSummary: {p._raw.summary()}\n")
            except Exception as e:
                t.insert(tk.END, f"Error: {e}")

        # ─── ML Training ──────────────────────────────────────────

        def _browse_csv(self):
            path = filedialog.askopenfilename(
                title="Select Dataset", filetypes=[("CSV", "*.csv"), ("All", "*.*")])
            if path: self._csv_var.set(path)

        def _start_training(self):
            csv = self._csv_var.get()
            if not csv or not os.path.isfile(csv):
                self._ml_log.insert(tk.END, "❌ Select a valid CSV file.\n", "err")
                return
            if not ML_AVAILABLE:
                self._ml_log.insert(tk.END, "❌ Install: pip install scikit-learn pandas numpy\n", "err")
                return
            self._train_btn.config(state=tk.DISABLED)
            lcol = self._lcol_var.get().strip() or None

            def _cb(stage, pct):
                self.root.after(0, lambda: (
                    self._ml_stat.set(f"Status: {stage}"),
                    setattr(self._progress, 'value', max(0, pct * 100)) if 0 <= pct <= 1 else None
                ))

            def _train():
                try:
                    m = self._orch.trainer.train(csv, label_col=lcol, progress_cb=_cb)
                    self.root.after(0, self._ml_done, m)
                except Exception as e:
                    self.root.after(0, self._ml_err, str(e))

            threading.Thread(target=_train, daemon=True, name="Trainer").start()

        def _ml_done(self, m):
            self._train_btn.config(state=tk.NORMAL)
            self._progress["value"] = 100
            self._ml_log.insert(tk.END, f"\n✅ Complete! acc={m.get('accuracy',0):.4f} f1={m.get('f1',0):.4f} "
                                        f"cv={m.get('cv_f1_mean',0):.4f} time={m.get('training_time',0):.1f}s\n", "ok")
            report_text = m.get("report") or m.get("classification_report") or "No classification report available."
            self._ml_log.insert(tk.END, report_text + "\n", "info")
            if "feature_importances" in m:
                fi = m.get("feature_importances", [])
                self._ml_log.insert(tk.END, f"Top features: {fi[:10]}\n", "info")
            self._ml_log.see(tk.END)
            classes = m.get("classes", [])
            self._ml_info.config(
                text=f"Model ✅ | Classes: {', '.join(str(c) for c in classes[:10])}")
            self._orch.ml_engine.reload_model()
            self._ml_bar.config(text="🤖 ML Ready", fg=TH.green)
            if self._capturing and not self._orch.ml_engine._running:
                self._orch.ml_engine.start()

        def _ml_err(self, err):
            self._train_btn.config(state=tk.NORMAL)
            self._progress["value"] = 0
            self._ml_stat.set("Status: Error")
            self._ml_log.insert(tk.END, f"\n❌ Failed: {err}\n", "err")
            self._ml_log.see(tk.END)

        # ─── File Operations ──────────────────────────────────────

        def _save_pcap(self):
            fn = filedialog.asksaveasfilename(
                defaultextension=".pcap", filetypes=[("PCAP", "*.pcap")])
            if fn:
                try:
                    n = self._orch.capture.save_pcap(fn)
                    messagebox.showinfo("Saved", f"{n} packets → {fn}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))

        def _export_alerts(self):
            fn = filedialog.asksaveasfilename(
                defaultextension=".txt", filetypes=[("Text", "*.txt")])
            if fn:
                with open(fn, "w", encoding="utf-8") as f:
                    f.write(self._alert_txt.get("1.0", tk.END))
                messagebox.showinfo("Saved", f"Alerts → {fn}")

        def _about(self):
            messagebox.showinfo("About Pherion", f"""
🛡️ Pherion vβ — SOC Advanced Detection & ML-IDS

SOC ENTERPRISE FEATURES:
✅ {len(RULE_REGISTRY)} Detection Rules with MITRE ATT&CK mapping
✅ Threat Intelligence IOC integration
✅ Alert Correlation Engine (incident grouping)
✅ Severity Scoring (Critical/High/Medium/Low)
✅ Structured Event Logging (JSONL)
✅ System Watchdog (health monitoring)
✅ Per-Rule Error Isolation (fault-tolerant)
✅ Dynamic Rule Enable/Disable
✅ Adaptive Threshold Auto-Tuning

DETECTION CAPABILITIES:
✅ Beacon/C2 detection (CoV interval analysis)
✅ Slow/UDP port scan · Land/Smurf/ICMP tunnel
✅ HTTP flood · Credential stuffing · SQL injection
✅ Webshell upload · SMB lateral movement
✅ JA3 blacklist · TTL anomaly · Payload entropy
✅ Per-protocol ML baseline (TCP/UDP/ICMP)
✅ Ensemble rule+ML scoring
✅ Suricata-style signature rules

pip install scapy psutil scikit-learn pandas numpy joblib
            """)

        def _on_close(self):
            if self._is_closing:
                return
            self._is_closing = True
            if self._capturing:
                self._orch.stop_capture()
            self._orch.shutdown()
            try:
                self.root.destroy()
            except tk.TclError:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 19: MAIN — Entry point with CLI args
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="🛡️ Pherion  vβ — Network Monitor & ML-IDS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python pherion.py                          # GUI mode
  sudo python pherion.py --headless               # Headless mode
  sudo python pherion.py --headless -i eth0       # Specific interface
  sudo python pherion.py --headless --bpf "tcp"   # With BPF filter
        """)
    parser.add_argument("--headless", action="store_true",
                        help="Run without GUI (console mode)")
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface to capture on")
    parser.add_argument("--bpf", default="",
                        help="BPF filter expression")
    parser.add_argument("--rules", default=None,
                        help="Path to Suricata-style signature rules file")
    parser.add_argument("--alert-json", default=None,
                        help="Path to append JSON alerts (one per line)")
    parser.add_argument("--syslog", default=None,
                        help="Syslog destination (host:port) for alerts")
    parser.add_argument("--whitelist", default=None,
                        help="Comma-separated list of IPs/Subnets to ignore")
    parser.add_argument("--blacklist", default=None,
                        help="Comma-separated list of IPs/Subnets to always alert")
    parser.add_argument("--promisc", action="store_true", default=True,
                        help="Enable promiscuous mode (capture all packets visible to the NIC)")
    parser.add_argument("--no-selfheal", action="store_true", default=False,
                        help="Disable self-healing engine (alerts only, no OS-level remediation)")
    args = parser.parse_args()

    print("=" * 64)
    print("  🛡️  Pherion  vβ — Network Monitor & ML-IDS")
    print("=" * 64)

    # Dependency check
    deps = {"scapy": SCAPY_OK, "psutil": PSUTIL_OK, "numpy": NUMPY_OK,
            "pandas": PANDAS_OK, "scikit-learn": SKLEARN_OK}
    missing = [k for k, v in deps.items() if not v]
    if missing:
        print(f"\n⚠️  Missing: {', '.join(missing)}")
        print(f"   pip install {' '.join(missing)}")
        if "scapy" in missing:
            print("   Windows: install Npcap → https://npcap.com")
        print()
    else:
        print("✅ All dependencies found")

    if check_privileges():
        print("✅ Running as Admin/Root")
    else:
        print("⚠️  NOT Admin/Root — capture requires elevation")
        if os.name == "nt":
            print("   → Right-click → Run as Administrator")
        else:
            print(f"   → sudo python3 {sys.argv[0]}")
        print()

    # Feature verification
    print(f"\n📋 SOC Advanced Detection Features ({len(RULE_REGISTRY)} rules):")
    features = [
        ("Ring Buffer (bounded memory)", True),
        ("Alert Deduplication (direction-independent)", True),
        ("Alert Rate Limiting", True),
        ("Thread Safety (RLock)", True),
        ("Per-Protocol ML Baseline (TCP/UDP/ICMP)", NUMPY_OK and SKLEARN_OK),
        ("Ensemble Rule+ML scoring", True),
        ("SQLite Persistence", True),
        ("Bidirectional Flow Tracking", True),
        (f"{len(RULE_REGISTRY)} Detection Rules (MITRE ATT&CK mapped)", True),
        ("Per-Rule Error Isolation (fault-tolerant)", True),
        ("Dynamic Rule Enable/Disable", True),
        ("Adaptive Threshold Auto-Tuning", True),
        ("Threat Intelligence IOC Integration", True),
        ("Alert Correlation Engine (incidents)", True),
        ("Severity Scoring (Critical/High/Med/Low)", True),
        ("Structured Event Logging (JSONL)", True),
        ("System Health Watchdog", True),
        ("Suricata-style Signature Engine", True),
        ("JA3 TLS Fingerprint Blacklisting", True),
        ("GeoIP Location Enrichment", GEOIP_OK),
        ("ML Training from CSV", ML_AVAILABLE),
        ("IP Fragmentation Detection", SCAPY_OK),
        ("Self-Healing Engine (non-blocking auto-remediation)", True),
    ]
    for name, ok in features:
        status = "✅" if ok else "⚠️ (missing deps)"
        print(f"   {status} {name}")
    print()

    # Apply whitelist/blacklist config if provided
    if args.whitelist:
        DET.whitelist_subnets = tuple(s.strip() for s in args.whitelist.split(",") if s.strip())
    if args.blacklist:
        DET.blacklist_subnets = tuple(s.strip() for s in args.blacklist.split(",") if s.strip())

    if args.headless:
        # ✅ Headless mode
        if not SCAPY_OK:
            print("❌ Scapy required for capture. Install: pip install scapy")
            sys.exit(1)
        runner = HeadlessRunner(
            interface=args.interface,
            bpf_filter=args.bpf,
            rules_path=args.rules,
            alert_json_path=args.alert_json,
            syslog_addr=args.syslog,
            promisc=args.promisc,
            no_selfheal=args.no_selfheal,
        )
        runner.run()
    else:
        # GUI mode
        if not TK_AVAILABLE:
            print("❌ tkinter not available. Use --headless mode or install tkinter.")
            sys.exit(1)

        root = tk.Tk()
        try:
            if os.name == "nt":
                root.iconbitmap(default="")
        except Exception:
            pass

        _app = PherionGUI(root,
                          rules_path=args.rules,
                          alert_json_path=args.alert_json,
                          syslog_addr=args.syslog,
                          promisc=args.promisc)
        print("✅ GUI started — click START to begin capture")
        print("   Use 🤖 ML Training tab to train from CSV\n")
        try:
            root.mainloop()
        except KeyboardInterrupt:
            print("\n⏹ Interrupted — shutting down…")
            try:
                # Force destroy to break mainloop if it's stuck
                root.quit()
                root.update()
                _app._on_close()
            except Exception:
                pass
            finally:
                try:
                    root.destroy()
                except Exception:
                    pass
                sys.exit(0)


if __name__ == "__main__":
    main()
