# Pherion — SOC Advanced Detection & ML-Powered IDS

**Pherion** is a Python network intrusion detection system (IDS) that combines a 37-rule, MITRE ATT&CK-mapped detection engine with a per-protocol machine learning baseline, alert correlation, and an optional human-in-the-loop self-healing (auto-remediation) engine. It runs as a desktop GUI (live packet stream, network graph, protocol charts) or fully headless for servers.

```
██████╗ ██╗  ██╗███████╗██████╗ ██╗ ██████╗ ███╗   ██╗
██╔══██╗██║  ██║██╔════╝██╔══██╗██║██╔═══██╗████╗  ██║
██████╔╝███████║█████╗  ██████╔╝██║██║   ██║██╔██╗ ██║
██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██║██║   ██║██║╚██╗██║
██║     ██║  ██║███████╗██║  ██║██║╚██████╔╝██║ ╚████║
╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
```

> **Status:** actively developed personal/SOC-lab security tool. See [Disclaimer](#️-disclaimer).

---

## ✨ Features

- **37 detection rules, MITRE ATT&CK-mapped** — SYN/UDP/slow port scans, NULL/XMAS/FIN scans, ARP spoofing, DNS tunneling/flood, ICMP flood/tunnel, brute force, credential stuffing, SQL injection, webshell upload, SMB lateral movement, data exfiltration, land/smurf/RST/HTTP floods, beacon/C2 detection, JA3 TLS fingerprint blacklisting, TTL anomaly, and payload entropy analysis.
- **Suricata-style signature engine** — write custom lightweight signatures alongside the built-in rules.
- **Per-protocol ML baseline** — TCP, UDP, and ICMP are modelled separately; an ensemble of rule engine + ML vote reduces false positives. Supports supervised training from CSV datasets (CIC-IDS, NSL-KDD, UNSW-NB15) via Random Forest, with optional SMOTE oversampling for imbalanced classes.
- **Threat intelligence & correlation** — IOC feed integration (IP/domain/hash), a correlation engine that groups related alerts into incidents, and Critical/High/Medium/Low severity scoring.
- **Human-in-the-loop self-healing** — on detection, the offending IP's traffic is paused and the operator is prompted (terminal + GUI) to **Block**, **Rate-Limit**, or **Ignore**. Nothing is auto-remediated without an explicit decision; if the operator doesn't respond, the traffic simply stays paused.
- **Production-grade plumbing** — bounded ring buffer (auto-evicting), direction-independent alert deduplication, per-rule rate limiting (10 alerts/min max), thread-safe shared state (RLock everywhere), SQLite persistence for alerts/stats/incidents, bidirectional flow tracking with idle/active timeouts, and per-rule error isolation so one bad rule can't crash the pipeline.
- **Structured logging** — JSONL event log (SIEM-ready), plus optional syslog forwarding.
- **GUI or headless** — full Tkinter dashboard (live packet stream, network graph, waveform/spline/bar charts) or `--headless` console mode for servers and CI-style boxes.
- **PCAP export** and **BPF filter** support for Wireshark follow-up analysis.
- **GeoIP enrichment** (optional) — location-tags alert source IPs if a GeoLite2-City database is present.

---

## 🚀 Getting Started

### Requirements

- Python 3.9+
- Windows, macOS, or Linux
- **Root/Administrator privileges** (raw packet capture requires elevation)
- Windows only: [Npcap](https://npcap.com) installed alongside `scapy`

### Installation

```bash
git clone https://github.com/<your-username>/pherion.git
cd pherion
pip install -r requirements.txt
```

### Run it

```bash
# GUI mode
sudo python pherion.py

# Headless mode
sudo python pherion.py --headless

# Headless, specific interface + BPF filter
sudo python pherion.py --headless --interface eth0 --bpf "tcp port 80"
```

> Windows: run your terminal **as Administrator** instead of using `sudo`.

---

## 🧰 CLI Flags

| Flag | What it does |
|---|---|
| `--headless` | Run without the Tkinter GUI (console mode). |
| `-i`, `--interface` | Network interface to capture on. |
| `--bpf` | Berkeley Packet Filter expression to scope capture. |
| `--rules` | Path to a Suricata-style signature rules file. |
| `--alert-json` | Path to append JSON alerts (one per line). |
| `--syslog` | `host:port` syslog destination for alerts. |
| `--whitelist` | Comma-separated IPs/subnets to always ignore. |
| `--blacklist` | Comma-separated IPs/subnets to always alert on. |
| `--promisc` | Enable promiscuous mode (default on). |
| `--no-selfheal` | Disable the self-healing engine — alerts only, no remediation prompts. |

---

## 📊 How detection works

1. **Capture & parse** — Scapy sniffs raw packets, which are normalized into a `ParsedPacket` and tracked in a bidirectional `FlowTracker`.
2. **Rule engine** — 37 rules run per packet/flow, each isolated so a faulty rule can't take down the pipeline; each match carries a MITRE ATT&CK technique ID.
3. **Signature engine** — an optional Suricata-style ruleset runs alongside the built-in detectors.
4. **ML ensemble** — a per-protocol baseline (TCP/UDP/ICMP modelled separately) votes alongside the rule engine to cut down false positives; models can be trained from labeled CSV datasets.
5. **Correlation & severity** — related alerts are grouped into incidents by the correlation engine and scored Critical/High/Medium/Low.
6. **Self-healing (optional)** — on a match, the attacker IP's traffic is paused and the operator is asked to Block, Rate-Limit, or Ignore — no fully automatic action is ever taken.
7. **Persistence & export** — alerts, stats, and incidents are written to SQLite; structured JSONL events and optional syslog forwarding support SIEM ingestion; captures can be exported to PCAP for Wireshark.

---

## ⚙️ Dependencies

| Package | Required? | Purpose |
|---|---|---|
| `scapy` | ✅ Required | Packet capture and protocol parsing |
| `numpy` | ✅ Required | ML baseline math / feature vectors |
| `pandas` | ✅ Required | CSV dataset loading for ML training |
| `scikit-learn` | ✅ Required | Random Forest classifier, scaling, metrics |
| `joblib` | ✅ Required | Saving/loading trained ML models |
| `psutil` | Optional | System health watchdog (CPU/memory/thread) |
| `imbalanced-learn` | Optional | SMOTE oversampling for imbalanced ML training data |
| `geoip2` | Optional | GeoIP enrichment (needs a local `GeoLite2-City.mmdb`) |
| `tkinter` | Optional | GUI mode (ships with most Python installs) |

Pherion degrades gracefully feature-by-feature if an optional dependency is missing — it prints exactly what's absent and how to install it on startup.

Install everything with:

```bash
pip install -r requirements.txt
```

---

## 📁 Data & output layout

On first run, Pherion creates a `pherion_data/` directory next to the script:

```
pherion_data/
├── db/       # SQLite persistence — alerts, stats, incidents
├── logs/     # daily rotating log + JSONL structured events
├── models/   # trained ML baseline/classifier artifacts
└── pcaps/    # exported packet captures
```

None of `pherion_data/` is committed to this repo — see `.gitignore`.

---

## 🗺️ Roadmap ideas

- [ ] IPv6-first rule coverage parity with IPv4
- [ ] Pluggable notification channels for the approval gate (Slack/webhook, not just terminal+GUI)
- [ ] Config file for whitelist/blacklist/thresholds instead of CLI flags only
- [ ] Additional pretrained baseline models per common network profile (home/SOHO/enterprise)

Have another idea? Open an issue!

---

## 🤝 Contributing

Contributions are welcome! Please read **[CONTRIBUTING.md](CONTRIBUTING.md)** for setup instructions and guidelines before opening a PR.

## 🔒 Security

Found a security issue in Pherion itself? See **[SECURITY.md](SECURITY.md)**.

## ⚠️ Disclaimer

Pherion is an educational/personal SOC-lab tool for monitoring traffic **you own or are explicitly authorized to monitor**. It captures raw packets and, with self-healing enabled, can rate-limit or null-route IPs on your own system at your explicit approval — do not point it at networks you don't control. Detection thresholds are tuned for general use and may need adjustment for your environment; false positives/negatives are possible with any IDS. This is not a substitute for a vetted enterprise SOC/SIEM stack in production-critical environments.

## 📄 License

Released under the [MIT License](LICENSE) — Copyright (c) 2025 Praveen K.
