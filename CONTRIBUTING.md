# Contributing to Pherion

Thanks for your interest in improving Pherion! Contributions are welcome — new detection rules, ML improvements, GUI polish, and documentation fixes all help.

## Getting started

1. Fork the repo and clone your fork.
2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Windows only: install [Npcap](https://npcap.com) so `scapy` can capture packets.
4. Create a branch for your change: `git checkout -b feature/my-improvement`.

## Running it

Packet capture needs elevated privileges:

```bash
sudo python pherion.py                          # GUI mode
sudo python pherion.py --headless               # headless / console mode
sudo python pherion.py --headless -i eth0        # specific interface
sudo python pherion.py --headless --bpf "tcp"    # with a BPF filter
```

If you don't have a spare NIC to generate real traffic against, test against loopback/local traffic first, and confirm the rule/severity/correlation pipeline still runs end-to-end before opening a PR.

## Guidelines

- **New detection rules** go through the `RuleEngine` / `RULE_REGISTRY` pattern — include a MITRE ATT&CK technique ID via `RuleMeta`, and keep the per-packet cost cheap (capture runs continuously, so heavy per-packet computation will bottleneck the pipeline).
- **Isolate failures** — a rule raising an exception must not take down the whole engine; follow the existing per-rule error isolation pattern rather than adding a new unguarded call site.
- **Respect the approval gate** — never wire a new detector directly to an OS-level remediation action (rate-limit, null-route, RST, ARP flush, isolate). All self-healing must go through `ManualApprovalGate` so a human explicitly approves before any traffic is blocked or throttled.
- **Keep offline paths offline** — GeoIP, threat-intel IOC feeds, and any other feature that reaches out to a file/API should degrade gracefully (clear message, feature skipped) if the optional dependency or data file isn't present, exactly like the existing `NUMPY_OK` / `SCAPY_OK` / `GEOIP_OK` guards.
- **No plaintext leakage** — alerts, JSONL events, and SQLite persistence should store structured metadata (IPs, ports, rule, severity, MITRE ID), not raw payload dumps beyond what's needed for triage.
- **Match the existing style** — Rich-free, Tkinter-based GUI using the existing `Theme` class and chart widgets (`NetworkGraph`, `ProtocolBarChart`, etc.) rather than introducing a new UI toolkit; `logging` module for all log output, not raw `print()`, outside of the CLI banner/startup messages.
- **Config, not magic numbers** — new tunable thresholds belong in `DetectionConfig` / `MLConfig` / `CaptureConfig` / `GUIConfig`, not hardcoded inline.

## Reporting bugs / suggesting features

Open a GitHub Issue with your OS/Python version, whether you ran GUI or `--headless`, the command-line flags used, and what happened vs. what you expected. If it's detection-accuracy related (false positive/negative), include the rule name and, if possible, a redacted PCAP snippet that reproduces it.

## Security issues

See [SECURITY.md](SECURITY.md).
