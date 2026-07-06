# Security

Pherion captures raw network traffic and, with self-healing enabled, can rate-limit or null-route IPs at your explicit approval. If you spot a way it could leak captured data, take an OS-level remediation action without operator approval, or otherwise misbehave in a way that affects a system beyond the one it's monitoring, I'd like to know.

## Found a problem?

- Open an issue on this repo, or
- Reach out to the maintainer directly (see profile) if it's something sensitive you'd rather not put in a public issue.

When you do, please include:
- Pherion version / commit hash
- OS and Python version
- GUI or `--headless`, and the flags used
- Steps to reproduce
- What actually happened vs. what you expected

## Scope notes

- **Remediation must always require operator approval.** `ManualApprovalGate` is the only path from a detection to a `rate_limit_ip` / `null_route_ip` / TCP RST / ARP flush / flow isolation action. Any path that reaches those actions without an explicit Block/Rate-Limit decision is a security bug worth flagging.
- **Captured payloads and PCAP exports** are written to your local `pherion_data/` directory and are never transmitted off the host by Pherion itself. If you find a code path that sends captured traffic, alerts, or PCAP data anywhere over the network beyond an explicitly configured `--syslog` destination, that's in scope.
- **GeoIP / threat-intel lookups** should only ever operate on IP/domain/hash indicators extracted from traffic metadata — if you find a path where raw payload content (not just header/flow metadata) leaves the host for enrichment, flag it.
- Pherion requires root/Administrator to capture packets — if you find a privilege-escalation path beyond what's needed for raw socket access, that's a serious issue and should be reported privately rather than as a public issue.
