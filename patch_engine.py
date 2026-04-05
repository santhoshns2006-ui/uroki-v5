#!/usr/bin/env python3
"""
Uroki engine.py patcher — fixes PCAP link-type 228 bug.
Run this from your ~/Downloads/urokio/ folder:
    python3 patch_engine.py
"""
import sys, os, shutil, re
from pathlib import Path

TARGET = Path("engine.py")

if not TARGET.exists():
    print("ERROR: engine.py not found. Run this script from ~/Downloads/urokio/")
    sys.exit(1)

# Backup
shutil.copy(TARGET, "engine.py.bak")
print("✓ Backup saved → engine.py.bak")

src = TARGET.read_text(encoding="utf-8")

# ── PATCH 1: Fix _parse_packet link-type dispatcher ──────────────────────────
OLD1 = '''        try:
            if self._link_type == 1:  # Ethernet
                self._parse_ethernet(data, pkt)
            elif self._link_type == 101:  # Raw IP
                self._parse_ip(data, pkt)
            else:
                pkt["raw"] = data[:64]'''

NEW1 = '''        try:
            if self._link_type == 1:      # Ethernet (LINKTYPE_ETHERNET)
                self._parse_ethernet(data, pkt)
            elif self._link_type in (101, 228, 12, 14):
                # 101 = LINKTYPE_RAW (BSD)
                # 228 = LINKTYPE_IPV4 (Linux raw IPv4)  ← your PCAP
                # 12  = LINKTYPE_RAW (OpenBSD)
                # 14  = LINKTYPE_RAW (FreeBSD)
                self._parse_ip(data, pkt)
            elif self._link_type == 113:  # LINKTYPE_LINUX_SLL (Linux cooked)
                if len(data) >= 16:
                    etype = struct.unpack(">H", data[14:16])[0]
                    if etype == 0x0800:
                        self._parse_ipv4(data[16:], pkt)
                    elif etype == 0x86DD:
                        self._parse_ipv6(data[16:], pkt)
            else:
                pkt["raw"] = data[:64]
                if len(data) >= 20:
                    version = (data[0] >> 4)
                    if version in (4, 6):
                        self._parse_ip(data, pkt)'''

if OLD1 not in src:
    print("ERROR: Could not find link-type patch target. Engine may already be patched or has changed.")
    sys.exit(1)

src = src.replace(OLD1, NEW1)
print("✓ Patch 1 applied: link-type 228 (Linux raw IPv4) now supported")

# ── PATCH 2: Improve DNS exfiltration detection ───────────────────────────────
OLD2 = '''    def _detect_dns_tunneling(self, summary: PcapSummary) -> List[ThreatEvent]:
        events = []
        domain_counts: Counter = Counter()
        for q in summary.dns_queries:
            name = q.get("name", "")
            parts = name.split(".")
            if len(parts) > 2:
                # High-entropy subdomain heuristic
                subdomain = parts[0]
                entropy = _shannon_entropy(subdomain)
                if entropy > 3.5 and len(subdomain) > 20:
                    events.append(ThreatEvent(
                        rule_id="T1071.004",
                        name="DNS Tunneling Indicator",
                        description=f"High-entropy DNS query: {name}",
                        severity="high",
                        mitre_tactic="Command and Control",
                        mitre_technique="T1071.004 — Application Layer Protocol: DNS",
                        timestamp=None,
                        source_ip=q.get("src"),
                        dest_ip=None,
                        source_port=None,
                        dest_port=53,
                        host="network",
                        process="pcap",
                        evidence=[f"Domain: {name}, Entropy: {entropy:.2f}"],
                        tags=["c2","dns-tunneling","exfiltration"],
                        raw_entries=[],
                    ))'''

NEW2 = '''    def _detect_dns_tunneling(self, summary: PcapSummary) -> List[ThreatEvent]:
        events = []
        domain_counts: Counter = Counter()
        _c2_keywords = re.compile(r"(?:exfil|evil|c2|tunnel|beacon|cmd)", re.I)
        _chunk_pat   = re.compile(r"^[a-z0-9]{8,}\\.\\d+\\.", re.I)
        for q in summary.dns_queries:
            name = q.get("name", "")
            qtype = q.get("type", "A")
            parts = name.split(".")
            if len(parts) > 2:
                subdomain = parts[0]
                entropy = _shannon_entropy(subdomain)
                is_high_entropy = entropy > 3.2 and len(subdomain) > 15
                is_chunk   = bool(_chunk_pat.match(name))
                is_c2_kw   = bool(_c2_keywords.search(name))
                is_txt_exfil = qtype == "TXT" and len(subdomain) > 8
                if is_high_entropy or is_chunk or is_c2_kw or is_txt_exfil:
                    severity = "critical" if (is_c2_kw or is_chunk) else "high"
                    rule     = "T1048-DNS-Exfil" if (is_c2_kw or is_chunk) else "T1071.004"
                    label    = "DNS Data Exfiltration via C2" if (is_c2_kw or is_chunk) else "DNS Tunneling Indicator"
                    events.append(ThreatEvent(
                        rule_id=rule,
                        name=label,
                        description=f"Suspicious DNS {qtype} query to {name} (entropy={entropy:.2f})",
                        severity=severity,
                        mitre_tactic="Exfiltration" if (is_c2_kw or is_chunk) else "Command and Control",
                        mitre_technique="T1048.003 — Exfiltration Over Alternative Protocol: DNS" if (is_c2_kw or is_chunk) else "T1071.004 — Application Layer Protocol: DNS",
                        timestamp=None,
                        source_ip=q.get("src"),
                        dest_ip=None,
                        source_port=None,
                        dest_port=53,
                        host="network",
                        process="pcap",
                        evidence=[f"DNS {qtype}: {name} | entropy={entropy:.2f} | c2={is_c2_kw} | chunk={is_chunk}"],
                        tags=["c2","dns-exfiltration","t1048","exfiltration"],
                        raw_entries=[],
                    ))'''

if OLD2 not in src:
    print("WARNING: DNS patch target not found — skipping (engine may already be patched)")
else:
    src = src.replace(OLD2, NEW2)
    print("✓ Patch 2 applied: DNS exfiltration detection enhanced (C2 keywords + chunk pattern)")

# Write patched file
TARGET.write_text(src, encoding="utf-8")
print("✓ engine.py written successfully")

# Clear pycache
import shutil
cache = Path("__pycache__")
if cache.exists():
    shutil.rmtree(cache)
    print("✓ __pycache__ cleared")

print()
print("=" * 60)
print("  All done! Now run:")
print()
print("  uroki analyze all -f suspicious_traffic.pcap access.log \\")
print("      -o report.html --json")
print("=" * 60)
