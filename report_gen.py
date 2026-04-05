"""
Uroki HTML Report Generator — produces a full Splunk-style dark dashboard.
"""

from __future__ import annotations

import json
import html
from datetime import datetime
from typing import Any, Dict, List, Optional
from collections import Counter

from engine import AnalysisReport, ThreatEvent, PcapSummary

# ──────────────────────────────────────────────────────────────────────────────
# Colour / severity helpers
# ──────────────────────────────────────────────────────────────────────────────

SEV_COLOR = {
    "critical": "#ff2d55",
    "high":     "#ff9500",
    "medium":   "#ffcc00",
    "low":      "#34c759",
    "info":     "#636366",
    "informational": "#636366",
    "none":     "#636366",
}

SEV_BADGE = {
    "critical": "badge-critical",
    "high":     "badge-high",
    "medium":   "badge-medium",
    "low":      "badge-low",
    "info":     "badge-info",
}


def _badge(severity: str) -> str:
    cls = SEV_BADGE.get(severity.lower(), "badge-info")
    return f'<span class="badge {cls}">{severity.upper()}</span>'


def _esc(s: Any) -> str:
    return html.escape(str(s or ""))


def _ts(ts) -> str:
    if ts is None:
        return "—"
    if isinstance(ts, str):
        return ts[:19].replace("T", " ")
    try:
        return ts.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


# ──────────────────────────────────────────────────────────────────────────────
# Chart data builders
# ──────────────────────────────────────────────────────────────────────────────

def _protocol_chart_data(proto_counts: Dict[str, int], threats=None) -> str:
    if not proto_counts and threats:
        # Derive pseudo-protocol distribution from threat tags and dest ports
        from collections import Counter as _Counter
        derived: _Counter = _Counter()
        port_proto = {80: "HTTP", 443: "HTTPS", 22: "SSH", 53: "DNS",
                      3306: "MySQL", 3389: "RDP", 21: "FTP", 25: "SMTP"}
        for t in threats:
            if t.dest_port and t.dest_port in port_proto:
                derived[port_proto[t.dest_port]] += 1
            for tag in t.tags:
                if tag in ("web-attack", "ssh", "dns", "c2"):
                    derived[tag.upper()] += 1
        proto_counts = dict(derived) if derived else {}
    if not proto_counts:
        return json.dumps({"labels": [], "data": []})
    items = sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)[:12]
    labels = [k for k, _ in items]
    data = [v for _, v in items]
    return json.dumps({"labels": labels, "data": data})


def _severity_chart_data(threats: List[ThreatEvent]) -> str:
    counts = Counter(t.severity for t in threats)
    order = ["critical", "high", "medium", "low", "info"]
    labels = [s.capitalize() for s in order]
    data = [counts.get(s, 0) for s in order]
    colors = [SEV_COLOR[s] for s in order]
    return json.dumps({"labels": labels, "data": data, "colors": colors})


def _timeline_chart_data(timeline: List[Dict]) -> str:
    hour_counts: Counter = Counter()
    for item in timeline:
        ts = item.get("timestamp", "")
        if ts and len(ts) >= 13:
            try:
                # normalise both ISO and plain datetime strings
                hour = ts[:13].replace("T", " ")
                hour_counts[hour] += 1
            except Exception:
                pass
    if not hour_counts:
        return json.dumps({"labels": [], "data": []})
    sorted_hours = sorted(hour_counts.keys())
    # Show date+hour for multi-day data, else just hour
    all_dates = set(h[:10] for h in sorted_hours)
    if len(all_dates) > 1:
        labels = [h[:13].replace(" ", " ") + ":00" for h in sorted_hours]
    else:
        labels = [h[11:] + ":00" if len(h) > 11 else h for h in sorted_hours]
    data = [hour_counts[h] for h in sorted_hours]
    return json.dumps({"labels": labels, "data": data})


def _top_talkers_data(top_talkers: List, threats=None) -> str:
    items = top_talkers[:10]
    # Fallback: if no PCAP talker data, derive counts from threat source IPs
    if not items and threats:
        from collections import Counter as _Counter
        ip_counts = _Counter(t.source_ip for t in threats if t.source_ip)
        items = [(ip, count * 1000) for ip, count in ip_counts.most_common(10)]
    labels = [ip for ip, _ in items]
    data = [b for _, b in items]
    return json.dumps({"labels": labels, "data": data, "is_threat_count": not top_talkers})


def _mitre_data(threats: List[ThreatEvent]) -> str:
    tactic_counts: Counter = Counter(t.mitre_tactic for t in threats)
    items = tactic_counts.most_common(10)
    return json.dumps({"labels": [i[0] for i in items], "data": [i[1] for i in items]})


# ──────────────────────────────────────────────────────────────────────────────
# Section builders
# ──────────────────────────────────────────────────────────────────────────────

def _build_overview_cards(report: AnalysisReport) -> str:
    s = report.stats
    score = report.severity_score
    score_color = SEV_COLOR.get(report.severity_label.lower(), "#636366")
    pcap = report.pcap_summary

    cards = [
        ("fa-shield-alt", "Severity Score", f"{score}/100", score_color, report.severity_label),
        ("fa-exclamation-triangle", "Threats Detected", len(report.threats), "#ff9500", "Events"),
        ("fa-file-alt", "Log Entries", f"{s.get('total_entries',0):,}", "#0a84ff", "Parsed"),
        ("fa-clock", "Timeline Events", len(report.timeline), "#5e5ce6", "Entries"),
    ]
    if pcap:
        cards.append(("fa-network-wired", "PCAP Packets", f"{pcap.total_packets:,}", "#30d158", "Captured"))
        cards.append(("fa-sitemap", "Network Flows", len(pcap.flows), "#64d2ff", "Sessions"))
        cards.append(("fa-globe", "DNS Queries", len(pcap.dns_queries), "#ffd60a", "Resolved"))
        cards.append(("fa-lock", "TLS Sessions", len(pcap.tls_sessions), "#bf5af2", "Encrypted"))

    html_parts = []
    for icon, title, value, color, subtitle in cards:
        html_parts.append(f"""
        <div class="card overview-card" style="border-top:3px solid {color}">
            <div class="card-icon" style="color:{color}"><i class="fas {icon}"></i></div>
            <div class="card-body">
                <div class="card-value" style="color:{color}">{value}</div>
                <div class="card-title">{title}</div>
                <div class="card-sub">{subtitle}</div>
            </div>
        </div>""")
    return "\n".join(html_parts)


def _build_threats_table(threats: List[ThreatEvent]) -> str:
    if not threats:
        return '<div class="empty-state"><i class="fas fa-check-circle"></i><p>No threats detected</p></div>'
    rows = []
    for t in sorted(threats, key=lambda x: x.severity_rank, reverse=True):
        evidence = _esc(t.evidence[0][:100] + "…" if t.evidence and len(t.evidence[0]) > 100 else (t.evidence[0] if t.evidence else ""))
        rows.append(f"""
        <tr>
            <td>{_badge(t.severity)}</td>
            <td><strong>{_esc(t.name)}</strong></td>
            <td><code>{_esc(t.rule_id)}</code></td>
            <td>{_esc(t.mitre_tactic)}</td>
            <td>{_esc(t.source_ip or "—")}</td>
            <td>{_ts(t.timestamp)}</td>
            <td class="evidence-cell" title="{evidence}">{evidence}</td>
        </tr>""")
    return f"""
    <table class="data-table" id="threats-table">
        <thead><tr>
            <th>Severity</th><th>Threat Name</th><th>Rule ID</th>
            <th>MITRE Tactic</th><th>Source IP</th><th>Timestamp</th><th>Evidence</th>
        </tr></thead>
        <tbody>{"".join(rows)}</tbody>
    </table>"""


def _build_log_stats(stats: Dict) -> str:
    items = {
        "Total Entries": f"{stats.get('total_entries', 0):,}",
        "Error Events": f"{stats.get('error_count', 0):,}",
        "Warning Events": f"{stats.get('warning_count', 0):,}",
        "Unique Hosts": f"{stats.get('unique_hosts', 0):,}",
        "Unique Processes": f"{stats.get('unique_processes', 0):,}",
        "Log Files Parsed": f"{stats.get('files_parsed', 0):,}",
        "Date Range": stats.get('date_range', 'Unknown'),
        "Top Process": stats.get('top_process', 'Unknown'),
    }
    rows = "".join(f"<tr><td>{k}</td><td><strong>{v}</strong></td></tr>" for k, v in items.items())
    return f"<table class='data-table'><tbody>{rows}</tbody></table>"


def _build_pcap_stats(pcap: PcapSummary) -> str:
    if not pcap:
        return '<div class="empty-state"><i class="fas fa-ethernet"></i><p>No PCAP file provided</p></div>'
    rows = [
        ("Total Packets", f"{pcap.total_packets:,}"),
        ("Total Bytes", f"{pcap.total_bytes:,}"),
        ("Duration", f"{pcap.duration_seconds:.2f}s"),
        ("Unique Flows", f"{len(pcap.flows):,}"),
        ("DNS Queries", f"{len(pcap.dns_queries):,}"),
        ("HTTP Transactions", f"{len(pcap.http_transactions):,}"),
        ("TLS Sessions", f"{len(pcap.tls_sessions):,}"),
        ("ARP Entries", f"{len(pcap.arp_table):,}"),
        ("Suspicious IPs", f"{len(pcap.suspicious_ips):,}"),
        ("Port Scan Candidates", f"{len(pcap.port_scan_candidates):,}"),
        ("Beaconing Candidates", f"{len(pcap.beaconing_candidates):,}"),
    ]
    tbl = "".join(f"<tr><td>{k}</td><td><strong>{v}</strong></td></tr>" for k, v in rows)
    return f"<table class='data-table'><tbody>{tbl}</tbody></table>"


def _build_flows_table(flows) -> str:
    if not flows:
        return '<div class="empty-state"><p>No flows</p></div>'
    rows = []
    for f in sorted(flows, key=lambda x: x.bytes_total, reverse=True)[:100]:
        flags_str = ",".join(sorted(f.flags)) if f.flags else "—"
        susp = "🔴" if f.is_suspicious else ""
        svc = f.service or "—"
        rows.append(f"""
        <tr class="{'suspicious-row' if f.is_suspicious else ''}">
            <td>{susp}<code>{f.proto}</code></td>
            <td>{_esc(f.src_ip)}:{f.src_port}</td>
            <td>{_esc(f.dst_ip)}:{f.dst_port}</td>
            <td>{svc}</td>
            <td>{f.packets:,}</td>
            <td>{f.bytes_total:,}</td>
            <td><small>{flags_str}</small></td>
            <td>{_ts(f.first_seen)}</td>
        </tr>""")
    return f"""
    <table class="data-table" id="flows-table">
        <thead><tr>
            <th>Proto</th><th>Source</th><th>Destination</th>
            <th>Service</th><th>Packets</th><th>Bytes</th><th>Flags</th><th>First Seen</th>
        </tr></thead>
        <tbody>{"".join(rows)}</tbody>
    </table>"""


def _build_dns_table(dns_queries) -> str:
    if not dns_queries:
        return '<div class="empty-state"><p>No DNS queries</p></div>'
    rows = []
    for q in dns_queries[:200]:
        rows.append(f"""
        <tr>
            <td>{_ts(q.get('timestamp'))}</td>
            <td>{_esc(q.get('src','—'))}</td>
            <td><strong>{_esc(q.get('name','—'))}</strong></td>
            <td><code>{_esc(q.get('type','—'))}</code></td>
        </tr>""")
    return f"""
    <table class="data-table">
        <thead><tr><th>Timestamp</th><th>Source IP</th><th>Query</th><th>Type</th></tr></thead>
        <tbody>{"".join(rows)}</tbody>
    </table>"""


def _build_http_table(http_txns) -> str:
    if not http_txns:
        return '<div class="empty-state"><p>No HTTP transactions</p></div>'
    rows = []
    for txn in http_txns[:200]:
        uri = _esc(txn.get('uri','')[:80])
        rows.append(f"""
        <tr>
            <td>{_ts(txn.get('timestamp'))}</td>
            <td>{_esc(txn.get('src','—'))}</td>
            <td><code>{_esc(txn.get('method','GET'))}</code></td>
            <td>{_esc(txn.get('host','—'))}</td>
            <td><small>{uri}</small></td>
        </tr>""")
    return f"""
    <table class="data-table">
        <thead><tr><th>Timestamp</th><th>Source</th><th>Method</th><th>Host</th><th>URI</th></tr></thead>
        <tbody>{"".join(rows)}</tbody>
    </table>"""


def _build_ip_table(ip_intel: Dict) -> str:
    if not ip_intel:
        return '<div class="empty-state"><p>No IP data</p></div>'
    rows = []
    sorted_ips = sorted(ip_intel.items(), key=lambda x: (x[1].get('log_threats',0)+x[1].get('pcap_threats',0)), reverse=True)
    for ip, data in sorted_ips[:100]:
        total_threats = data.get('log_threats', 0) + data.get('pcap_threats', 0)
        is_priv = "🏠 Private" if data.get('is_private') else "🌐 External"
        mac = data.get('mac', '—')
        threat_names = ", ".join(set(data.get('threat_names', [])))[:80]
        rows.append(f"""
        <tr class="{'high-risk-row' if total_threats > 2 else ''}">
            <td><code>{_esc(ip)}</code></td>
            <td>{is_priv}</td>
            <td>{mac}</td>
            <td>{data.get('bytes_sent',0):,}</td>
            <td><strong style="color:{'#ff2d55' if total_threats>5 else '#ff9500' if total_threats>0 else '#34c759'}">{total_threats}</strong></td>
            <td><small>{_esc(threat_names)}</small></td>
        </tr>""")
    return f"""
    <table class="data-table">
        <thead><tr><th>IP Address</th><th>Type</th><th>MAC</th><th>Bytes</th><th>Threats</th><th>Threat Names</th></tr></thead>
        <tbody>{"".join(rows)}</tbody>
    </table>"""


def _build_timeline_list(timeline: List[Dict]) -> str:
    if not timeline:
        return '<div class="empty-state"><p>No timeline events</p></div>'
    items = []
    for item in timeline[-200:]:
        sev = item.get("severity", "info")
        color = SEV_COLOR.get(sev, "#636366")
        icon = "fa-exclamation-circle" if item["type"] == "threat" else "fa-file-alt"
        if item["type"] == "threat":
            content = f"<strong>{_esc(item.get('name',''))}</strong> — {_esc(item.get('mitre',''))}<br><small>Source: {_esc(item.get('source_ip','—'))} | {_esc(item.get('evidence','')[:100])}</small>"
        else:
            content = f"<strong>{_esc(item.get('process',''))}</strong> — {_esc(item.get('message','')[:150])}<br><small>Host: {_esc(item.get('host',''))}</small>"
        items.append(f"""
        <div class="timeline-item">
            <div class="timeline-dot" style="background:{color}"><i class="fas {icon}"></i></div>
            <div class="timeline-content">
                <div class="timeline-ts">{_ts(item.get('timestamp'))}</div>
                <div class="timeline-body">{content}</div>
            </div>
        </div>""")
    return "".join(items)


def _build_recommendations(recs: List[str]) -> str:
    items = "".join(f'<div class="rec-item"><i class="fas fa-chevron-right"></i> {_esc(r)}</div>' for r in recs)
    return items if items else '<div class="empty-state"><p>No recommendations</p></div>'


# ──────────────────────────────────────────────────────────────────────────────
# Main generator
# ──────────────────────────────────────────────────────────────────────────────

def generate_html_report(report: AnalysisReport, output_path: str = "report.html") -> str:
    """Generate the full HTML dashboard report."""

    pcap = report.pcap_summary
    s = report.stats
    score_color = SEV_COLOR.get(report.severity_label.lower(), "#636366")

    # Pre-build all sections
    overview_cards = _build_overview_cards(report)
    threats_table = _build_threats_table(report.threats)
    log_stats_table = _build_log_stats(s)
    pcap_stats = _build_pcap_stats(pcap)
    flows_table = _build_flows_table(pcap.flows if pcap else [])
    dns_table = _build_dns_table(pcap.dns_queries if pcap else [])
    http_table = _build_http_table(pcap.http_transactions if pcap else [])
    ip_table = _build_ip_table(report.ip_correlation)
    timeline_list = _build_timeline_list(report.timeline)
    recs_html = _build_recommendations(report.recommendations)

    # Chart data
    proto_data = _protocol_chart_data(pcap.protocols if pcap else {}, report.threats)
    severity_data = _severity_chart_data(report.threats)
    timeline_data = _timeline_chart_data(report.timeline)
    talkers_data = _top_talkers_data(pcap.top_talkers if pcap else [], report.threats)
    mitre_data = _mitre_data(report.threats)

    # Log level stats
    log_level_labels = json.dumps(["Error", "Warning", "Info"])
    log_level_data = json.dumps([s.get("error_count", 0), s.get("warning_count", 0), s.get("info_count", 0)])

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Uroki Security Analysis Report — {_ts(report.generated_at)}</title>
<!-- Font Awesome with inline SVG fallback for file:// mode -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"
      onerror="this.onerror=null;document.head.insertAdjacentHTML('beforeend','<style>.fas,.fa{{font-family:sans-serif!important}}.fas::before,.fa::before{{content:\\'▶\\'}}.fa-shield-alt::before{{content:\\'🛡\\'}}.fa-exclamation-triangle::before{{content:\\'⚠\\'}}.fa-file-alt::before{{content:\\'📄\\'}}.fa-clock::before{{content:\\'🕐\\'}}.fa-network-wired::before{{content:\\'🌐\\'}}.fa-sitemap::before{{content:\\'🔗\\'}}.fa-globe::before{{content:\\'🌍\\'}}.fa-lock::before{{content:\\'🔒\\'}}.fa-check-circle::before{{content:\\'✓\\'}}.fa-ethernet::before{{content:\\'📡\\'}}.fa-chevron-right::before{{content:\\'›\\'}}.fa-exclamation-circle::before{{content:\\'❗\\'}}.fa-lightbulb::before{{content:\\'💡\\'}}.fa-bug::before{{content:\\'🐛\\'}}.fa-server::before{{content:\\'🖥\\'}}.fa-chart-bar::before{{content:\\'📊\\'}}.fa-terminal::before{{content:\\'💻\\'}}</style>')"/>
<!-- Chart.js: try CDN, fall back to unpkg, then jsDelivr -->
<script>
(function(){{
  function tryLoad(urls, idx) {{
    if (idx >= urls.length) {{ window._chartJsFailed=true; return; }}
    var s = document.createElement('script');
    s.src = urls[idx];
    s.onerror = function(){{ tryLoad(urls, idx+1); }};
    document.head.appendChild(s);
  }}
  tryLoad([
    'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js',
    'https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js',
    'https://unpkg.com/chart.js@4.4.1/dist/chart.umd.min.js'
  ], 0);
}})();
</script>
<style>
:root {{
    --bg-primary:    #0d0d0f;
    --bg-secondary:  #141417;
    --bg-tertiary:   #1c1c22;
    --bg-card:       #1e1e26;
    --bg-input:      #252530;
    --border:        #2a2a38;
    --border-light:  #35354a;
    --text-primary:  #e8e8f0;
    --text-secondary:#9898b0;
    --text-muted:    #5a5a78;
    --accent-blue:   #0a84ff;
    --accent-purple: #bf5af2;
    --accent-green:  #30d158;
    --accent-orange: #ff9500;
    --accent-red:    #ff2d55;
    --accent-teal:   #64d2ff;
    --accent-yellow: #ffd60a;
    --sidebar-width: 260px;
    --header-h:      60px;
    --radius:        12px;
    --radius-sm:     8px;
    --shadow:        0 4px 24px rgba(0,0,0,.5);
    --glass:         rgba(255,255,255,.03);
    --transition:    .2s ease;
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
html{{scroll-behavior:smooth}}
body{{
    font-family:-apple-system,BlinkMacSystemFont,'SF Pro Display','Segoe UI',sans-serif;
    background:var(--bg-primary);
    color:var(--text-primary);
    line-height:1.6;
    overflow-x:hidden;
}}

/* ── Scrollbar ── */
::-webkit-scrollbar{{width:6px;height:6px}}
::-webkit-scrollbar-track{{background:var(--bg-secondary)}}
::-webkit-scrollbar-thumb{{background:var(--border-light);border-radius:3px}}
::-webkit-scrollbar-thumb:hover{{background:var(--text-muted)}}

/* ── Layout ── */
.layout{{display:flex;min-height:100vh}}

/* ── Sidebar ── */
.sidebar{{
    width:var(--sidebar-width);
    background:var(--bg-secondary);
    border-right:1px solid var(--border);
    position:fixed;
    top:0;left:0;bottom:0;
    overflow-y:auto;
    z-index:100;
    transition:transform var(--transition);
}}
.sidebar-brand{{
    display:flex;align-items:center;gap:12px;
    padding:20px 20px 16px;
    border-bottom:1px solid var(--border);
}}
.brand-icon{{
    width:40px;height:40px;
    background:linear-gradient(135deg,var(--accent-blue),var(--accent-purple));
    border-radius:10px;
    display:flex;align-items:center;justify-content:center;
    font-size:18px;
}}
.brand-name{{font-size:20px;font-weight:700;letter-spacing:-.5px}}
.brand-ver{{font-size:11px;color:var(--text-muted);letter-spacing:.5px}}
.sidebar-section{{padding:12px 0 4px}}
.sidebar-label{{
    font-size:10px;font-weight:600;letter-spacing:1.5px;
    color:var(--text-muted);text-transform:uppercase;
    padding:0 20px 6px;
}}
.sidebar-item{{
    display:flex;align-items:center;gap:10px;
    padding:9px 20px;
    color:var(--text-secondary);
    text-decoration:none;
    font-size:14px;
    border-left:3px solid transparent;
    transition:all var(--transition);
    cursor:pointer;
}}
.sidebar-item:hover{{
    color:var(--text-primary);
    background:var(--glass);
    border-left-color:var(--accent-blue);
}}
.sidebar-item.active{{
    color:var(--accent-blue);
    background:rgba(10,132,255,.1);
    border-left-color:var(--accent-blue);
}}
.sidebar-item i{{width:18px;text-align:center;font-size:14px}}
.sidebar-badge{{
    margin-left:auto;
    background:var(--accent-red);
    color:#fff;
    font-size:10px;font-weight:700;
    padding:2px 6px;border-radius:10px;
    min-width:20px;text-align:center;
}}
.sidebar-score{{
    margin:16px;
    padding:16px;
    background:var(--bg-tertiary);
    border-radius:var(--radius-sm);
    border:1px solid var(--border);
}}
.score-label{{font-size:11px;color:var(--text-muted);margin-bottom:6px}}
.score-value{{font-size:28px;font-weight:800;color:{score_color}}}
.score-sub{{font-size:12px;color:var(--text-secondary)}}
.score-bar{{
    height:4px;background:var(--border);
    border-radius:2px;margin-top:8px;overflow:hidden;
}}
.score-fill{{
    height:100%;width:{report.severity_score}%;
    background:linear-gradient(90deg,var(--accent-green),{score_color});
    border-radius:2px;
}}

/* ── Main content ── */
.main{{
    margin-left:var(--sidebar-width);
    flex:1;
    min-width:0;
}}

/* ── Header ── */
.header{{
    height:var(--header-h);
    background:var(--bg-secondary);
    border-bottom:1px solid var(--border);
    display:flex;align-items:center;justify-content:space-between;
    padding:0 24px;
    position:sticky;top:0;z-index:50;
}}
.header-title{{font-size:15px;font-weight:600}}
.header-meta{{
    display:flex;align-items:center;gap:16px;
    font-size:13px;color:var(--text-muted);
}}
.status-dot{{
    width:8px;height:8px;border-radius:50%;
    background:var(--accent-green);
    box-shadow:0 0 8px var(--accent-green);
    animation:pulse 2s infinite;
}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.4}}}}

/* ── Sections ── */
.content{{padding:24px}}
.section{{
    margin-bottom:32px;
    scroll-margin-top:80px;
}}
.section-header{{
    display:flex;align-items:center;gap:12px;
    margin-bottom:20px;
    padding-bottom:12px;
    border-bottom:1px solid var(--border);
}}
.section-icon{{
    width:36px;height:36px;
    border-radius:8px;
    display:flex;align-items:center;justify-content:center;
    font-size:16px;
}}
.section-title{{font-size:18px;font-weight:700}}
.section-sub{{font-size:13px;color:var(--text-muted);margin-left:auto}}

/* ── Cards ── */
.card{{
    background:var(--bg-card);
    border:1px solid var(--border);
    border-radius:var(--radius);
    padding:20px;
    transition:box-shadow var(--transition);
}}
.card:hover{{box-shadow:var(--shadow)}}
.card-grid{{
    display:grid;
    grid-template-columns:repeat(auto-fill,minmax(200px,1fr));
    gap:16px;
}}
.overview-card{{
    display:flex;align-items:flex-start;gap:16px;
}}
.card-icon{{font-size:28px;flex-shrink:0;padding-top:2px}}
.card-value{{font-size:26px;font-weight:800;line-height:1}}
.card-title{{font-size:13px;color:var(--text-secondary);margin-top:4px}}
.card-sub{{font-size:11px;color:var(--text-muted);margin-top:2px}}

/* ── Charts grid ── */
.charts-grid{{
    display:grid;
    grid-template-columns:repeat(auto-fill,minmax(380px,1fr));
    gap:20px;
    margin-bottom:24px;
}}
.chart-card{{
    background:var(--bg-card);
    border:1px solid var(--border);
    border-radius:var(--radius);
    padding:20px;
}}
.chart-title{{
    font-size:13px;font-weight:600;
    color:var(--text-secondary);
    margin-bottom:16px;
    text-transform:uppercase;letter-spacing:.5px;
}}
.chart-wrap{{position:relative;height:220px}}

/* ── Tables ── */
.table-wrap{{overflow-x:auto;border-radius:var(--radius-sm)}}
.data-table{{
    width:100%;border-collapse:collapse;
    font-size:13px;
}}
.data-table th{{
    background:var(--bg-tertiary);
    color:var(--text-muted);
    font-size:11px;font-weight:600;
    text-transform:uppercase;letter-spacing:.8px;
    padding:10px 14px;
    text-align:left;
    border-bottom:1px solid var(--border);
    white-space:nowrap;
}}
.data-table td{{
    padding:10px 14px;
    border-bottom:1px solid var(--border);
    vertical-align:middle;
}}
.data-table tr:last-child td{{border-bottom:none}}
.data-table tr:hover td{{background:var(--glass)}}
.data-table code{{
    background:var(--bg-input);
    padding:2px 6px;border-radius:4px;
    font-family:'SF Mono','Fira Code',monospace;
    font-size:12px;color:var(--accent-teal);
}}
.suspicious-row td{{background:rgba(255,45,85,.05)}}
.high-risk-row td{{background:rgba(255,149,0,.05)}}
.evidence-cell{{
    max-width:300px;
    overflow:hidden;text-overflow:ellipsis;
    white-space:nowrap;
    cursor:help;
    color:var(--text-muted);font-size:12px;
}}

/* ── Badges ── */
.badge{{
    display:inline-block;
    padding:3px 8px;border-radius:5px;
    font-size:10px;font-weight:700;
    letter-spacing:.5px;text-transform:uppercase;
}}
.badge-critical{{background:rgba(255,45,85,.2);color:#ff2d55;border:1px solid rgba(255,45,85,.4)}}
.badge-high{{background:rgba(255,149,0,.2);color:#ff9500;border:1px solid rgba(255,149,0,.4)}}
.badge-medium{{background:rgba(255,214,10,.15);color:#ffd60a;border:1px solid rgba(255,214,10,.3)}}
.badge-low{{background:rgba(52,199,89,.15);color:#34c759;border:1px solid rgba(52,199,89,.3)}}
.badge-info{{background:rgba(99,99,102,.2);color:#636366;border:1px solid rgba(99,99,102,.4)}}

/* ── Search bar ── */
.search-bar{{
    margin-bottom:16px;
    display:flex;align-items:center;gap:8px;
}}
.search-input{{
    flex:1;
    background:var(--bg-input);
    border:1px solid var(--border);
    color:var(--text-primary);
    padding:8px 14px 8px 36px;
    border-radius:var(--radius-sm);
    font-size:13px;
    outline:none;
    background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='14' height='14' viewBox='0 0 24 24' fill='none' stroke='%235a5a78' stroke-width='2'%3E%3Ccircle cx='11' cy='11' r='8'/%3E%3Cpath d='m21 21-4.35-4.35'/%3E%3C/svg%3E");
    background-repeat:no-repeat;
    background-position:12px center;
    transition:border-color var(--transition);
}}
.search-input:focus{{border-color:var(--accent-blue)}}
.search-input::placeholder{{color:var(--text-muted)}}

/* ── Timeline ── */
.timeline{{position:relative;padding-left:40px}}
.timeline::before{{
    content:'';position:absolute;left:14px;top:0;bottom:0;
    width:2px;background:var(--border);
}}
.timeline-item{{
    position:relative;
    margin-bottom:20px;
    animation:fadeIn .4s ease;
}}
@keyframes fadeIn{{from{{opacity:0;transform:translateX(-10px)}}to{{opacity:1;transform:translateX(0)}}}}
.timeline-dot{{
    position:absolute;left:-34px;top:4px;
    width:24px;height:24px;border-radius:50%;
    display:flex;align-items:center;justify-content:center;
    font-size:10px;color:#fff;
    z-index:1;
}}
.timeline-content{{
    background:var(--bg-card);
    border:1px solid var(--border);
    border-radius:var(--radius-sm);
    padding:12px 16px;
}}
.timeline-ts{{
    font-size:11px;color:var(--text-muted);
    font-family:'SF Mono',monospace;
    margin-bottom:4px;
}}
.timeline-body{{font-size:13px;line-height:1.5}}
.timeline-body small{{color:var(--text-muted)}}

/* ── Recommendations ── */
.rec-item{{
    display:flex;align-items:flex-start;gap:10px;
    padding:12px 16px;
    background:var(--bg-tertiary);
    border:1px solid var(--border);
    border-radius:var(--radius-sm);
    margin-bottom:10px;
    font-size:13px;
    line-height:1.5;
    color:var(--text-secondary);
    transition:all var(--transition);
}}
.rec-item:hover{{border-color:var(--accent-blue);color:var(--text-primary)}}
.rec-item i{{color:var(--accent-blue);flex-shrink:0;margin-top:2px}}

/* ── Empty state ── */
.empty-state{{
    text-align:center;padding:40px;
    color:var(--text-muted);
}}
.empty-state i{{font-size:32px;margin-bottom:12px;display:block}}

/* ── Two-col layout ── */
.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
@media(max-width:900px){{.two-col{{grid-template-columns:1fr}}}}

/* ── Report meta ── */
.report-meta{{
    display:flex;flex-wrap:wrap;gap:16px;
    padding:16px;
    background:var(--bg-tertiary);
    border-radius:var(--radius-sm);
    margin-bottom:24px;
    font-size:12px;color:var(--text-muted);
}}
.meta-item{{display:flex;align-items:center;gap:6px}}
.meta-item strong{{color:var(--text-primary)}}

/* ── Footer ── */
.footer{{
    text-align:center;padding:24px;
    border-top:1px solid var(--border);
    color:var(--text-muted);font-size:12px;
}}
</style>
</head>
<body>
<div class="layout">

<!-- ════════════════════════════════ SIDEBAR ════════════════════════════════ -->
<nav class="sidebar">
    <div class="sidebar-brand">
        <div class="brand-icon">🛡️</div>
        <div>
            <div class="brand-name">Uroki</div>
            <div class="brand-ver">v5.0 — SECURITY ANALYSIS</div>
        </div>
    </div>

    <div class="sidebar-score">
        <div class="score-label">SEVERITY SCORE</div>
        <div class="score-value">{report.severity_score}</div>
        <div class="score-sub">{report.severity_label} Risk</div>
        <div class="score-bar"><div class="score-fill"></div></div>
    </div>

    <div class="sidebar-section">
        <div class="sidebar-label">Navigation</div>
        <a class="sidebar-item active" href="#overview">
            <i class="fas fa-tachometer-alt"></i> Overview
        </a>
        <a class="sidebar-item" href="#threats">
            <i class="fas fa-exclamation-triangle"></i> Threats
            <span class="sidebar-badge">{len(report.threats)}</span>
        </a>
        <a class="sidebar-item" href="#log-analysis">
            <i class="fas fa-file-alt"></i> Log Analysis
        </a>
        <a class="sidebar-item" href="#pcap-analysis">
            <i class="fas fa-network-wired"></i> PCAP Analysis
        </a>
        <a class="sidebar-item" href="#threat-intel">
            <i class="fas fa-crosshairs"></i> Threat Intelligence
        </a>
        <a class="sidebar-item" href="#timeline">
            <i class="fas fa-clock"></i> Timeline
        </a>
        <a class="sidebar-item" href="#recommendations">
            <i class="fas fa-lightbulb"></i> Recommendations
        </a>
    </div>

    <div class="sidebar-section">
        <div class="sidebar-label">Report Info</div>
        <div class="sidebar-item" style="cursor:default">
            <i class="fas fa-calendar"></i> <span style="font-size:12px">{_ts(report.generated_at)}</span>
        </div>
        <div class="sidebar-item" style="cursor:default">
            <i class="fas fa-list"></i> <span style="font-size:12px">{len(report.log_entries):,} log entries</span>
        </div>
    </div>
</nav>

<!-- ════════════════════════════════ MAIN ════════════════════════════════ -->
<div class="main">

    <!-- Header -->
    <div class="header">
        <div class="header-title">
            <i class="fas fa-shield-alt" style="color:var(--accent-blue);margin-right:8px"></i>
            Security Analysis Report
        </div>
        <div class="header-meta">
            <div class="status-dot"></div>
            <span>Analysis Complete</span>
            <span>|</span>
            <span>{_ts(report.generated_at)}</span>
        </div>
    </div>

    <!-- Content -->
    <div class="content">

        <!-- Report metadata bar -->
        <div class="report-meta">
            <div class="meta-item"><i class="fas fa-file-import"></i> Files: <strong>{report.stats.get('files_parsed',0)}</strong></div>
            <div class="meta-item"><i class="fas fa-list"></i> Log Lines: <strong>{report.stats.get('total_entries',0):,}</strong></div>
            <div class="meta-item"><i class="fas fa-exclamation-triangle"></i> Threats: <strong>{len(report.threats)}</strong></div>
            <div class="meta-item"><i class="fas fa-calendar-alt"></i> Range: <strong>{report.stats.get('date_range','—')}</strong></div>
            {'<div class="meta-item"><i class="fas fa-network-wired"></i> Packets: <strong>' + str(f"{report.pcap_summary.total_packets:,}") + '</strong></div>' if pcap else ''}
        </div>

        <!-- ── SECTION 1: Overview ── -->
        <div class="section" id="overview">
            <div class="section-header">
                <div class="section-icon" style="background:rgba(10,132,255,.15);color:var(--accent-blue)">
                    <i class="fas fa-tachometer-alt"></i>
                </div>
                <div class="section-title">Overview Dashboard</div>
                <div class="section-sub">Automated intelligence summary</div>
            </div>

            <div class="card-grid" style="margin-bottom:24px">
                {overview_cards}
            </div>

            <div class="charts-grid">
                <div class="chart-card">
                    <div class="chart-title">Threat Severity Distribution</div>
                    <div class="chart-wrap"><canvas id="chartSeverity"></canvas></div>
                </div>
                <div class="chart-card">
                    <div class="chart-title">Event Activity Timeline (last 24h)</div>
                    <div class="chart-wrap"><canvas id="chartTimeline"></canvas></div>
                </div>
                <div class="chart-card">
                    <div class="chart-title">MITRE ATT&amp;CK Tactics</div>
                    <div class="chart-wrap"><canvas id="chartMitre"></canvas></div>
                </div>
                <div class="chart-card">
                    <div class="chart-title">Log Level Breakdown</div>
                    <div class="chart-wrap"><canvas id="chartLogLevels"></canvas></div>
                </div>
                {'<div class="chart-card"><div class="chart-title">Protocol Distribution</div><div class="chart-wrap"><canvas id="chartProtocols"></canvas></div></div>' if pcap else ''}
                {'<div class="chart-card"><div class="chart-title">Top Talkers (by bytes)</div><div class="chart-wrap"><canvas id="chartTalkers"></canvas></div></div>' if pcap else ''}
            </div>
        </div>

        <!-- ── SECTION 2: Threats ── -->
        <div class="section" id="threats">
            <div class="section-header">
                <div class="section-icon" style="background:rgba(255,45,85,.15);color:var(--accent-red)">
                    <i class="fas fa-exclamation-triangle"></i>
                </div>
                <div class="section-title">Threat Detections</div>
                <div class="section-sub">{len(report.threats)} events | MITRE ATT&amp;CK aligned</div>
            </div>
            <div class="search-bar">
                <input class="search-input" type="text" id="threats-search" placeholder="Filter threats…" oninput="filterTable('threats-table','threats-search')"/>
            </div>
            <div class="card table-wrap">
                {threats_table}
            </div>
        </div>

        <!-- ── SECTION 3: Log Analysis ── -->
        <div class="section" id="log-analysis">
            <div class="section-header">
                <div class="section-icon" style="background:rgba(100,210,255,.15);color:var(--accent-teal)">
                    <i class="fas fa-file-alt"></i>
                </div>
                <div class="section-title">Log Analysis</div>
                <div class="section-sub">Parsed from {report.stats.get('files_parsed',0)} source files</div>
            </div>
            <div class="two-col" style="margin-bottom:20px">
                <div class="card">
                    <div class="chart-title">Statistics</div>
                    {log_stats_table}
                </div>
                <div class="card">
                    <div class="chart-title">Top Processes (by event volume)</div>
                    <div class="chart-wrap"><canvas id="chartTopProcs"></canvas></div>
                </div>
            </div>
        </div>

        <!-- ── SECTION 4: PCAP ── -->
        <div class="section" id="pcap-analysis">
            <div class="section-header">
                <div class="section-icon" style="background:rgba(48,209,88,.15);color:var(--accent-green)">
                    <i class="fas fa-network-wired"></i>
                </div>
                <div class="section-title">PCAP / Network Analysis</div>
                <div class="section-sub">Packet-level forensics</div>
            </div>
            <div class="two-col" style="margin-bottom:20px">
                <div class="card">
                    <div class="chart-title">Capture Statistics</div>
                    {pcap_stats}
                </div>
                <div class="card">
                    <div class="chart-title">ARP Table</div>
                    {'<table class="data-table"><thead><tr><th>IP</th><th>MAC</th></tr></thead><tbody>' + "".join(f"<tr><td><code>{_esc(ip)}</code></td><td><code>{_esc(mac)}</code></td></tr>" for ip, mac in (pcap.arp_table.items() if pcap else {}.items())) + '</tbody></table>' if pcap and pcap.arp_table else '<div class="empty-state"><p>No ARP data</p></div>'}
                </div>
            </div>

            <div class="card" style="margin-bottom:20px">
                <div class="chart-title" style="margin-bottom:12px">Network Flows (top 100 by bytes)</div>
                <div class="search-bar">
                    <input class="search-input" type="text" id="flows-search" placeholder="Filter flows…" oninput="filterTable('flows-table','flows-search')"/>
                </div>
                <div class="table-wrap">{flows_table}</div>
            </div>

            <div class="two-col">
                <div class="card">
                    <div class="chart-title" style="margin-bottom:12px">DNS Queries</div>
                    <div class="table-wrap">{dns_table}</div>
                </div>
                <div class="card">
                    <div class="chart-title" style="margin-bottom:12px">HTTP Transactions</div>
                    <div class="table-wrap">{http_table}</div>
                </div>
            </div>
        </div>

        <!-- ── SECTION 5: Threat Intel / IP correlation ── -->
        <div class="section" id="threat-intel">
            <div class="section-header">
                <div class="section-icon" style="background:rgba(191,90,242,.15);color:var(--accent-purple)">
                    <i class="fas fa-crosshairs"></i>
                </div>
                <div class="section-title">Threat Intelligence — IP Correlation</div>
                <div class="section-sub">Cross-referenced across log + PCAP sources</div>
            </div>
            <div class="card table-wrap">
                {ip_table}
            </div>
        </div>

        <!-- ── SECTION 6: Timeline ── -->
        <div class="section" id="timeline">
            <div class="section-header">
                <div class="section-icon" style="background:rgba(255,149,0,.15);color:var(--accent-orange)">
                    <i class="fas fa-clock"></i>
                </div>
                <div class="section-title">Attack Timeline</div>
                <div class="section-sub">{len(report.timeline)} events (showing last 200)</div>
            </div>
            <div class="timeline">
                {timeline_list}
            </div>
        </div>

        <!-- ── SECTION 7: Recommendations ── -->
        <div class="section" id="recommendations">
            <div class="section-header">
                <div class="section-icon" style="background:rgba(255,214,10,.15);color:var(--accent-yellow)">
                    <i class="fas fa-lightbulb"></i>
                </div>
                <div class="section-title">Remediation Recommendations</div>
                <div class="section-sub">Actionable security improvements</div>
            </div>
            {recs_html}
        </div>

    </div><!-- /content -->

    <div class="footer">
        Generated by <strong>Uroki v5.0</strong> — Advanced Security Analysis Platform |
        {_ts(report.generated_at)}
    </div>
</div><!-- /main -->
</div><!-- /layout -->

<script>
// ── Wait for Chart.js to load (handles async script injection) ───────────────
function waitForChart(cb, tries) {{
    tries = tries || 0;
    if (typeof Chart !== 'undefined') {{ cb(); return; }}
    if (tries > 100) {{
        document.querySelectorAll('.chart-wrap').forEach(function(el) {{
            el.innerHTML = '<div style="color:#5a5a78;text-align:center;padding:60px 0;font-size:12px">Chart.js failed to load.<br>Open this file in a browser with internet access.</div>';
        }});
        return;
    }}
    setTimeout(function(){{ waitForChart(cb, tries+1); }}, 80);
}}

waitForChart(function() {{

// ── Chart defaults ──────────────────────────────────────────────────────────
Chart.defaults.color = '#9898b0';
Chart.defaults.borderColor = '#2a2a38';
Chart.defaults.font.family = "-apple-system,'SF Pro Display','Segoe UI',sans-serif";
Chart.defaults.font.size = 12;

const C_BLUE   = '#0a84ff';
const C_PURPLE = '#bf5af2';
const C_GREEN  = '#30d158';
const C_ORANGE = '#ff9500';
const C_RED    = '#ff2d55';
const C_TEAL   = '#64d2ff';
const C_YELLOW = '#ffd60a';

function makeGrad(ctx, colors) {{
    const g = ctx.createLinearGradient(0,0,0,200);
    colors.forEach((c,i) => g.addColorStop(i/(colors.length-1||1), c + '99'));
    return g;
}}

// ── Severity doughnut ────────────────────────────────────────────────────────
(function(){{
    const d = {severity_data};
    if (!d.data || !d.data.some(v=>v>0)) {{
        document.getElementById('chartSeverity').parentElement.innerHTML = '<div style="color:#5a5a78;text-align:center;padding:80px 0;font-size:13px">No threats detected</div>';
        return;
    }}
    new Chart(document.getElementById('chartSeverity'), {{
        type:'doughnut',
        data:{{
            labels:d.labels,
            datasets:[{{
                data:d.data,
                backgroundColor:d.colors.map(c=>c+'bb'),
                borderColor:d.colors,
                borderWidth:2,
                hoverOffset:8,
            }}]
        }},
        options:{{
            responsive:true,maintainAspectRatio:false,
            plugins:{{
                legend:{{position:'right',labels:{{boxWidth:12,padding:16}}}},
                tooltip:{{callbacks:{{label:(c)=>` ${{c.label}}: ${{c.raw}} events`}}}}
            }},
            cutout:'65%',
        }}
    }});
}})();

// ── Timeline bar ─────────────────────────────────────────────────────────────
(function(){{
    const d = {timeline_data};
    if (!d.labels || !d.labels.length) {{
        document.getElementById('chartTimeline').parentElement.innerHTML = '<div style="color:#5a5a78;text-align:center;padding:80px 0;font-size:13px">No timeline data</div>';
        return;
    }}
    // Limit to last 48 points for performance
    const labels = d.labels.slice(-48);
    const data   = d.data.slice(-48);
    const ctx = document.getElementById('chartTimeline').getContext('2d');
    new Chart(ctx, {{
        type:'bar',
        data:{{
            labels:labels,
            datasets:[{{
                label:'Events',
                data:data,
                backgroundColor:makeGrad(ctx,[C_BLUE,C_PURPLE]),
                borderRadius:4,
            }}]
        }},
        options:{{
            responsive:true,maintainAspectRatio:false,
            animation:{{duration:400}},
            plugins:{{legend:{{display:false}}}},
            scales:{{
                x:{{grid:{{display:false}},ticks:{{maxTicksLimit:8,font:{{size:10}}}}}},
                y:{{grid:{{color:'#2a2a38'}},ticks:{{precision:0}}}}
            }}
        }}
    }});
}})();

// ── MITRE bar ────────────────────────────────────────────────────────────────
(function(){{
    const d = {mitre_data};
    if (!d.labels || !d.labels.length) {{
        document.getElementById('chartMitre').parentElement.innerHTML = '<div style="color:#5a5a78;text-align:center;padding:80px 0;font-size:13px">No MITRE data</div>';
        return;
    }}
    const ctx = document.getElementById('chartMitre').getContext('2d');
    new Chart(ctx, {{
        type:'bar',
        data:{{
            labels:d.labels,
            datasets:[{{
                label:'Events',
                data:d.data,
                backgroundColor:makeGrad(ctx,[C_RED,C_ORANGE]),
                borderRadius:4,
            }}]
        }},
        options:{{
            indexAxis:'y',
            responsive:true,maintainAspectRatio:false,
            plugins:{{legend:{{display:false}}}},
            scales:{{
                x:{{grid:{{color:'#2a2a38'}},ticks:{{precision:0}}}},
                y:{{grid:{{display:false}},ticks:{{font:{{size:11}}}}}}
            }}
        }}
    }});
}})();

// ── Log levels pie ───────────────────────────────────────────────────────────
(function(){{
    const labels = {log_level_labels};
    const data   = {log_level_data};
    if (!data || !data.some(v=>v>0)) {{
        document.getElementById('chartLogLevels').parentElement.innerHTML = '<div style="color:#5a5a78;text-align:center;padding:80px 0;font-size:13px">No log data</div>';
        return;
    }}
    new Chart(document.getElementById('chartLogLevels'), {{
        type:'pie',
        data:{{
            labels,
            datasets:[{{
                data,
                backgroundColor:[C_RED+'bb',C_YELLOW+'bb',C_TEAL+'bb'],
                borderColor:[C_RED,C_YELLOW,C_TEAL],
                borderWidth:2,
            }}]
        }},
        options:{{
            responsive:true,maintainAspectRatio:false,
            plugins:{{legend:{{position:'right',labels:{{boxWidth:12,padding:16}}}}}}
        }}
    }});
}})();

// ── Protocol doughnut ────────────────────────────────────────────────────────
(function(){{
    const pd = {proto_data};
    if (!pd.labels || !pd.labels.length) {{
        document.getElementById('chartProtocols').parentElement.innerHTML = '<div style="color:#5a5a78;text-align:center;padding:80px 0;font-size:13px">No protocol data</div>';
        return;
    }}
    const palette = [C_BLUE,C_PURPLE,C_GREEN,C_ORANGE,C_RED,C_TEAL,C_YELLOW,'#ff6b6b','#4ecdc4','#45b7d1','#96ceb4','#ffeaa7'];
    new Chart(document.getElementById('chartProtocols'), {{
        type:'doughnut',
        data:{{labels:pd.labels,datasets:[{{data:pd.data,backgroundColor:palette.map(c=>c+'99'),borderColor:palette,borderWidth:2}}]}},
        options:{{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{position:'right',labels:{{boxWidth:10,padding:12}}}}}},cutout:'55%'}}
    }});
}})();

// ── Top talkers bar ───────────────────────────────────────────────────────────
(function(){{
    const td = {talkers_data};
    if (!td.labels || !td.labels.length) {{
        document.getElementById('chartTalkers').parentElement.innerHTML = '<div style="color:#5a5a78;text-align:center;padding:80px 0;font-size:13px">No IP traffic data</div>';
        return;
    }}
    const ctx2 = document.getElementById('chartTalkers').getContext('2d');
    const axisLabel = td.is_threat_count ? 'Threat Events' : 'Bytes';
    new Chart(ctx2, {{
        type:'bar',
        data:{{labels:td.labels,datasets:[{{label:axisLabel,data:td.data,backgroundColor:makeGrad(ctx2,[C_GREEN,C_TEAL]),borderRadius:4}}]}},
        options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{{legend:{{display:false}}}},scales:{{x:{{grid:{{color:'#2a2a38'}}}},y:{{grid:{{display:false}},ticks:{{font:{{size:11}}}}}}}}}}
    }});
}})();

// ── Top processes bar ─────────────────────────────────────────────────────────
(function(){{
    const raw = {json.dumps(report.stats.get('top_processes', {}))};
    const labels = Object.keys(raw).slice(0,15);
    const data = labels.map(k=>raw[k]);
    if (!labels.length) {{
        document.getElementById('chartTopProcs').parentElement.innerHTML = '<div style="color:#5a5a78;text-align:center;padding:80px 0;font-size:13px">No process data</div>';
        return;
    }}
    const ctx3 = document.getElementById('chartTopProcs').getContext('2d');
    new Chart(ctx3, {{
        type:'bar',
        data:{{
            labels,
            datasets:[{{
                label:'Events',
                data,
                backgroundColor:makeGrad(ctx3,[C_TEAL,C_BLUE]),
                borderRadius:4,
            }}]
        }},
        options:{{
            indexAxis:'y',responsive:true,maintainAspectRatio:false,
            plugins:{{legend:{{display:false}}}},
            scales:{{
                x:{{grid:{{color:'#2a2a38'}},ticks:{{precision:0}}}},
                y:{{grid:{{display:false}},ticks:{{font:{{size:10}}}}}}
            }}
        }}
    }});
}})();

// ── Table search ──────────────────────────────────────────────────────────────
function filterTable(tableId, inputId) {{
    const q = document.getElementById(inputId).value.toLowerCase();
    const rows = document.querySelectorAll(`#${{tableId}} tbody tr`);
    rows.forEach(row => {{
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    }});
}}

// ── Sidebar active link tracking ─────────────────────────────────────────────
const sections = document.querySelectorAll('.section');
const navItems = document.querySelectorAll('.sidebar-item[href]');
const observer = new IntersectionObserver((entries) => {{
    entries.forEach(entry => {{
        if (entry.isIntersecting) {{
            navItems.forEach(item => item.classList.remove('active'));
            const active = document.querySelector(`.sidebar-item[href="#${{entry.target.id}}"]`);
            if (active) active.classList.add('active');
        }}
    }});
}}, {{rootMargin:'-30% 0px -60% 0px'}});
sections.forEach(s => observer.observe(s));

}}); // end waitForChart
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)

    return output_path
