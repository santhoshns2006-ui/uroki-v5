#!/usr/bin/env python3
"""
Uroki v5.0 — Advanced Security Analysis Platform
A hybrid of Splunk + Wireshark + Zeek — automated intelligent analyzer.

Usage:
    uroki.py analyze logs  -f file1.log file2.log [-o report.html] [--json]
    uroki.py analyze pcap  -f capture.pcap         [-o report.html] [--json]
    uroki.py analyze all   -f *.log capture.pcap   [-o report.html] [--json]
    uroki.py plugins list
    uroki.py plugins check
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import os
import sys
import time
import traceback
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Optional rich / yaml imports (graceful fallback) ─────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.text import Text
    from rich.align import Align
    from rich.columns import Columns
    from rich.rule import Rule
    from rich.syntax import Syntax
    from rich import box
    RICH = True
except ImportError:
    RICH = False

try:
    import yaml
    YAML = True
except ImportError:
    YAML = False

# ── Engine imports ────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from engine import (
    MultiFormatParser, PcapReader, ThreatDetectionEngine, CorrelationEngine,
    calculate_severity_score, generate_recommendations,
    AnalysisReport, LogEntry, ThreatEvent, PcapSummary,
    SEVERITY_RANK,
)
from report_gen import generate_html_report

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("uroki")

# ── Constants ─────────────────────────────────────────────────────────────────
VERSION = "5.0.0"
PLUGIN_DIR = Path.home() / ".uroki" / "plugins"
SESSION_DIR = Path.home() / ".uroki" / "sessions"
CONFIG_PATHS = [
    Path.home() / ".uroki" / "config.yaml",
    Path.home() / ".uroki" / "config.json",
    Path("uroki.yaml"),
    Path("uroki.json"),
]

SEV_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "⚪",
    "none":     "✅",
}

SEV_RICH_COLOR = {
    "critical": "bold red",
    "high":     "bold yellow",
    "medium":   "yellow",
    "low":      "green",
    "info":     "dim white",
}

# ──────────────────────────────────────────────────────────────────────────────
# Console helpers
# ──────────────────────────────────────────────────────────────────────────────

if RICH:
    console = Console(highlight=False)

    def _print(msg: str, style: str = ""):
        console.print(msg, style=style)

    def _rule(title: str = "", style: str = "dim"):
        console.print(Rule(title, style=style))

    def _panel(content: str, title: str = "", style: str = "blue"):
        console.print(Panel(content, title=title, border_style=style, expand=False))

else:
    def _print(msg: str, style: str = ""):
        print(msg)

    def _rule(title: str = "", style: str = ""):
        print("\n" + ("─" * 60) + (f" {title} " if title else "") + ("─" * 60) + "\n")

    def _panel(content: str, title: str = "", style: str = ""):
        print(f"\n╔═ {title} ═╗\n{content}\n╚{'═'*(len(title)+4)}╝\n")


# ──────────────────────────────────────────────────────────────────────────────
# Config loader
# ──────────────────────────────────────────────────────────────────────────────

def load_config(config_path: Optional[str] = None) -> Dict:
    """Load YAML or JSON config from default locations or explicit path."""
    paths = [Path(config_path)] if config_path else CONFIG_PATHS
    for p in paths:
        if p.exists():
            try:
                with open(p, "r") as fh:
                    if p.suffix in (".yaml", ".yml") and YAML:
                        cfg = yaml.safe_load(fh) or {}
                    else:
                        cfg = json.load(fh)
                logger.info("Loaded config from %s", p)
                return cfg
            except Exception as exc:
                logger.warning("Failed to load config %s: %s", p, exc)
    return {}


# ──────────────────────────────────────────────────────────────────────────────
# Plugin system
# ──────────────────────────────────────────────────────────────────────────────

class PluginManager:
    """
    Loads Python plugins from ~/.uroki/plugins/.
    Each plugin must expose:
        - PLUGIN_NAME  : str
        - PLUGIN_VERSION: str
        - run(entries, threats, pcap_summary) -> List[ThreatEvent]
    """

    def __init__(self):
        self._plugins: List[Any] = []
        PLUGIN_DIR.mkdir(parents=True, exist_ok=True)

    def load_all(self) -> int:
        count = 0
        for py_file in PLUGIN_DIR.glob("*.py"):
            try:
                spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "run") and hasattr(mod, "PLUGIN_NAME"):
                    self._plugins.append(mod)
                    count += 1
                    logger.info("Loaded plugin: %s v%s", mod.PLUGIN_NAME, getattr(mod, "PLUGIN_VERSION", "?"))
            except Exception as exc:
                logger.warning("Plugin load error %s: %s", py_file, exc)
        return count

    def run_all(self, entries, threats, pcap_summary) -> List[ThreatEvent]:
        extra: List[ThreatEvent] = []
        for plugin in self._plugins:
            try:
                result = plugin.run(entries, threats, pcap_summary)
                if result:
                    extra.extend(result)
            except Exception as exc:
                logger.warning("Plugin %s error: %s", getattr(plugin, "PLUGIN_NAME", "?"), exc)
        return extra

    @property
    def plugins(self):
        return self._plugins


# ──────────────────────────────────────────────────────────────────────────────
# Stats builder
# ──────────────────────────────────────────────────────────────────────────────

def build_stats(entries: List[LogEntry], files: List[Path]) -> Dict:
    """Compute summary statistics from log entries."""
    if not entries:
        return {
            "total_entries": 0,
            "error_count": 0,
            "warning_count": 0,
            "info_count": 0,
            "unique_hosts": 0,
            "unique_processes": 0,
            "files_parsed": len(files),
            "date_range": "No data",
            "top_process": "N/A",
            "top_processes": {},
        }

    level_counts: Counter = Counter(e.log_level for e in entries)
    host_counts: Counter = Counter(e.host for e in entries)
    proc_counts: Counter = Counter(e.process for e in entries)

    timestamps = [e.timestamp for e in entries if e.timestamp]
    if timestamps:
        t0, t1 = min(timestamps), max(timestamps)
        date_range = f"{t0.strftime('%Y-%m-%d')} → {t1.strftime('%Y-%m-%d')}"
    else:
        date_range = "Unknown"

    return {
        "total_entries": len(entries),
        "error_count": level_counts.get("error", 0) + level_counts.get("critical", 0),
        "warning_count": level_counts.get("warning", 0),
        "info_count": level_counts.get("info", 0),
        "unique_hosts": len(host_counts),
        "unique_processes": len(proc_counts),
        "files_parsed": len(files),
        "date_range": date_range,
        "top_process": proc_counts.most_common(1)[0][0] if proc_counts else "N/A",
        "top_processes": dict(proc_counts.most_common(15)),
        "top_hosts": dict(host_counts.most_common(10)),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Progress-aware orchestrator
# ──────────────────────────────────────────────────────────────────────────────

class Uroki:
    """Main analysis orchestrator."""

    def __init__(self, config: Dict, verbose: bool = False):
        self.config = config
        self.verbose = verbose
        self.plugin_manager = PluginManager()
        self.parser = MultiFormatParser()
        self.detector = ThreatDetectionEngine(
            config=config.get("detection", {}),
            custom_rules=config.get("custom_rules", []),
        )
        self.correlator = CorrelationEngine()
        if verbose:
            logging.getLogger("uroki").setLevel(logging.DEBUG)

    # ── File classification ───────────────────────────────────────────────────

    @staticmethod
    def classify_files(files: List[Path]) -> Tuple[List[Path], List[Path]]:
        """Split input files into log files and PCAP files."""
        logs, pcaps = [], []
        pcap_exts = {".pcap", ".pcapng", ".cap", ".pcap.gz"}
        for f in files:
            if f.suffix.lower() in pcap_exts or f.name.endswith(".pcap.gz"):
                pcaps.append(f)
            else:
                logs.append(f)
        return logs, pcaps

    # ── Log analysis ──────────────────────────────────────────────────────────

    def analyze_logs(self, log_files: List[Path]) -> Tuple[List[LogEntry], List[ThreatEvent], Dict]:
        entries: List[LogEntry] = []
        _print(f"\n[bold cyan]📜 Parsing {len(log_files)} log file(s)…[/bold cyan]" if RICH
               else f"\n>>> Parsing {len(log_files)} log file(s)…")

        if RICH:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Parsing logs", total=len(log_files))
                for f in log_files:
                    progress.update(task, description=f"[cyan]{f.name}[/cyan]")
                    file_entries, fmt = self.parser.parse_file(f)
                    entries.extend(file_entries)
                    progress.advance(task)
                    if self.verbose:
                        console.print(f"  [dim]{f.name}[/dim] → {len(file_entries)} entries ({fmt})")
        else:
            for i, f in enumerate(log_files, 1):
                file_entries, fmt = self.parser.parse_file(f)
                entries.extend(file_entries)
                print(f"  [{i}/{len(log_files)}] {f.name} — {len(file_entries)} entries ({fmt})")

        _print(f"  Total entries: [bold]{len(entries):,}[/bold]" if RICH else f"  Total: {len(entries):,}")

        _print("\n[bold cyan]🔍 Running threat detection…[/bold cyan]" if RICH else "\n>>> Threat detection…")
        threats = self.detector.analyze_logs(entries)
        _print(f"  Detected: [bold red]{len(threats)}[/bold red] threat events" if RICH
               else f"  Threats: {len(threats)}")

        stats = build_stats(entries, log_files)
        return entries, threats, stats

    # ── PCAP analysis ─────────────────────────────────────────────────────────

    def analyze_pcap(self, pcap_files: List[Path]) -> Tuple[Optional[PcapSummary], List[ThreatEvent]]:
        if not pcap_files:
            return None, []

        _print(f"\n[bold cyan]📡 Analysing {len(pcap_files)} PCAP file(s)…[/bold cyan]" if RICH
               else f"\n>>> Analysing {len(pcap_files)} PCAP file(s)…")

        all_packets = []
        for pcap_path in pcap_files:
            _print(f"  Reading [cyan]{pcap_path.name}[/cyan]…" if RICH else f"  Reading {pcap_path.name}…")
            reader = PcapReader(pcap_path)
            pkts = list(reader.read())
            all_packets.extend(pkts)
            _print(f"  → [bold]{len(pkts):,}[/bold] packets" if RICH else f"  → {len(pkts):,} packets")

        if not all_packets:
            _print("[yellow]⚠  No packets could be read from PCAP files[/yellow]" if RICH
                   else "!  No packets read from PCAPs")
            return PcapSummary(), []

        _print(f"\n[bold cyan]🔍 Analysing {len(all_packets):,} packets…[/bold cyan]" if RICH
               else f"\n>>> Analysing {len(all_packets):,} packets…")
        summary, threats = self.detector.analyze_pcap(all_packets)
        _print(f"  Flows: [bold]{len(summary.flows):,}[/bold]  DNS queries: [bold]{len(summary.dns_queries):,}[/bold]  PCAP threats: [bold red]{len(threats)}[/bold red]"
               if RICH else f"  Flows: {len(summary.flows):,}  DNS: {len(summary.dns_queries):,}  Threats: {len(threats)}")
        return summary, threats

    # ── Full analysis run ─────────────────────────────────────────────────────

    def run(self, files: List[Path], output: str = "report.html",
            export_json: bool = False, mode: str = "all") -> AnalysisReport:
        start = time.perf_counter()

        # Load plugins
        n_plugins = self.plugin_manager.load_all()
        if n_plugins:
            _print(f"[green]🔌 {n_plugins} plugin(s) loaded[/green]" if RICH else f"  {n_plugins} plugins loaded")

        log_files, pcap_files = self.classify_files(files)

        # Mode filtering
        if mode == "logs":
            pcap_files = []
        elif mode == "pcap":
            log_files = []

        # ── Log analysis ──────────────────────────────────────────────────────
        entries: List[LogEntry] = []
        log_threats: List[ThreatEvent] = []
        stats: Dict = {}
        if log_files:
            entries, log_threats, stats = self.analyze_logs(log_files)
        else:
            stats = build_stats([], [])

        # ── PCAP analysis ─────────────────────────────────────────────────────
        pcap_summary: Optional[PcapSummary] = None
        pcap_threats: List[ThreatEvent] = []
        if pcap_files:
            pcap_summary, pcap_threats = self.analyze_pcap(pcap_files)

        # ── Plugin execution ──────────────────────────────────────────────────
        if n_plugins:
            _print("\n[bold cyan]🔌 Running plugins…[/bold cyan]" if RICH else "\n>>> Running plugins…")
            plugin_threats = self.plugin_manager.run_all(entries, log_threats + pcap_threats, pcap_summary)
            _print(f"  Plugin threats: [bold]{len(plugin_threats)}[/bold]" if RICH
                   else f"  Plugin threats: {len(plugin_threats)}")
        else:
            plugin_threats = []

        # ── Correlation ───────────────────────────────────────────────────────
        _print("\n[bold cyan]🔗 Correlating events…[/bold cyan]" if RICH else "\n>>> Correlating events…")
        all_threats, timeline, ip_intel = self.correlator.correlate(
            entries, log_threats + plugin_threats, pcap_summary, pcap_threats
        )

        # ── Scoring & recommendations ─────────────────────────────────────────
        score, score_label = calculate_severity_score(all_threats)
        recommendations = generate_recommendations(all_threats, stats)

        # ── Build report ──────────────────────────────────────────────────────
        report = AnalysisReport(
            generated_at=datetime.now(),
            log_entries=entries,
            threats=all_threats,
            pcap_summary=pcap_summary,
            severity_score=score,
            severity_label=score_label,
            stats=stats,
            timeline=timeline,
            ip_correlation=ip_intel,
            recommendations=recommendations,
        )

        # ── Generate HTML ─────────────────────────────────────────────────────
        _print(f"\n[bold cyan]📊 Generating HTML report → [white]{output}[/white][/bold cyan]" if RICH
               else f"\n>>> Generating HTML → {output}")
        generate_html_report(report, output)

        # ── JSON export ───────────────────────────────────────────────────────
        if export_json:
            json_path = output.replace(".html", ".json")
            with open(json_path, "w", encoding="utf-8") as fh:
                json.dump(report.to_dict(), fh, indent=2, default=str)
            _print(f"[green]✓ JSON exported → {json_path}[/green]" if RICH else f"  JSON → {json_path}")

        elapsed = time.perf_counter() - start
        _print(f"\n[green]✓ Analysis complete in {elapsed:.2f}s[/green]" if RICH
               else f"\n✓ Done in {elapsed:.2f}s")

        return report


# ──────────────────────────────────────────────────────────────────────────────
# CLI output — summary printer
# ──────────────────────────────────────────────────────────────────────────────

def print_summary(report: AnalysisReport):
    """Print a rich CLI summary of the analysis results."""
    sev_color = SEV_RICH_COLOR.get(report.severity_label.lower(), "white")
    emoji = SEV_EMOJI.get(report.severity_label.lower(), "❓")

    if RICH:
        _rule("  UROKI v5.0 — ANALYSIS REPORT  ", style="bold blue")

        # Score panel
        score_text = Text()
        score_text.append(f"\n  {emoji} Severity Score: ", style="bold")
        score_text.append(f"{report.severity_score}/100", style=f"bold {sev_color}")
        score_text.append(f"  ({report.severity_label})\n", style=sev_color)
        score_text.append(f"  📅 Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}\n", style="dim")
        score_text.append(f"  📄 Log Entries: {report.stats.get('total_entries',0):,}\n", style="dim")
        if report.pcap_summary:
            score_text.append(f"  📡 PCAP Packets: {report.pcap_summary.total_packets:,}\n", style="dim")
        console.print(Panel(score_text, border_style=sev_color, title="Uroki Security Report", expand=False))

        # Threats table
        if report.threats:
            _rule("  THREATS  ", style="bold red")
            tbl = Table(box=box.ROUNDED, show_header=True, header_style="bold dim",
                        border_style="dim", row_styles=["", "dim"], expand=True)
            tbl.add_column("Sev", width=8)
            tbl.add_column("Rule", width=12)
            tbl.add_column("Threat Name", min_width=30)
            tbl.add_column("Source IP", width=18)
            tbl.add_column("Timestamp", width=20)
            tbl.add_column("Evidence", min_width=40)

            for t in sorted(report.threats, key=lambda x: x.severity_rank, reverse=True):
                row_style = SEV_RICH_COLOR.get(t.severity, "white")
                evidence = (t.evidence[0][:60] + "…") if t.evidence and len(t.evidence[0]) > 60 else (t.evidence[0] if t.evidence else "")
                tbl.add_row(
                    Text(f"{SEV_EMOJI[t.severity]} {t.severity.upper()}", style=row_style),
                    t.rule_id,
                    t.name,
                    t.source_ip or "—",
                    t.timestamp.strftime("%Y-%m-%d %H:%M") if t.timestamp else "—",
                    evidence,
                )
            console.print(tbl)
        else:
            console.print("\n[green]✅ No threats detected[/green]")

        # PCAP summary
        if report.pcap_summary:
            _rule("  NETWORK SUMMARY  ", style="bold green")
            pcap = report.pcap_summary
            net_info = Text()
            net_info.append(f"  Packets: {pcap.total_packets:,}  |  Bytes: {pcap.total_bytes:,}  |  Duration: {pcap.duration_seconds:.2f}s\n")
            net_info.append(f"  Flows: {len(pcap.flows):,}  |  DNS: {len(pcap.dns_queries):,}  |  HTTP: {len(pcap.http_transactions):,}  |  TLS: {len(pcap.tls_sessions):,}\n")
            if pcap.suspicious_ips:
                net_info.append(f"  🚨 Suspicious IPs: {', '.join(list(pcap.suspicious_ips)[:8])}\n", style="red")
            if pcap.port_scan_candidates:
                net_info.append(f"  🔍 Port Scan: {', '.join(pcap.port_scan_candidates[:4])}\n", style="yellow")
            console.print(Panel(net_info, title="PCAP Analysis", border_style="green", expand=False))

        # Log stats
        _rule("  LOG STATISTICS  ", style="bold cyan")
        s = report.stats
        stats_text = Text()
        stats_text.append(f"  Entries: {s.get('total_entries',0):,}  |  Errors: {s.get('error_count',0):,}  |  Warnings: {s.get('warning_count',0):,}\n")
        stats_text.append(f"  Hosts: {s.get('unique_hosts',0)}  |  Processes: {s.get('unique_processes',0)}  |  Range: {s.get('date_range','?')}\n")
        console.print(Panel(stats_text, title="Log Stats", border_style="cyan", expand=False))

        # Recommendations
        if report.recommendations:
            _rule("  RECOMMENDATIONS  ", style="bold yellow")
            for i, rec in enumerate(report.recommendations, 1):
                console.print(f"  [yellow]{i}.[/yellow] {rec}")

        # Report location
        _rule()
        console.print(f"  [bold green]📄 HTML Report ready[/bold green]")
        console.print(f"  [bold blue]Open in browser:[/bold blue] report.html\n")

    else:
        # Plain text fallback
        print("\n" + "="*70)
        print(f"  UROKI v5.0 SECURITY REPORT")
        print(f"  Score: {report.severity_score}/100 ({report.severity_label})")
        print(f"  Threats: {len(report.threats)}")
        print("="*70)
        for t in sorted(report.threats, key=lambda x: x.severity_rank, reverse=True):
            print(f"  [{t.severity.upper():8}] {t.rule_id} — {t.name}")
            if t.evidence:
                print(f"           {t.evidence[0][:80]}")
        print("\n  Recommendations:")
        for i, r in enumerate(report.recommendations, 1):
            print(f"  {i}. {r}")
        print("="*70)


# ──────────────────────────────────────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────────────────────────────────────

BANNER = r"""
 ██╗   ██╗██████╗  ██████╗ ██╗  ██╗██╗
 ██║   ██║██╔══██╗██╔═══██╗██║ ██╔╝██║
 ██║   ██║██████╔╝██║   ██║█████╔╝ ██║
 ██║   ██║██╔══██╗██║   ██║██╔═██╗ ██║
 ╚██████╔╝██║  ██║╚██████╔╝██║  ██╗██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  v5.0
  Advanced Security Analysis Platform
  Splunk × Wireshark × Zeek — Automated
"""


def print_banner():
    if RICH:
        console.print(BANNER, style="bold blue")
        console.print(Rule(style="dim blue"))
    else:
        print(BANNER)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin sub-commands
# ──────────────────────────────────────────────────────────────────────────────

def cmd_plugins_list(args):
    pm = PluginManager()
    pm.load_all()
    if not pm.plugins:
        _print(f"[yellow]No plugins found in {PLUGIN_DIR}[/yellow]" if RICH
               else f"No plugins in {PLUGIN_DIR}")
        _print(f"  Place .py plugin files in [cyan]{PLUGIN_DIR}[/cyan]" if RICH
               else f"  Place .py plugins in {PLUGIN_DIR}")
        return
    if RICH:
        tbl = Table(box=box.ROUNDED, header_style="bold dim")
        tbl.add_column("Name")
        tbl.add_column("Version")
        tbl.add_column("File")
        for p in pm.plugins:
            tbl.add_row(p.PLUGIN_NAME, getattr(p, "PLUGIN_VERSION", "?"),
                        str(getattr(p, "__file__", "?")))
        console.print(tbl)
    else:
        for p in pm.plugins:
            print(f"  {p.PLUGIN_NAME} v{getattr(p,'PLUGIN_VERSION','?')}")


def cmd_plugins_check(args):
    """Write a sample plugin template."""
    sample = PLUGIN_DIR / "sample_plugin.py"
    PLUGIN_DIR.mkdir(parents=True, exist_ok=True)
    template = '''\
"""
Sample Uroki plugin — rename and customise.
"""
from engine import ThreatEvent
from datetime import datetime

PLUGIN_NAME    = "SamplePlugin"
PLUGIN_VERSION = "1.0.0"


def run(entries, threats, pcap_summary):
    """
    entries       : List[LogEntry]
    threats       : List[ThreatEvent]  (already detected)
    pcap_summary  : PcapSummary | None
    Returns       : List[ThreatEvent]
    """
    new_threats = []
    for entry in entries:
        if "SAMPLE_KEYWORD" in entry.message:
            new_threats.append(ThreatEvent(
                rule_id="PLUGIN-001",
                name="Sample Detection",
                description="Plugin matched SAMPLE_KEYWORD",
                severity="low",
                mitre_tactic="Custom",
                mitre_technique="Custom — Sample",
                timestamp=entry.timestamp,
                source_ip=None,
                dest_ip=None,
                source_port=None,
                dest_port=None,
                host=entry.host,
                process=entry.process,
                evidence=[entry.message[:200]],
                tags=["plugin","sample"],
                raw_entries=[entry.raw],
            ))
    return new_threats
'''
    with open(sample, "w") as fh:
        fh.write(template)
    _print(f"[green]✓ Sample plugin written to {sample}[/green]" if RICH
           else f"  Sample plugin → {sample}")


# ──────────────────────────────────────────────────────────────────────────────
# Argument parser
# ──────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uroki",
        description="Uroki v5.0 — Advanced Security Analysis Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  uroki analyze logs  -f auth.log syslog.log
  uroki analyze pcap  -f capture.pcap -o pcap_report.html --json
  uroki analyze all   -f *.log capture.pcap --json
  uroki plugins list
  uroki plugins check
        """,
    )
    parser.add_argument("--version", action="version", version=f"Uroki v{VERSION}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--config", metavar="PATH", help="Config file path (YAML or JSON)")
    parser.add_argument("--no-banner", action="store_true", help="Suppress ASCII banner")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── analyze ───────────────────────────────────────────────────────────────
    analyze_p = sub.add_parser("analyze", help="Run analysis", aliases=["a"])
    analyze_sub = analyze_p.add_subparsers(dest="mode", metavar="MODE")

    # Common analyse args
    def add_analyze_args(p):
        p.add_argument("-f", "--files", nargs="+", required=True, metavar="FILE",
                       help="Input file(s): log files and/or PCAP files")
        p.add_argument("-o", "--output", default="report.html", metavar="PATH",
                       help="Output HTML report path (default: report.html)")
        p.add_argument("--json", action="store_true", help="Also export JSON")
        p.add_argument("--no-html", action="store_true", help="Skip HTML report (CLI only)")
        p.add_argument("--min-severity", choices=["info","low","medium","high","critical"],
                       default="info", help="Filter threats below this severity")
        p.add_argument("--rules", metavar="FILE", help="Custom rules JSON file")

    logs_p = analyze_sub.add_parser("logs", help="Analyse log files only")
    add_analyze_args(logs_p)

    pcap_p = analyze_sub.add_parser("pcap", help="Analyse PCAP file(s) only")
    add_analyze_args(pcap_p)

    all_p = analyze_sub.add_parser("all", help="Analyse logs + PCAP together")
    add_analyze_args(all_p)

    # ── plugins ───────────────────────────────────────────────────────────────
    plugins_p = sub.add_parser("plugins", help="Manage plugins", aliases=["p"])
    plugins_sub = plugins_p.add_subparsers(dest="plugin_mode", metavar="ACTION")
    plugins_sub.add_parser("list", help="List installed plugins")
    plugins_sub.add_parser("check", help="Write sample plugin template")

    return parser


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.no_banner if hasattr(args, "no_banner") else True:
        print_banner()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    config = load_config(args.config if hasattr(args, "config") else None)

    # ── Plugin commands ───────────────────────────────────────────────────────
    if args.command in ("plugins", "p"):
        if args.plugin_mode == "list":
            cmd_plugins_list(args)
        elif args.plugin_mode == "check":
            cmd_plugins_check(args)
        else:
            parser.parse_args(["plugins", "--help"])
        return

    # ── Analyze commands ──────────────────────────────────────────────────────
    if args.command in ("analyze", "a"):
        if not args.mode:
            analyze_p = [p for p in parser._subparsers._group_actions
                         if hasattr(p, '_name_parser_map') and 'analyze' in p._name_parser_map]
            parser.print_help()
            sys.exit(1)

        # Validate files — handle absolute paths, relative paths, globs
        files: List[Path] = []
        missing = []
        cwd = Path.cwd()
        for f in args.files:
            p = Path(f)
            # Resolve relative paths against cwd
            if not p.is_absolute():
                p = cwd / p
            if p.exists():
                files.append(p.resolve())
            else:
                # Try glob only for relative patterns (no leading /)
                try:
                    rel = Path(f)
                    if not rel.is_absolute():
                        expanded = list(cwd.glob(f))
                    else:
                        expanded = []
                except (NotImplementedError, ValueError):
                    expanded = []
                if expanded:
                    files.extend(ep.resolve() for ep in expanded)
                else:
                    missing.append(f)
        if missing:
            _print(f"[red]✗ Files not found: {', '.join(missing)}[/red]" if RICH
                   else f"  ERROR: Files not found: {', '.join(missing)}")
            sys.exit(1)

        if not files:
            _print("[red]✗ No valid input files provided[/red]" if RICH else "  ERROR: No input files")
            sys.exit(1)

        # Load custom rules
        if hasattr(args, "rules") and args.rules:
            try:
                with open(args.rules) as fh:
                    custom_rules = json.load(fh)
                config.setdefault("custom_rules", []).extend(custom_rules)
                _print(f"[green]✓ Loaded {len(custom_rules)} custom rules[/green]" if RICH
                       else f"  {len(custom_rules)} custom rules loaded")
            except Exception as exc:
                _print(f"[yellow]⚠ Could not load custom rules: {exc}[/yellow]" if RICH
                       else f"  WARN: custom rules error: {exc}")

        # Run
        uroki = Uroki(config=config, verbose=args.verbose)
        try:
            report = uroki.run(
                files=files,
                output=args.output,
                export_json=args.json,
                mode=args.mode,
            )
        except KeyboardInterrupt:
            _print("\n[yellow]⚠ Analysis interrupted[/yellow]" if RICH else "\n  Interrupted")
            sys.exit(130)
        except Exception as exc:
            _print(f"[red]✗ Analysis failed: {exc}[/red]" if RICH else f"  ERROR: {exc}")
            if args.verbose:
                traceback.print_exc()
            sys.exit(1)

        # Filter by min severity
        min_rank = SEVERITY_RANK.get(args.min_severity, 0)
        report.threats = [t for t in report.threats if t.severity_rank >= min_rank]

        # Print CLI summary
        print_summary(report)

        # Regenerate HTML with filtered threats if needed
        if min_rank > 0:
            generate_html_report(report, args.output)

        return

    parser.print_help()


if __name__ == "__main__":
    main()
