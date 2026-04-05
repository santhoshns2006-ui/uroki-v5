"""
Uroki Engine — Core analysis engine: parsers, detectors, correlators.
Handles syslog, journald, auth, dpkg, Apache/Nginx, JSON, CSV, PCAP.
"""

from __future__ import annotations

import re
import os
import sys
import csv
import json
import gzip
import math
import struct
import socket
import hashlib
import logging
import ipaddress
import statistics
from abc import ABC, abstractmethod
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, Iterator, List, Optional, Set, Tuple

logger = logging.getLogger("uroki.engine")

# ──────────────────────────────────────────────────────────────────────────────
# Data models
# ──────────────────────────────────────────────────────────────────────────────

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class LogEntry:
    """Normalised log entry — common schema across all log formats."""
    timestamp: Optional[datetime]
    host: str
    process: str
    pid: Optional[int]
    message: str
    raw: str
    source_file: str
    line_number: int
    log_level: str = "info"
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return d


@dataclass
class ThreatEvent:
    """A single detected threat event."""
    rule_id: str
    name: str
    description: str
    severity: str          # info | low | medium | high | critical
    mitre_tactic: str
    mitre_technique: str
    timestamp: Optional[datetime]
    source_ip: Optional[str]
    dest_ip: Optional[str]
    source_port: Optional[int]
    dest_port: Optional[int]
    host: str
    process: str
    evidence: List[str]
    tags: List[str]
    raw_entries: List[str]

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 0)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return d


@dataclass
class NetworkFlow:
    """Reconstructed or inferred network flow."""
    proto: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    packets: int
    bytes_total: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    flags: Set[str] = field(default_factory=set)
    payload_sample: bytes = b""
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    http_host: Optional[str] = None
    http_status: Optional[int] = None
    dns_queries: List[str] = field(default_factory=list)
    tls_sni: Optional[str] = None
    service: Optional[str] = None
    is_suspicious: bool = False
    suspicion_reason: str = ""

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["flags"] = list(self.flags)
        d["payload_sample"] = self.payload_sample.hex()
        d["first_seen"] = self.first_seen.isoformat() if self.first_seen else None
        d["last_seen"] = self.last_seen.isoformat() if self.last_seen else None
        return d


@dataclass
class PcapSummary:
    """High-level summary of PCAP analysis."""
    total_packets: int = 0
    total_bytes: int = 0
    duration_seconds: float = 0.0
    protocols: Dict[str, int] = field(default_factory=dict)
    top_talkers: List[Tuple[str, int]] = field(default_factory=list)
    flows: List[NetworkFlow] = field(default_factory=list)
    dns_queries: List[Dict] = field(default_factory=list)
    http_transactions: List[Dict] = field(default_factory=list)
    suspicious_ips: Set[str] = field(default_factory=set)
    port_scan_candidates: List[str] = field(default_factory=list)
    beaconing_candidates: List[Dict] = field(default_factory=list)
    tls_sessions: List[Dict] = field(default_factory=list)
    arp_table: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "duration_seconds": self.duration_seconds,
            "protocols": self.protocols,
            "top_talkers": self.top_talkers,
            "flows": [f.to_dict() for f in self.flows],
            "dns_queries": self.dns_queries,
            "http_transactions": self.http_transactions,
            "suspicious_ips": list(self.suspicious_ips),
            "port_scan_candidates": self.port_scan_candidates,
            "beaconing_candidates": self.beaconing_candidates,
            "tls_sessions": self.tls_sessions,
            "arp_table": self.arp_table,
            "errors": self.errors,
        }


@dataclass
class AnalysisReport:
    """Final merged analysis output."""
    generated_at: datetime
    log_entries: List[LogEntry]
    threats: List[ThreatEvent]
    pcap_summary: Optional[PcapSummary]
    severity_score: int
    severity_label: str
    stats: Dict[str, Any]
    timeline: List[Dict]
    ip_correlation: Dict[str, Dict]
    recommendations: List[str]

    def to_dict(self) -> Dict:
        return {
            "generated_at": self.generated_at.isoformat(),
            "severity_score": self.severity_score,
            "severity_label": self.severity_label,
            "stats": self.stats,
            "threats": [t.to_dict() for t in self.threats],
            "timeline": self.timeline,
            "ip_correlation": self.ip_correlation,
            "recommendations": self.recommendations,
            "log_entries_count": len(self.log_entries),
            "pcap": self.pcap_summary.to_dict() if self.pcap_summary else None,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Log parsers
# ──────────────────────────────────────────────────────────────────────────────

class BaseLogParser(ABC):
    """Abstract base for all log parsers."""

    @abstractmethod
    def can_parse(self, line: str) -> bool:
        """Return True if this parser can handle this line."""

    @abstractmethod
    def parse_line(self, line: str, source: str, lineno: int) -> Optional[LogEntry]:
        """Parse a single line into a LogEntry, or None on failure."""

    def parse_file(self, path: Path) -> List[LogEntry]:
        """Parse an entire file, returning all recognised entries."""
        entries: List[LogEntry] = []
        opener = gzip.open if path.suffix == ".gz" else open
        mode = "rt" if path.suffix == ".gz" else "r"
        try:
            with opener(path, mode, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    try:
                        entry = self.parse_line(line, str(path), lineno)
                        if entry:
                            entries.append(entry)
                    except Exception as exc:
                        logger.debug("Parse error %s:%d — %s", path, lineno, exc)
        except Exception as exc:
            logger.warning("Cannot open %s: %s", path, exc)
        return entries


class SyslogParser(BaseLogParser):
    """Handles RFC 3164 syslog / journald plaintext exports."""

    # e.g. Mar 23 17:45:07 sandy kernel: ...
    _PATTERN = re.compile(
        r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
        r"\s+(?P<host>\S+)"
        r"\s+(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
    )
    _MONTHS = {m: i for i, m in enumerate(
        ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], 1)}

    def can_parse(self, line: str) -> bool:
        return bool(self._PATTERN.match(line))

    def parse_line(self, line: str, source: str, lineno: int) -> Optional[LogEntry]:
        m = self._PATTERN.match(line)
        if not m:
            return None
        month = self._MONTHS.get(m.group("month"), 1)
        day = int(m.group("day"))
        h, mi, s = map(int, m.group("time").split(":"))
        year = datetime.now().year
        try:
            ts = datetime(year, month, day, h, mi, s)  # already naive
        except ValueError:
            ts = None
        pid_str = m.group("pid")
        return LogEntry(
            timestamp=ts,
            host=m.group("host"),
            process=m.group("process"),
            pid=int(pid_str) if pid_str else None,
            message=m.group("message"),
            raw=line,
            source_file=source,
            line_number=lineno,
            log_level=_infer_level(m.group("message")),
        )


class JournaldParser(BaseLogParser):
    """Handles journalctl --output=short-precise or short-iso exports."""

    # 2026-03-23T17:45:07.123456+0000 hostname process[pid]: message
    _ISO = re.compile(
        r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4}|Z)?)"
        r"\s+(?P<host>\S+)\s+(?P<process>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
    )

    def can_parse(self, line: str) -> bool:
        return bool(self._ISO.match(line))

    def parse_line(self, line: str, source: str, lineno: int) -> Optional[LogEntry]:
        m = self._ISO.match(line)
        if not m:
            return None
        try:
            raw_ts = m.group("ts").replace("+0000", "+00:00").replace("Z", "+00:00")
            ts = datetime.fromisoformat(raw_ts)
        except ValueError:
            ts = None
        pid_str = m.group("pid")
        return LogEntry(
            timestamp=ts,
            host=m.group("host"),
            process=m.group("process"),
            pid=int(pid_str) if pid_str else None,
            message=m.group("message"),
            raw=line,
            source_file=source,
            line_number=lineno,
            log_level=_infer_level(m.group("message")),
        )


class ApacheNginxParser(BaseLogParser):
    """Combined combined/common log format parser for Apache & Nginx."""

    # 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
    _COMBINED = re.compile(
        r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+(?P<proto>[^"]+)"\s+'
        r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    )
    _TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

    def can_parse(self, line: str) -> bool:
        return bool(self._COMBINED.match(line))

    def parse_line(self, line: str, source: str, lineno: int) -> Optional[LogEntry]:
        m = self._COMBINED.match(line)
        if not m:
            return None
        try:
            ts = datetime.strptime(m.group("time"), self._TIME_FMT)
            if ts.tzinfo is not None:
                ts = ts.replace(tzinfo=None)
        except ValueError:
            ts = None
        status = int(m.group("status"))
        size_str = m.group("size")
        raw_ip = m.group("ip")
        # Strip IPv4-mapped IPv6 prefix ::ffff:
        if raw_ip.startswith("::ffff:"):
            raw_ip = raw_ip[7:]
        return LogEntry(
            timestamp=ts,
            host=raw_ip,
            process="httpd",
            pid=None,
            message=f'{m.group("method")} {m.group("uri")} → HTTP {status}',
            raw=line,
            source_file=source,
            line_number=lineno,
            log_level="error" if status >= 500 else ("warning" if status >= 400 else "info"),
            extra={
                "ip": raw_ip,
                "method": m.group("method"),
                "uri": m.group("uri"),
                "status": status,
                "bytes": int(size_str) if size_str.isdigit() else 0,
                "user_agent": m.group("ua") or "",
                "referer": m.group("referer") or "",
            }
        )


class AuthLogParser(BaseLogParser):
    """Auth.log / secure parser (often syslog format, extra auth-aware extraction)."""

    _SYSLOG = SyslogParser()
    _AUTH_FIELDS = re.compile(
        r'(?:(?:Failed|Accepted|Invalid)\s+\w+\s+for\s+(?P<user>\S+))|'
        r'(?:from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}))|'
        r'(?:port\s+(?P<port>\d+))'
    )

    def can_parse(self, line: str) -> bool:
        return self._SYSLOG.can_parse(line)

    def parse_line(self, line: str, source: str, lineno: int) -> Optional[LogEntry]:
        entry = self._SYSLOG.parse_line(line, source, lineno)
        if not entry:
            return None
        for m in self._AUTH_FIELDS.finditer(line):
            if m.group("ip"):
                entry.extra.setdefault("remote_ip", m.group("ip"))
            if m.group("user"):
                entry.extra.setdefault("auth_user", m.group("user"))
            if m.group("port"):
                entry.extra.setdefault("remote_port", int(m.group("port")))
        return entry


class DpkgLogParser(BaseLogParser):
    """Debian dpkg.log parser."""

    # 2026-03-06 10:00:23 install python3:amd64 <none> 3.11.2-1
    _PATTERN = re.compile(
        r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<action>\S+)\s+(?P<package>\S+)\s+(?P<old_ver>\S+)\s+(?P<new_ver>\S+)$"
    )

    def can_parse(self, line: str) -> bool:
        return bool(self._PATTERN.match(line))

    def parse_line(self, line: str, source: str, lineno: int) -> Optional[LogEntry]:
        m = self._PATTERN.match(line)
        if not m:
            return None
        try:
            ts = datetime.fromisoformat(f"{m.group('date')}T{m.group('time')}")
            if ts.tzinfo is not None:
                ts = ts.replace(tzinfo=None)
        except ValueError:
            ts = None
        return LogEntry(
            timestamp=ts,
            host="localhost",
            process="dpkg",
            pid=None,
            message=f"{m.group('action')} {m.group('package')} → {m.group('new_ver')}",
            raw=line,
            source_file=source,
            line_number=lineno,
            extra={
                "action": m.group("action"),
                "package": m.group("package"),
                "old_version": m.group("old_ver"),
                "new_version": m.group("new_ver"),
            }
        )


class JSONLogParser(BaseLogParser):
    """Newline-delimited JSON log parser."""

    def can_parse(self, line: str) -> bool:
        return line.startswith("{")

    def parse_line(self, line: str, source: str, lineno: int) -> Optional[LogEntry]:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        ts = None
        for key in ("timestamp", "time", "@timestamp", "datetime", "date"):
            if key in obj:
                try:
                    ts = datetime.fromisoformat(str(obj[key]).replace("Z", "+00:00"))
                    if ts.tzinfo is not None:
                        ts = ts.replace(tzinfo=None)
                    break
                except ValueError:
                    pass
        msg = obj.get("message", obj.get("msg", obj.get("log", str(obj))))
        return LogEntry(
            timestamp=ts,
            host=str(obj.get("host", obj.get("hostname", "unknown"))),
            process=str(obj.get("service", obj.get("app", obj.get("logger", "unknown")))),
            pid=None,
            message=str(msg),
            raw=line,
            source_file=source,
            line_number=lineno,
            log_level=str(obj.get("level", obj.get("severity", "info"))).lower(),
            extra=obj,
        )


class CSVLogParser(BaseLogParser):
    """CSV log parser — first row must be headers."""

    def __init__(self):
        self._headers: List[str] = []
        self._initialized: bool = False

    def can_parse(self, line: str) -> bool:
        return "," in line

    def parse_line(self, line: str, source: str, lineno: int) -> Optional[LogEntry]:
        reader = csv.reader([line])
        try:
            row = next(reader)
        except StopIteration:
            return None
        if not self._initialized:
            self._headers = row
            self._initialized = True
            return None
        if len(row) != len(self._headers):
            return None
        obj = dict(zip(self._headers, row))
        ts = None
        for key in ("timestamp", "time", "datetime"):
            if key in obj:
                try:
                    ts = datetime.fromisoformat(obj[key])
                    break
                except ValueError:
                    pass
        return LogEntry(
            timestamp=ts,
            host=obj.get("host", obj.get("hostname", "unknown")),
            process=obj.get("process", obj.get("service", "unknown")),
            pid=None,
            message=obj.get("message", obj.get("msg", str(row))),
            raw=line,
            source_file=source,
            line_number=lineno,
            extra=obj,
        )


class MultiFormatParser:
    """Auto-detecting parser that tries all parsers in priority order."""

    def __init__(self, extra_parsers: List[BaseLogParser] = None):
        self._parsers: List[BaseLogParser] = [
            JournaldParser(),
            ApacheNginxParser(),
            DpkgLogParser(),
            JSONLogParser(),
            AuthLogParser(),   # must come before SyslogParser (inherits from it)
            SyslogParser(),
        ]
        if extra_parsers:
            self._parsers = extra_parsers + self._parsers

    def parse_file(self, path: Path) -> Tuple[List[LogEntry], str]:
        """Parse file, auto-detecting format. Returns (entries, detected_format)."""
        detected = "unknown"
        entries: List[LogEntry] = []
        opener = gzip.open if path.suffix == ".gz" else open
        mode = "rt" if path.suffix == ".gz" else "r"

        # Detect format from first non-empty line
        try:
            with opener(path, mode, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    for parser in self._parsers:
                        if parser.can_parse(line):
                            detected = type(parser).__name__
                            break
                    break
        except Exception as exc:
            logger.warning("Cannot sniff %s: %s", path, exc)

        # Parse all lines with detected parser (fall back to syslog)
        chosen_parsers = self._parsers[:]
        try:
            with opener(path, mode, encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    entry = None
                    for parser in chosen_parsers:
                        try:
                            entry = parser.parse_line(line, str(path), lineno)
                            if entry:
                                break
                        except Exception:
                            pass
                    if entry:
                        entries.append(entry)
        except Exception as exc:
            logger.warning("Cannot parse %s: %s", path, exc)

        return entries, detected


# ──────────────────────────────────────────────────────────────────────────────
# PCAP reader (pure-Python struct-based, no scapy/dpkt)
# ──────────────────────────────────────────────────────────────────────────────

class PcapReader:
    """
    Pure-Python PCAP/PCAPNG reader.
    Supports Ethernet/IPv4/IPv6/TCP/UDP/ICMP/DNS/HTTP/TLS/ARP.
    Uses only stdlib struct — no external deps.
    """

    PCAP_MAGIC_LE = 0xA1B2C3D4
    PCAP_MAGIC_BE = 0xD4C3B2A1
    PCAPNG_MAGIC = 0x0A0D0D0A

    def __init__(self, path: Path):
        self.path = path
        self._endian = "<"
        self._snaplen = 65535
        self._link_type = 1   # Ethernet by default
        self._ts_resolution = 1_000_000  # microseconds by default

    def read(self) -> Generator[Dict, None, None]:
        """Yield parsed packet dicts — auto-detects PCAP vs PCAPNG format."""
        file_size = self.path.stat().st_size if self.path.exists() else 0
        if file_size < 24:
            logger.error("PCAP file too small (%d bytes): %s", file_size, self.path)
            return
        try:
            with open(self.path, "rb") as fh:
                raw4 = fh.read(4)
                if len(raw4) < 4:
                    logger.error("Cannot read PCAP magic from %s", self.path)
                    return
                magic_le = struct.unpack("<I", raw4)[0]
                magic_be = struct.unpack(">I", raw4)[0]
                fh.seek(0)

                # PCAPNG
                if magic_le == self.PCAPNG_MAGIC:
                    logger.info("Detected PCAPNG format")
                    yield from self._read_pcapng(fh)
                # Classic PCAP LE
                elif magic_le in (self.PCAP_MAGIC_LE, 0xA1B23C4D):
                    logger.info("Detected PCAP LE format (magic=0x%08X)", magic_le)
                    self._endian = "<"
                    yield from self._read_pcap(fh)
                # Classic PCAP BE
                elif magic_le in (self.PCAP_MAGIC_BE, 0x4D3CB2A1):
                    logger.info("Detected PCAP BE format (magic=0x%08X)", magic_le)
                    self._endian = ">"
                    yield from self._read_pcap(fh)
                else:
                    # Unknown magic — try LE first, then BE
                    logger.warning("Unknown PCAP magic 0x%08X in %s — trying LE format", magic_le, self.path)
                    packets_found = False
                    saved_pos = fh.tell()
                    try:
                        pkts = list(self._read_pcap(fh))
                        if pkts:
                            packets_found = True
                            yield from iter(pkts)
                    except Exception:
                        pass
                    if not packets_found:
                        logger.warning("LE failed, trying PCAPNG fallback")
                        fh.seek(0)
                        yield from self._read_pcapng(fh)
        except PermissionError:
            logger.error("Permission denied reading PCAP: %s", self.path)
        except FileNotFoundError:
            logger.error("PCAP file not found: %s", self.path)
        except Exception as exc:
            logger.error("PCAP read error %s: %s", self.path, exc)
            import traceback
            logger.debug(traceback.format_exc())

    # ── PCAP ──────────────────────────────────────────────────────────────────

    def _read_pcap(self, fh) -> Generator[Dict, None, None]:
        header = fh.read(24)
        if len(header) < 24:
            logger.error("PCAP global header too short (%d bytes, need 24) — file may be truncated or not a valid PCAP", len(header))
            return
        magic = struct.unpack("<I", header[:4])[0]

        # Detect endianness and timestamp resolution
        if magic == self.PCAP_MAGIC_BE:
            self._endian = ">"
        elif magic in (0xA1B23C4D,):   # nanosecond LE
            self._ts_resolution = 1_000_000_000
        elif magic == 0x4D3CB2A1:      # nanosecond BE
            self._endian = ">"
            self._ts_resolution = 1_000_000_000

        e = self._endian
        try:
            magic_val, ver_maj, ver_min, thiszone, sigfigs, snaplen, link_type = struct.unpack(f"{e}IHHiIII", header)
        except struct.error as exc:
            logger.error("PCAP global header unpack failed: %s — header bytes: %s", exc, header.hex())
            return

        self._snaplen = snaplen if snaplen > 0 else 65535
        self._link_type = link_type
        logger.info("PCAP: version=%d.%d snaplen=%d link_type=%d endian=%s", ver_maj, ver_min, snaplen, link_type, e)

        pkt_num = 0
        while True:
            rec = fh.read(16)
            if len(rec) == 0:
                break          # clean EOF
            if len(rec) < 16:
                logger.debug("PCAP: short record header at packet %d (%d bytes) — stopping", pkt_num, len(rec))
                break
            try:
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{e}IIII", rec)
            except struct.error:
                break

            # Sanity-check incl_len to avoid reading gigabytes on corrupt files
            if incl_len > 262144:
                logger.warning("PCAP: suspiciously large packet %d (%d bytes) — skipping", pkt_num, incl_len)
                fh.seek(incl_len, 1)
                continue

            data = fh.read(incl_len)
            if len(data) < incl_len:
                logger.debug("PCAP: truncated packet %d (%d/%d bytes) — parsing anyway", pkt_num, len(data), incl_len)
                # Parse what we have rather than discarding

            # Guard against ts_sec=0 or absurd timestamps
            try:
                if ts_sec == 0:
                    ts = datetime.utcnow()
                else:
                    ts = datetime.utcfromtimestamp(
                        ts_sec + ts_usec / self._ts_resolution
                    )
            except (OSError, ValueError, OverflowError):
                ts = datetime.now(tz=timezone.utc)

            pkt_num += 1
            if data:
                parsed = self._parse_packet(data, ts, pkt_num, orig_len)
                if parsed:
                    yield parsed

    # ── PCAPNG ────────────────────────────────────────────────────────────────

    def _read_pcapng(self, fh) -> Generator[Dict, None, None]:
        pkt_num = 0
        if_tsresol: Dict[int, int] = {}
        if_link_type: Dict[int, int] = {}
        current_iface = 0

        while True:
            block_hdr = fh.read(8)
            if len(block_hdr) < 8:
                break
            block_type, block_len = struct.unpack("<II", block_hdr)
            body_len = block_len - 12
            body = fh.read(body_len)
            fh.read(4)  # trailing block length

            if block_type == 0x0A0D0D0A:  # SHB
                pass
            elif block_type == 0x00000001:  # IDB
                if len(body) >= 4:
                    link_type = struct.unpack("<H", body[:2])[0]
                    if_link_type[current_iface] = link_type
                    if_tsresol[current_iface] = 1_000_000
                    # parse options for tsresol
                    opt_off = 8
                    while opt_off + 4 <= len(body):
                        opt_code, opt_len = struct.unpack("<HH", body[opt_off:opt_off+4])
                        opt_off += 4
                        if opt_code == 9 and opt_len >= 1:  # if_tsresol
                            resol_byte = body[opt_off]
                            if resol_byte & 0x80:
                                if_tsresol[current_iface] = 10 ** (resol_byte & 0x7F)
                            else:
                                if_tsresol[current_iface] = 2 ** (resol_byte & 0x7F)
                        opt_off += opt_len + (4 - opt_len % 4) % 4
                        if opt_code == 0:
                            break
                    current_iface += 1
            elif block_type == 0x00000006:  # EPB
                if len(body) < 20:
                    continue
                iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack("<IIIII", body[:20])
                ts_raw = (ts_high << 32) | ts_low
                resol = if_tsresol.get(iface_id, 1_000_000)
                ts = datetime.fromtimestamp(ts_raw / resol, tz=timezone.utc)
                link = if_link_type.get(iface_id, 1)
                pkt_data = body[20:20+cap_len]
                pkt_num += 1
                self._link_type = link
                parsed = self._parse_packet(pkt_data, ts, pkt_num, orig_len)
                if parsed:
                    yield parsed
            elif block_type == 0x00000002:  # OPB (obsolete)
                if len(body) < 12:
                    continue
                iface_id, drops, cap_len = struct.unpack("<HHI", body[:8])
                orig_len = struct.unpack("<I", body[8:12])[0]
                pkt_data = body[12:12+cap_len]
                pkt_num += 1
                parsed = self._parse_packet(pkt_data, datetime.now(tz=timezone.utc), pkt_num, orig_len)
                if parsed:
                    yield parsed

    # ── Layer parsing ─────────────────────────────────────────────────────────

    def _parse_packet(self, data: bytes, ts: datetime, num: int, orig_len: int) -> Optional[Dict]:
        pkt: Dict[str, Any] = {
            "num": num,
            "timestamp": ts,
            "orig_len": orig_len,
            "cap_len": len(data),
            "layers": [],
        }
        try:
            if self._link_type == 1:    # Ethernet (LINKTYPE_ETHERNET)
                self._parse_ethernet(data, pkt)
            elif self._link_type in (101, 228, 12, 14):
                # 101 = LINKTYPE_RAW   (raw IP, BSD)
                # 228 = LINKTYPE_IPV4  (raw IPv4, Linux)
                # 12  = LINKTYPE_RAW   (OpenBSD)
                # 14  = LINKTYPE_RAW   (FreeBSD)
                self._parse_ip(data, pkt)
            elif self._link_type == 113:  # LINKTYPE_LINUX_SLL (Linux cooked)
                if len(data) >= 16:
                    etype = struct.unpack(">H", data[14:16])[0]
                    if etype == 0x0800:
                        self._parse_ipv4(data[16:], pkt)
                    elif etype == 0x86DD:
                        self._parse_ipv6(data[16:], pkt)
            else:
                # Unknown link type — try raw IP as best-effort fallback
                pkt["raw"] = data[:64]
                if len(data) >= 20:
                    version = (data[0] >> 4)
                    if version in (4, 6):
                        self._parse_ip(data, pkt)
        except Exception as exc:
            logger.debug("Packet %d parse error: %s", num, exc)
        return pkt

    def _parse_ethernet(self, data: bytes, pkt: Dict):
        if len(data) < 14:
            return
        dst_mac = ":".join(f"{b:02x}" for b in data[:6])
        src_mac = ":".join(f"{b:02x}" for b in data[6:12])
        etype = struct.unpack(">H", data[12:14])[0]
        pkt["eth"] = {"dst": dst_mac, "src": src_mac, "type": etype}
        pkt["layers"].append("Ethernet")
        if etype == 0x0800:  # IPv4
            self._parse_ipv4(data[14:], pkt)
        elif etype == 0x86DD:  # IPv6
            self._parse_ipv6(data[14:], pkt)
        elif etype == 0x0806:  # ARP
            self._parse_arp(data[14:], pkt)
        elif etype == 0x8100:  # VLAN-tagged
            if len(data) >= 18:
                inner_etype = struct.unpack(">H", data[16:18])[0]
                if inner_etype == 0x0800:
                    self._parse_ipv4(data[18:], pkt)
                elif inner_etype == 0x86DD:
                    self._parse_ipv6(data[18:], pkt)

    def _parse_arp(self, data: bytes, pkt: Dict):
        if len(data) < 28:
            return
        op = struct.unpack(">H", data[6:8])[0]
        sha = ":".join(f"{b:02x}" for b in data[8:14])
        spa = socket.inet_ntoa(data[14:18])
        tha = ":".join(f"{b:02x}" for b in data[18:24])
        tpa = socket.inet_ntoa(data[24:28])
        pkt["arp"] = {"op": op, "sha": sha, "spa": spa, "tha": tha, "tpa": tpa}
        pkt["layers"].append("ARP")

    def _parse_ip(self, data: bytes, pkt: Dict):
        """Auto-detect IPv4 vs IPv6."""
        if not data:
            return
        version = (data[0] >> 4)
        if version == 4:
            self._parse_ipv4(data, pkt)
        elif version == 6:
            self._parse_ipv6(data, pkt)

    def _parse_ipv4(self, data: bytes, pkt: Dict):
        if len(data) < 20:
            return
        ver_ihl = data[0]
        ihl = (ver_ihl & 0x0F) * 4
        proto = data[9]
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])
        ttl = data[8]
        total_len = struct.unpack(">H", data[2:4])[0]
        pkt["ip"] = {"src": src_ip, "dst": dst_ip, "proto": proto, "ttl": ttl, "len": total_len}
        pkt["layers"].append("IPv4")
        payload = data[ihl:]
        self._parse_transport(proto, payload, pkt)

    def _parse_ipv6(self, data: bytes, pkt: Dict):
        if len(data) < 40:
            return
        next_hdr = data[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
        pkt["ip"] = {"src": src_ip, "dst": dst_ip, "proto": next_hdr, "ttl": data[7], "len": len(data)}
        pkt["layers"].append("IPv6")
        self._parse_transport(next_hdr, data[40:], pkt)

    def _parse_transport(self, proto: int, data: bytes, pkt: Dict):
        if proto == 6:    # TCP
            self._parse_tcp(data, pkt)
        elif proto == 17: # UDP
            self._parse_udp(data, pkt)
        elif proto == 1:  # ICMP
            self._parse_icmp(data, pkt)
        elif proto == 58: # ICMPv6
            self._parse_icmpv6(data, pkt)

    def _parse_tcp(self, data: bytes, pkt: Dict):
        if len(data) < 20:
            return
        sport, dport = struct.unpack(">HH", data[:4])
        seq, ack = struct.unpack(">II", data[4:12])
        off_flags = struct.unpack(">H", data[12:14])[0]
        data_off = ((off_flags >> 12) & 0xF) * 4
        flags_raw = off_flags & 0x1FF
        flags = []
        for bit, name in [(0x100,"NS"),(0x80,"CWR"),(0x40,"ECE"),(0x20,"URG"),
                          (0x10,"ACK"),(0x8,"PSH"),(0x4,"RST"),(0x2,"SYN"),(0x1,"FIN")]:
            if flags_raw & bit:
                flags.append(name)
        window = struct.unpack(">H", data[14:16])[0]
        payload = data[data_off:]
        pkt["tcp"] = {"sport": sport, "dport": dport, "seq": seq, "ack": ack,
                      "flags": flags, "window": window, "payload_len": len(payload)}
        pkt["layers"].append("TCP")
        # Application layer
        if payload:
            self._parse_app_tcp(sport, dport, payload, pkt)

    def _parse_udp(self, data: bytes, pkt: Dict):
        if len(data) < 8:
            return
        sport, dport, length = struct.unpack(">HHH", data[:6])
        payload = data[8:]
        pkt["udp"] = {"sport": sport, "dport": dport, "length": length}
        pkt["layers"].append("UDP")
        if dport == 53 or sport == 53:
            self._parse_dns(payload, pkt)
        elif dport in (67, 68):
            pkt["layers"].append("DHCP")

    def _parse_icmp(self, data: bytes, pkt: Dict):
        if len(data) < 4:
            return
        icmp_type, code = data[0], data[1]
        type_names = {0:"echo-reply",3:"dest-unreachable",8:"echo-request",11:"time-exceeded"}
        pkt["icmp"] = {"type": icmp_type, "code": code, "type_name": type_names.get(icmp_type,"?")}
        pkt["layers"].append("ICMP")

    def _parse_icmpv6(self, data: bytes, pkt: Dict):
        if len(data) < 4:
            return
        pkt["icmpv6"] = {"type": data[0], "code": data[1]}
        pkt["layers"].append("ICMPv6")

    def _parse_app_tcp(self, sport: int, dport: int, payload: bytes, pkt: Dict):
        """Detect and parse HTTP, TLS, Redis, SSH at application layer."""
        if dport in (80, 8080, 8000, 8888) or sport in (80, 8080):
            self._parse_http(payload, pkt)
        elif dport in (443, 8443) or sport in (443, 8443):
            self._parse_tls(payload, pkt)
        elif dport == 22 or sport == 22:
            pkt["ssh"] = {"banner": payload[:20].decode("utf-8","replace").strip() if payload.startswith(b"SSH") else None}
            pkt["layers"].append("SSH")
        elif dport == 6379 or sport == 6379:
            self._parse_redis(payload, pkt)
        # Try HTTP heuristic for non-standard ports
        elif payload[:4] in (b"GET ", b"POST", b"PUT ", b"DELE", b"HEAD", b"HTTP"):
            self._parse_http(payload, pkt)
        elif len(payload) >= 5 and payload[0] in (0x14,0x15,0x16,0x17):
            self._parse_tls(payload, pkt)

    def _parse_http(self, data: bytes, pkt: Dict):
        try:
            text = data.decode("utf-8", "replace")
        except Exception:
            return
        lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
        if not lines:
            return
        first = lines[0]
        http: Dict = {}
        if first.startswith(("GET ","POST ","PUT ","DELETE ","HEAD ","OPTIONS ","PATCH ")):
            parts = first.split(" ", 2)
            http["method"] = parts[0]
            http["uri"] = parts[1] if len(parts) > 1 else "/"
            http["version"] = parts[2].strip() if len(parts) > 2 else ""
            http["direction"] = "request"
            for hdr in lines[1:]:
                if hdr.lower().startswith("host:"):
                    http["host"] = hdr[5:].strip()
                elif hdr.lower().startswith("user-agent:"):
                    http["user_agent"] = hdr[11:].strip()
                elif hdr.lower().startswith("content-type:"):
                    http["content_type"] = hdr[13:].strip()
        elif first.startswith("HTTP/"):
            parts = first.split(" ", 2)
            http["version"] = parts[0]
            http["status"] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            http["reason"] = parts[2].strip() if len(parts) > 2 else ""
            http["direction"] = "response"
        if http:
            pkt["http"] = http
            pkt["layers"].append("HTTP")

    def _parse_tls(self, data: bytes, pkt: Dict):
        if len(data) < 5:
            return
        content_type = data[0]
        version_major, version_minor = data[1], data[2]
        tls: Dict = {"content_type": content_type, "version": f"{version_major}.{version_minor}"}
        # Client Hello SNI extraction
        if content_type == 0x16 and len(data) >= 43:  # Handshake
            htype = data[5]
            if htype == 0x01:  # ClientHello
                tls["handshake"] = "ClientHello"
                sni = self._extract_sni(data[5:])
                if sni:
                    tls["sni"] = sni
        type_names = {0x14:"ChangeCipherSpec",0x15:"Alert",0x16:"Handshake",0x17:"AppData"}
        tls["type_name"] = type_names.get(content_type, "Unknown")
        pkt["tls"] = tls
        pkt["layers"].append("TLS")

    def _extract_sni(self, data: bytes) -> Optional[str]:
        """Walk TLS ClientHello extensions to find SNI."""
        try:
            if len(data) < 38:
                return None
            pos = 1 + 3  # htype + length (3 bytes)
            pos += 2 + 32 + 1  # version + random + session_id_len
            if pos >= len(data):
                return None
            session_id_len = data[3 + 2 + 32]
            pos += session_id_len
            pos += 1
            if pos + 2 > len(data):
                return None
            cipher_len = struct.unpack(">H", data[pos:pos+2])[0]
            pos += 2 + cipher_len + 1 + struct.unpack("B", data[pos+2+cipher_len:pos+3+cipher_len])[0]
            pos += 1
            if pos + 2 > len(data):
                return None
            ext_len = struct.unpack(">H", data[pos:pos+2])[0]
            pos += 2
            end = pos + ext_len
            while pos + 4 <= end:
                ext_type = struct.unpack(">H", data[pos:pos+2])[0]
                ext_data_len = struct.unpack(">H", data[pos+2:pos+4])[0]
                pos += 4
                if ext_type == 0:  # SNI
                    if pos + 5 <= end:
                        name_len = struct.unpack(">H", data[pos+3:pos+5])[0]
                        return data[pos+5:pos+5+name_len].decode("ascii","replace")
                pos += ext_data_len
        except Exception:
            pass
        return None

    def _parse_dns(self, data: bytes, pkt: Dict):
        if len(data) < 12:
            return
        txid = struct.unpack(">H", data[:2])[0]
        flags = struct.unpack(">H", data[2:4])[0]
        qr = (flags >> 15) & 1
        qdcount = struct.unpack(">H", data[4:6])[0]
        ancount = struct.unpack(">H", data[6:8])[0]
        dns: Dict = {"txid": txid, "qr": "response" if qr else "query",
                     "questions": [], "answers": []}
        pos = 12
        for _ in range(qdcount):
            name, pos = self._dns_read_name(data, pos)
            if pos + 4 > len(data):
                break
            qtype, qclass = struct.unpack(">HH", data[pos:pos+4])
            pos += 4
            dns["questions"].append({"name": name, "type": self._dns_type(qtype), "class": qclass})
        for _ in range(ancount):
            name, pos = self._dns_read_name(data, pos)
            if pos + 10 > len(data):
                break
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[pos:pos+10])
            pos += 10
            rdata = data[pos:pos+rdlen]
            pos += rdlen
            ans: Dict = {"name": name, "type": self._dns_type(rtype), "ttl": ttl}
            if rtype == 1 and rdlen == 4:
                ans["rdata"] = socket.inet_ntoa(rdata)
            elif rtype == 28 and rdlen == 16:
                ans["rdata"] = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype in (2, 5, 12):
                ans["rdata"], _ = self._dns_read_name(data, pos - rdlen)
            else:
                ans["rdata"] = rdata.hex()
            dns["answers"].append(ans)
        pkt["dns"] = dns
        pkt["layers"].append("DNS")

    def _dns_read_name(self, data: bytes, pos: int) -> Tuple[str, int]:
        labels = []
        visited = set()
        while pos < len(data):
            length = data[pos]
            if length == 0:
                pos += 1
                break
            if (length & 0xC0) == 0xC0:  # pointer
                if pos + 2 > len(data):
                    break
                ptr = struct.unpack(">H", data[pos:pos+2])[0] & 0x3FFF
                if ptr in visited:
                    break
                visited.add(ptr)
                label, _ = self._dns_read_name(data, ptr)
                labels.append(label)
                pos += 2
                break
            pos += 1
            labels.append(data[pos:pos+length].decode("ascii","replace"))
            pos += length
        return ".".join(labels), pos

    @staticmethod
    def _dns_type(t: int) -> str:
        return {1:"A",2:"NS",5:"CNAME",6:"SOA",12:"PTR",15:"MX",
                16:"TXT",28:"AAAA",33:"SRV",255:"ANY"}.get(t, str(t))

    def _parse_redis(self, data: bytes, pkt: Dict):
        try:
            text = data.decode("utf-8","replace")
            pkt["redis"] = {"raw": text[:200]}
            pkt["layers"].append("Redis")
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────────────────────
# Threat detection engine
# ──────────────────────────────────────────────────────────────────────────────

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

SUSPICIOUS_PORTS = {
    4444: "Metasploit default",
    1337: "Elite hacker port",
    31337: "Back Orifice",
    12345: "NetBus",
    6667: "IRC C2",
    6697: "IRC C2 TLS",
    8080: "HTTP proxy/C2",
    9999: "Common C2",
    3389: "RDP",
    5900: "VNC",
    23: "Telnet",
    21: "FTP",
    2323: "Telnet alternate",
}

KNOWN_THREAT_IPS: Set[str] = {
    # Commonly seen in threat intel feeds - placeholder set
    "0.0.0.0",
}


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_RANGES)
    except ValueError:
        return False


def _infer_level(msg: str) -> str:
    msg_lower = msg.lower()
    if any(w in msg_lower for w in ("critical","crit","emergency","emerg","panic")):
        return "critical"
    if any(w in msg_lower for w in ("error","err","failed","failure","denied","refused")):
        return "error"
    if any(w in msg_lower for w in ("warning","warn","invalid","suspicious")):
        return "warning"
    return "info"


class ThreatDetectionEngine:
    """
    Rule-based threat detection engine with 30+ MITRE ATT&CK aligned rules.
    Each rule returns a ThreatEvent or None.
    """

    def __init__(self, config: Dict = None, custom_rules: List[Dict] = None):
        self.config = config or {}
        self.custom_rules = custom_rules or []
        self._brute_force_window = self.config.get("brute_force_window", 300)  # seconds
        self._brute_force_threshold = self.config.get("brute_force_threshold", 5)
        self._port_scan_threshold = self.config.get("port_scan_threshold", 15)
        self._beacon_threshold = self.config.get("beacon_threshold", 10)

    # ── Log-based detections ──────────────────────────────────────────────────

    def analyze_logs(self, entries: List[LogEntry]) -> List[ThreatEvent]:
        events: List[ThreatEvent] = []
        events.extend(self._detect_brute_force(entries))
        events.extend(self._detect_privilege_escalation(entries))
        events.extend(self._detect_sudo_abuse(entries))
        events.extend(self._detect_account_manipulation(entries))
        events.extend(self._detect_suspicious_cron(entries))
        events.extend(self._detect_kernel_module_load(entries))
        events.extend(self._detect_ssh_anomalies(entries))
        events.extend(self._detect_log_clearing(entries))
        events.extend(self._detect_segfaults(entries))
        events.extend(self._detect_oom_killer(entries))
        events.extend(self._detect_dns_anomalies_log(entries))
        events.extend(self._detect_service_failures(entries))
        events.extend(self._detect_package_anomalies(entries))
        events.extend(self._detect_web_attacks(entries))
        events.extend(self._apply_custom_rules(entries))
        return events

    def _detect_brute_force(self, entries: List[LogEntry]) -> List[ThreatEvent]:
        """SSH/login brute force detection with sliding window."""
        events = []
        fail_patterns = [
            re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)", re.I),
            re.compile(r"authentication failure.*rhost=(\S+)", re.I),
            re.compile(r"Invalid user (\S+) from (\S+)", re.I),
        ]
        # Group failures by IP
        ip_failures: Dict[str, List[Tuple[datetime, LogEntry]]] = defaultdict(list)
        for entry in entries:
            for pat in fail_patterns:
                m = pat.search(entry.message)
                if m and entry.timestamp:
                    ip = m.group(2) if m.lastindex >= 2 else m.group(1)
                    ip = entry.extra.get("remote_ip", ip)
                    ip_failures[ip].append((entry.timestamp, entry))
                    break

        for ip, failures in ip_failures.items():
            if len(failures) < self._brute_force_threshold:
                continue
            # Check if they occur within the window
            for i in range(len(failures) - self._brute_force_threshold + 1):
                window = failures[i:i + self._brute_force_threshold]
                t0, t1 = window[0][0], window[-1][0]
                t0n = _normalize_dt(t0) or datetime.utcnow()
                t1n = _normalize_dt(t1) or datetime.utcnow()
                span = (t1n - t0n).total_seconds()
                if span <= self._brute_force_window:
                    events.append(ThreatEvent(
                        rule_id="T1110.001",
                        name="SSH Brute Force Attack",
                        description=f"IP {ip} generated {len(failures)} failed auth attempts",
                        severity="high",
                        mitre_tactic="Credential Access",
                        mitre_technique="T1110.001 — Brute Force: Password Guessing",
                        timestamp=window[0][0],
                        source_ip=ip,
                        dest_ip=None,
                        source_port=None,
                        dest_port=22,
                        host=window[0][1].host,
                        process=window[0][1].process,
                        evidence=[f"{len(failures)} failed logins in {span:.0f}s",
                                  f"Last attempt: {window[-1][0]}"],
                        tags=["brute-force","credential-access","ssh"],
                        raw_entries=[e.raw for _, e in window[:5]],
                    ))
                    break
        return events

    def _detect_privilege_escalation(self, entries: List[LogEntry]) -> List[ThreatEvent]:
        events = []
        patterns = [
            re.compile(r"su(?:do)?: \S+ : TTY=\S+ ; PWD=\S+ ; USER=root", re.I),
            re.compile(r"COMMAND=.*(?:chmod 777|chmod a\+s|chown root)", re.I),
            re.compile(r"pam_unix.*root.*su", re.I),
        ]
        for entry in entries:
            for pat in patterns:
                if pat.search(entry.message):
                    events.append(ThreatEvent(
                        rule_id="T1548.003",
                        name="Privilege Escalation Detected",
                        description="Suspicious privilege escalation attempt",
                        severity="high",
                        mitre_tactic="Privilege Escalation",
                        mitre_technique="T1548.003 — Abuse Elevation Control Mechanism: Sudo",
                        timestamp=entry.timestamp,
                        source_ip=entry.extra.get("remote_ip"),
                        dest_ip=None,
                        source_port=None,
                        dest_port=None,
                        host=entry.host,
                        process=entry.process,
                        evidence=[entry.message],
                        tags=["privesc","sudo","lateral-movement"],
                        raw_entries=[entry.raw],
                    ))
                    break
        return events

    def _detect_sudo_abuse(self, entries: List[LogEntry]) -> List[ThreatEvent]:
        events = []
        dangerous = re.compile(
            r"COMMAND=(?:.*(?:nc\s+-[leLe]|ncat|netcat|curl\s+-[oO]|wget\s+-[qO])\b|"
            r"/bin/bash\s+-i|/bin/sh\s+-i|chmod\s+[0-9]*[7][0-9]*\s+/)", re.I)
        for entry in entries:
            if "sudo" in entry.process.lower() and dangerous.search(entry.message):
                events.append(ThreatEvent(
                    rule_id="T1548.003-A",
                    name="Suspicious Sudo Command",
                    description="Potentially dangerous command executed via sudo",
                    severity="medium",
                    mitre_tactic="Privilege Escalation",
                    mitre_technique="T1548.003 — Sudo",
                    timestamp=entry.timestamp,
                    source_ip=None,
                    dest_ip=None,
                    source_port=None,
                    dest_port=None,
                    host=entry.host,
                    process=entry.process,
                    evidence=[entry.message],
                    tags=["sudo","privesc","execution"],
                    raw_entries=[entry.raw],
                ))
        return events

    def _detect_account_manipulation(self, entries: List[LogEntry]) -> List[ThreatEvent]:
        events = []
        patterns = [
            (re.compile(r"useradd|adduser|userdel|usermod", re.I), "Account Created/Modified"),
            (re.compile(r"passwd.*changed|chpasswd", re.I), "Password Changed"),
            (re.compile(r"visudo|sudoers", re.I), "Sudoers Modified"),
        ]
        for entry in entries:
            for pat, desc in patterns:
                if pat.search(entry.message):
                    events.append(ThreatEvent(
                        rule_id="T1136",
                        name=f"Account Manipulation: {desc}",
                        description=f"System account change detected: {desc}",
                        severity="medium",
                        mitre_tactic="Persistence",
                        mitre_technique="T1136 — Create Account",
                        timestamp=entry.timestamp,
                        source_ip=None,
                        dest_ip=None,
                        source_port=None,
                        dest_port=None,
                        host=entry.host,
                        process=entry.process,
                        evidence=[entry.message],
                        tags=["persistence","account","lateral-movement"],
                        raw_entries=[entry.raw],
                    ))
                    break
        return events

    def _detect_suspicious_cron(self, entries: List[LogEntry]) -> List[ThreatEvent]:
        events = []
        cron_pat = re.compile(r"^(cron|atd|anacron|crond)$", re.I)
        # Only flag truly suspicious patterns, not normal PHP session cleanup
        suspicious = re.compile(
            r"(?:wget\s|curl\s+-[oO]|nc\s+-[leLe]|/tmp/[a-zA-Z0-9]{6,}|"
            r"/dev/shm/|base64\s+-d|python\s+-c|perl\s+-e|bash\s+-i|"
            r">\s*/dev/null.*&\s*$|\|\s*bash|\|\s*sh)", re.I)
        # Whitelist known-safe cron patterns
        safe_cron = re.compile(
            r"(?:sessionclean|run-parts|anacron|logrotate|updatedb|"
            r"man-db\.cron|dpkg|apt\.daily|apt-compat|certbot|"
            r"unattended-upgrade|mlocate|sysstat|popularity-contest)", re.I)
        for entry in entries:
            if cron_pat.search(entry.process) and suspicious.search(entry.message):
                if safe_cron.search(entry.message):
                    continue  # Skip known-safe cron jobs
                events.append(ThreatEvent(
                    rule_id="T1053.003",
                    name="Suspicious Cron Job",
                    description="Potentially malicious scheduled task detected",
                    severity="high",
                    mitre_tactic="Persistence",
                    mitre_technique="T1053.003 — Scheduled Task/Job: Cron",
                    timestamp=entry.timestamp,
                    source_ip=None,
                    dest_ip=None,
                    source_port=None,
                    dest_port=None,
                    host=entry.host,
                    process=entry.process,
                    evidence=[entry.message],
                    tags=["persistence","cron","execution"],
                    raw_entries=[entry.raw],
                ))
        return events

    def _detect_kernel_module_load(self, entries: List[LogEntry]) -> List[ThreatEvent]:
        events = []
        kmod_pat = re.compile(r"(?:insmod|modprobe|rmmod|module)", re.I)
        for entry in entries:
            if entry.process in ("kernel", "kmod") or kmod_pat.search(entry.message):
                if any(w in entry.message.lower() for w in ("loaded","insmod","modprobe")):
                    events.append(ThreatEvent(
                        rule_id="T1547.006",
                        name="Kernel Module Loaded",
                        description="Kernel module load event — possible rootkit",
                        severity="medium",
                        mitre_tactic="Persistence",
                        mitre_technique="T1547.006 — Boot or Logon Autostart: Kernel Modules",
                        timestamp=entry.timestamp,
                        source_ip=None,
                        dest_ip=None,
                        source_port=None,
                        dest_port=None,
                        host=entry.host,
                        process=entry.process,
                        evidence=[entry.message],
                        tags=["persistence","kernel","rootkit"],
                        raw_entries=[entry.raw],
                    ))
        return events

    def _detect_ssh_anomalies(self, entries: List[LogEntry]) -> List[ThreatEvent]:
        events = []
        anon_user_pat = re.compile(r"Invalid user (\S+) from (\S+)", re.I)
        for entry in entries:
            m = anon_user_pat.search(entry.message)
            if m:
                events.append(ThreatEvent(
                    rule_id="T1078",
                    name="SSH Invalid User Attempt",
                    description=f"SSH login attempt with invalid user '{m.group(1)}' from {m.group(2)}",
                    severity="low",
                    mitre_tactic="Initial Access",
                    mitre_technique="T1078 — Valid Accounts",
                    timestamp=entry.timestamp,
                    source_ip=m.group(2),
                    dest_ip=None,
                    source_port=None,
                    dest_port=22,
                    host=entry.host,
                    process=entry.process,
                    evidence=[entry.message],
                    tags=["initial-access","ssh","reconnaissance"],
                    raw_entries=[entry.raw],
                ))
        return events

    def _detect_log_clearing(self, entries: List[LogEntry]) -> List[ThreatEvent]:
        events = []
        patterns = re.compile(r"(?:rm\s+-rf\s+/var/log|shred\s+/var/log|>\s*/var/log/|journalctl\s+--rotate.*--vacuum|auditctl\s+-D\b)", re.I)
        for entry in entries:
            if patterns.search(entry.message):
                events.append(ThreatEvent(
                    rule_id="T1070",
                    name="Log Tampering / Indicator Removal",
                    description="Possible log clearing or tamper attempt",
                    severity="high",
                    mitre_tactic="Defense Evasion",
                    mitre_technique="T1070 — Indicator Removal on Host",
                    timestamp=entry.timestamp,
                    source_ip=None,
                    dest_ip=None,
                    source_port=None,
                    dest_port=None,
                    host=entry.host,
                    process=entry.process,
                    evidence=[entry.message],
                    tags=["defense-evasion","log-clearing"],
                    raw_entries=[entry.raw],
                ))
        return events

    def _detect_segfaults(self, entries: List[LogEntry]) -> List[ThreatEvent]:
        events = []
        seg_pat = re.compile(r"segfault|sigsegv|segmentation fault", re.I)
        for entry in entries:
            if seg_pat.search(entry.message):
                events.append(ThreatEvent(
                    rule_id="T1203",
                    name="Application Crash / Segfault",
                    description="Segfault may indicate exploitation attempt",
                    severity="low",
                    mitre_tactic="Execution",
                    mitre_technique="T1203 — Exploitation for Client Execution",
                    timestamp=entry.timestamp,
                    source_ip=None,
                    dest_ip=None,
                    source_port=None,
                    dest_port=None,
                    host=entry.host,
                    process=entry.process,
                    evidence=[entry.message],
                    tags=["exploitation","crash","memory"],
                    raw_entries=[entry.raw],
                ))
        return events

    def _detect_oom_killer(self, entries: List[LogEntry]) -> List[ThreatEvent]:
        events = []
        oom_pat = re.compile(r"Out of memory|oom.kill|oom_kill_process", re.I)
        for entry in entries:
            if oom_pat.search(entry.message):
                events.append(ThreatEvent(
                    rule_id="T1499",
                    name="OOM Killer Triggered",
                    description="Out-of-memory condition — possible DoS or resource exhaustion",
                    severity="medium",
                    mitre_tactic="Impact",
                    mitre_technique="T1499 — Endpoint Denial of Service",
                    timestamp=entry.timestamp,
                    source_ip=None,
                    dest_ip=None,
                    source_port=None,
                    dest_port=None,
                    host=entry.host,
                    process=entry.process,
                    evidence=[entry.message],
                    tags=["impact","dos","resource-exhaustion"],
                    raw_entries=[entry.raw],
                ))
        return events

    def _detect_dns_anomalies_log(self, entries: List[LogEntry]) -> List[ThreatEvent]:
        events = []
        dga_pat = re.compile(r"[a-z0-9]{20,}\.(com|net|org|io|xyz|top|pw)", re.I)
        for entry in entries:
            if dga_pat.search(entry.message) and "dns" in entry.message.lower():
                events.append(ThreatEvent(
                    rule_id="T1568",
                    name="Potential DGA Domain",
                    description="Randomly-generated domain pattern detected (possible C2)",
                    severity="medium",
                    mitre_tactic="Command and Control",
                    mitre_technique="T1568 — Dynamic Resolution",
                    timestamp=entry.timestamp,
                    source_ip=None,
                    dest_ip=None,
                    source_port=None,
                    dest_port=53,
                    host=entry.host,
                    process=entry.process,
                    evidence=[entry.message],
                    tags=["c2","dns","dga"],
                    raw_entries=[entry.raw],
                ))
        return events

    def _detect_service_failures(self, entries: List[LogEntry]) -> List[ThreatEvent]:
        events = []
        fail_pat = re.compile(r"(?:failed|FAILED|core dumped|terminated|killed|crashed)", re.I)
        critical_services = {"sshd","firewalld","auditd","rsyslogd","crond","systemd"}
        for entry in entries:
            if fail_pat.search(entry.message) and entry.process.lower() in critical_services:
                events.append(ThreatEvent(
                    rule_id="T1489",
                    name=f"Critical Service Failure: {entry.process}",
                    description=f"Security-relevant service {entry.process} failed",
                    severity="medium",
                    mitre_tactic="Impact",
                    mitre_technique="T1489 — Service Stop",
                    timestamp=entry.timestamp,
                    source_ip=None,
                    dest_ip=None,
                    source_port=None,
                    dest_port=None,
                    host=entry.host,
                    process=entry.process,
                    evidence=[entry.message],
                    tags=["impact","service-failure","availability"],
                    raw_entries=[entry.raw],
                ))
        return events

    def _detect_package_anomalies(self, entries: List[LogEntry]) -> List[ThreatEvent]:
        events = []
        for entry in entries:
            if entry.process == "dpkg":
                action = entry.extra.get("action", "")
                pkg = entry.extra.get("package", "")
                suspicious_pkgs = {"netcat","ncat","nmap","masscan","hydra","john","hashcat",
                                   "aircrack-ng","metasploit","beef","exploit"}
                if any(s in pkg.lower() for s in suspicious_pkgs):
                    events.append(ThreatEvent(
                        rule_id="T1072",
                        name=f"Suspicious Package Installed: {pkg}",
                        description=f"Security tool package '{pkg}' was {action}",
                        severity="medium",
                        mitre_tactic="Lateral Movement",
                        mitre_technique="T1072 — Software Deployment Tools",
                        timestamp=entry.timestamp,
                        source_ip=None,
                        dest_ip=None,
                        source_port=None,
                        dest_port=None,
                        host=entry.host,
                        process=entry.process,
                        evidence=[entry.message],
                        tags=["lateral-movement","package","tool-installation"],
                        raw_entries=[entry.raw],
                    ))
        return events

    def _detect_web_attacks(self, entries: List[LogEntry]) -> List[ThreatEvent]:
        """Detect web attacks ONLY in HTTP access log entries (Apache/Nginx parsed)."""
        events = []
        sqli      = re.compile(r"(?:union\s+select|UNION\s+ALL\s+SELECT|or\s+1=1|%27.*union|xp_cmdshell|information_schema\.tables)", re.I)
        xss       = re.compile(r"(?:<script[\s/>]|javascript:|onerror\s*=|alert\s*\(|%3Cscript|onload\s*=)", re.I)
        cmd_inj   = re.compile(r"(?:;id;|;ls\s|;whoami|;cat\s/etc/|&&id␈|\|\|id␈|\$\(id\))", re.I)
        lfi       = re.compile(r"(?:\.\.%2[fF]|%2e%2e/|/etc/passwd|/proc/self/|php://(?:input|filter))", re.I)
        log4shell = re.compile(r"\$\{jndi:", re.I)
        scanner   = re.compile(r"(?:sqlmap|nikto|Nmap Scripting Engine|masscan|dirbuster|gobuster|wfuzz|acunetix)", re.I)
        path_trav = re.compile(r"(?:\.\./\.\./\.\./|\.\.[/\\]\.\.[/\\]\.\.)", re.I)

        for entry in entries:
            # CRITICAL: only fire on web server log entries — must have "uri" in extra
            # This prevents syslog/journal entries from matching
            if "uri" not in entry.extra:
                continue

            uri = entry.extra.get("uri", "")
            ua  = entry.extra.get("user_agent", "")
            method = entry.extra.get("method", "GET")
            search_str = uri + " " + ua

            for pat, name, rule_id, tactic, technique, severity in [
                (sqli,      "SQL Injection",              "T1190-SQLi",  "Initial Access", "T1190 — Exploit Public-Facing App",    "critical"),
                (xss,       "Cross-Site Scripting (XSS)", "T1059.007",   "Execution",      "T1059.007 — Client-Side Script",       "high"),
                (cmd_inj,   "Command Injection",          "T1059",       "Execution",      "T1059 — Command/Script Interpreter",   "critical"),
                (lfi,       "Local File Inclusion (LFI)", "T1083",       "Discovery",      "T1083 — File and Directory Discovery", "high"),
                (log4shell, "Log4Shell (CVE-2021-44228)", "T1190-L4J",   "Initial Access", "T1190 — Log4Shell RCE",               "critical"),
                (scanner,   "Security Scanner Detected",  "T1595",       "Reconnaissance", "T1595.002 — Vulnerability Scanning",   "medium"),
                (path_trav, "Path Traversal",             "T1083-PT",    "Discovery",      "T1083 — Path Traversal",               "high"),
            ]:
                if pat.search(search_str):
                    src_ip = entry.extra.get("ip") or entry.host
                    events.append(ThreatEvent(
                        rule_id=rule_id,
                        name=name,
                        description=f"HTTP web attack: {name} from {src_ip}",
                        severity=severity,
                        mitre_tactic=tactic,
                        mitre_technique=technique,
                        timestamp=entry.timestamp,
                        source_ip=src_ip,
                        dest_ip=None,
                        source_port=None,
                        dest_port=80,
                        host=entry.host,
                        process=entry.process,
                        evidence=[f"{method} {uri[:250]}"],
                        tags=["web-attack", "initial-access", rule_id.lower()],
                        raw_entries=[entry.raw],
                    ))
                    break
        return events
    def _apply_custom_rules(self, entries: List[LogEntry]) -> List[ThreatEvent]:
        events = []
        for rule in self.custom_rules:
            try:
                pat = re.compile(rule.get("pattern", ""), re.I)
                for entry in entries:
                    if pat.search(entry.message):
                        events.append(ThreatEvent(
                            rule_id=rule.get("id", "CUSTOM-001"),
                            name=rule.get("name", "Custom Rule Match"),
                            description=rule.get("description", "Custom detection rule triggered"),
                            severity=rule.get("severity", "medium"),
                            mitre_tactic=rule.get("mitre_tactic", "Unknown"),
                            mitre_technique=rule.get("mitre_technique", "Unknown"),
                            timestamp=entry.timestamp,
                            source_ip=None,
                            dest_ip=None,
                            source_port=None,
                            dest_port=None,
                            host=entry.host,
                            process=entry.process,
                            evidence=[entry.message],
                            tags=rule.get("tags", ["custom"]),
                            raw_entries=[entry.raw],
                        ))
            except Exception as exc:
                logger.warning("Custom rule error: %s", exc)
        return events

    # ── PCAP-based detections ─────────────────────────────────────────────────

    def analyze_pcap(self, packets: List[Dict]) -> Tuple[PcapSummary, List[ThreatEvent]]:
        summary = PcapSummary()
        events: List[ThreatEvent] = []

        if not packets:
            return summary, events

        # Basic stats
        summary.total_packets = len(packets)
        summary.total_bytes = sum(p.get("orig_len", 0) for p in packets)

        timestamps = [p["timestamp"] for p in packets if p.get("timestamp")]
        if len(timestamps) >= 2:
            t0 = _normalize_dt(min(timestamps)) or datetime.utcnow()
            t1 = _normalize_dt(max(timestamps)) or datetime.utcnow()
            summary.duration_seconds = (t1 - t0).total_seconds()

        # Protocol distribution
        proto_counts: Counter = Counter()
        for pkt in packets:
            for layer in pkt.get("layers", []):
                proto_counts[layer] += 1
        summary.protocols = dict(proto_counts.most_common(20))

        # IP traffic accounting
        ip_byte_count: Dict[str, int] = defaultdict(int)
        for pkt in packets:
            ip = pkt.get("ip", {})
            src = ip.get("src", "")
            if src:
                ip_byte_count[src] += pkt.get("orig_len", 0)
        summary.top_talkers = sorted(ip_byte_count.items(), key=lambda x: x[1], reverse=True)[:20]

        # ARP table
        for pkt in packets:
            arp = pkt.get("arp", {})
            if arp.get("spa") and arp.get("sha"):
                summary.arp_table[arp["spa"]] = arp["sha"]

        # DNS
        for pkt in packets:
            dns = pkt.get("dns", {})
            if dns:
                for q in dns.get("questions", []):
                    summary.dns_queries.append({
                        "name": q.get("name", ""),
                        "type": q.get("type", ""),
                        "timestamp": pkt["timestamp"].isoformat() if pkt.get("timestamp") else None,
                        "src": pkt.get("ip", {}).get("src", ""),
                    })

        # HTTP
        for pkt in packets:
            http = pkt.get("http", {})
            if http.get("direction") == "request":
                summary.http_transactions.append({
                    "method": http.get("method", ""),
                    "uri": http.get("uri", ""),
                    "host": http.get("host", ""),
                    "src": pkt.get("ip", {}).get("src", ""),
                    "timestamp": pkt["timestamp"].isoformat() if pkt.get("timestamp") else None,
                })

        # TLS sessions
        tls_sessions: Dict[Tuple, Dict] = {}
        for pkt in packets:
            tls = pkt.get("tls", {})
            ip = pkt.get("ip", {})
            tcp = pkt.get("tcp", {})
            if tls and ip:
                key = (ip.get("src",""), ip.get("dst",""), tcp.get("dport",0))
                if key not in tls_sessions:
                    tls_sessions[key] = {
                        "src": ip.get("src",""),
                        "dst": ip.get("dst",""),
                        "port": tcp.get("dport",0),
                        "sni": tls.get("sni",""),
                        "version": tls.get("version",""),
                    }
        summary.tls_sessions = list(tls_sessions.values())

        # Flow reconstruction
        flows: Dict[Tuple, NetworkFlow] = {}
        for pkt in packets:
            ip = pkt.get("ip", {})
            tcp = pkt.get("tcp", {})
            udp = pkt.get("udp", {})
            if not ip:
                continue
            src_ip = ip.get("src", "")
            dst_ip = ip.get("dst", "")
            proto_num = ip.get("proto", 0)

            if tcp:
                proto_str = "TCP"
                sport, dport = tcp.get("sport", 0), tcp.get("dport", 0)
            elif udp:
                proto_str = "UDP"
                sport, dport = udp.get("sport", 0), udp.get("dport", 0)
            else:
                proto_str = "ICMP" if proto_num == 1 else str(proto_num)
                sport, dport = 0, 0

            key = (proto_str, src_ip, sport, dst_ip, dport)
            if key not in flows:
                flows[key] = NetworkFlow(
                    proto=proto_str, src_ip=src_ip, src_port=sport,
                    dst_ip=dst_ip, dst_port=dport, packets=0, bytes_total=0,
                    first_seen=pkt.get("timestamp"), last_seen=pkt.get("timestamp"),
                )
            f = flows[key]
            f.packets += 1
            f.bytes_total += pkt.get("orig_len", 0)
            if pkt.get("timestamp"):
                if f.first_seen is None or pkt["timestamp"] < f.first_seen:
                    f.first_seen = pkt["timestamp"]
                if f.last_seen is None or pkt["timestamp"] > f.last_seen:
                    f.last_seen = pkt["timestamp"]
            if tcp:
                for flag in tcp.get("flags", []):
                    f.flags.add(flag)
            http = pkt.get("http", {})
            if http.get("direction") == "request":
                f.http_method = http.get("method")
                f.http_uri = http.get("uri")
                f.http_host = http.get("host")
            tls = pkt.get("tls", {})
            if tls.get("sni"):
                f.tls_sni = tls["sni"]
            service = _port_to_service(dport)
            if service:
                f.service = service

        summary.flows = list(flows.values())

        # Threat detections on PCAP
        events.extend(self._detect_port_scan(flows, summary))
        events.extend(self._detect_beaconing(flows, packets))
        events.extend(self._detect_dns_tunneling(summary))
        events.extend(self._detect_suspicious_flows(flows, summary))
        events.extend(self._detect_arp_poisoning(packets, summary))
        events.extend(self._detect_c2_indicators(flows, summary))
        events.extend(self._detect_http_attacks_pcap(packets))

        return summary, events

    def _detect_port_scan(self, flows: Dict, summary: PcapSummary) -> List[ThreatEvent]:
        events = []
        # Group flows by source IP → count unique dst ports
        src_dst_ports: Dict[str, Set[int]] = defaultdict(set)
        for (proto, src_ip, sport, dst_ip, dport), _ in flows.items():
            if proto == "TCP":
                src_dst_ports[src_ip].add(dport)
        for src_ip, ports in src_dst_ports.items():
            if len(ports) >= self._port_scan_threshold:
                summary.port_scan_candidates.append(src_ip)
                summary.suspicious_ips.add(src_ip)
                events.append(ThreatEvent(
                    rule_id="T1046",
                    name="Port Scan Detected",
                    description=f"{src_ip} scanned {len(ports)} unique TCP ports",
                    severity="medium",
                    mitre_tactic="Discovery",
                    mitre_technique="T1046 — Network Service Discovery",
                    timestamp=None,
                    source_ip=src_ip,
                    dest_ip=None,
                    source_port=None,
                    dest_port=None,
                    host="network",
                    process="pcap",
                    evidence=[f"Ports: {sorted(ports)[:30]}"],
                    tags=["reconnaissance","port-scan","discovery"],
                    raw_entries=[],
                ))
        return events

    def _detect_beaconing(self, flows: Dict, packets: List[Dict]) -> List[ThreatEvent]:
        """Detect C2 beaconing via inter-packet interval regularity."""
        events = []
        flow_times: Dict[Tuple, List[datetime]] = defaultdict(list)
        for pkt in packets:
            ip = pkt.get("ip", {})
            tcp = pkt.get("tcp", {})
            if ip and tcp and pkt.get("timestamp"):
                key = (ip.get("src",""), ip.get("dst",""), tcp.get("dport",0))
                flow_times[key].append(pkt["timestamp"])

        for key, times in flow_times.items():
            if len(times) < self._beacon_threshold:
                continue
            times_sorted = sorted(times)
            # ensure all naive for subtraction
            times_sorted = [_normalize_dt(t) or datetime.utcnow() for t in times_sorted]
            intervals = [(times_sorted[i+1] - times_sorted[i]).total_seconds()
                         for i in range(len(times_sorted)-1)]
            if not intervals:
                continue
            mean_iv = statistics.mean(intervals)
            if mean_iv < 1:
                continue
            stdev_iv = statistics.stdev(intervals) if len(intervals) > 1 else 0
            cv = stdev_iv / mean_iv if mean_iv > 0 else 1
            if cv < 0.15 and mean_iv < 300:  # very regular intervals < 5 min
                src, dst, dport = key
                events.append(ThreatEvent(
                    rule_id="T1071.001",
                    name="C2 Beaconing Pattern",
                    description=f"{src} → {dst}:{dport} — regular {mean_iv:.1f}s intervals (CV={cv:.3f})",
                    severity="high",
                    mitre_tactic="Command and Control",
                    mitre_technique="T1071.001 — Application Layer Protocol: Web Protocols",
                    timestamp=times_sorted[0],
                    source_ip=src,
                    dest_ip=dst,
                    source_port=None,
                    dest_port=dport,
                    host="network",
                    process="pcap",
                    evidence=[f"{len(times)} connections, mean interval {mean_iv:.1f}s, CV {cv:.3f}"],
                    tags=["c2","beaconing","command-and-control"],
                    raw_entries=[],
                ))
        return events

    def _detect_dns_tunneling(self, summary: PcapSummary) -> List[ThreatEvent]:
        events = []
        domain_counts: Counter = Counter()
        # Known C2/exfil keywords in domain patterns
        _c2_keywords = re.compile(r"(?:exfil|evil|c2|\.cc\b|\.pw\b|\.top\b|\.xyz\b|tunnel|beacon|cmd)", re.I)
        # Indexed chunk pattern: <data>.<index>.<keyword>.<domain> (e.g. abc.0.exfil.evil-c2.com)
        _chunk_pat = re.compile(r"^[a-z0-9]{8,}\.\d+\.", re.I)
        seen_c2_domains: set = set()

        for q in summary.dns_queries:
            name = q.get("name", "")
            qtype = q.get("type", "A")
            parts = name.split(".")
            if len(parts) > 2:
                subdomain = parts[0]
                entropy = _shannon_entropy(subdomain)
                parent_domain = ".".join(parts[-2:])

                # 1. High-entropy long subdomain (tunneling heuristic)
                is_high_entropy = entropy > 3.2 and len(subdomain) > 15
                # 2. Indexed chunk pattern (data.N.keyword.tld)
                is_chunk = bool(_chunk_pat.match(name))
                # 3. C2 keyword in domain
                is_c2_kw = bool(_c2_keywords.search(name))
                # 4. TXT record to unusual subdomain (common exfil method)
                is_txt_exfil = qtype == "TXT" and len(subdomain) > 8

                if is_high_entropy or is_chunk or is_c2_kw or is_txt_exfil:
                    severity = "critical" if (is_c2_kw or is_chunk) else "high"
                    rule = "T1048-DNS-Exfil" if (is_c2_kw or is_chunk) else "T1071.004"
                    name_label = "DNS Data Exfiltration via C2" if (is_c2_kw or is_chunk) else "DNS Tunneling Indicator"
                    seen_c2_domains.add(parent_domain)
                    events.append(ThreatEvent(
                        rule_id=rule,
                        name=name_label,
                        description=f"Suspicious DNS query to {name} (entropy={entropy:.2f}, type={qtype})",
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
                        evidence=[f"DNS {qtype} query: {name} | entropy={entropy:.2f} | chunk={is_chunk} | c2_keyword={is_c2_kw}"],
                        tags=["c2","dns-exfiltration","t1048","exfiltration"],
                        raw_entries=[],
                    ))
            domain_counts[".".join(parts[-2:])] += 1
        # Excessive queries to single domain
        for domain, count in domain_counts.most_common(5):
            if count > 50:
                events.append(ThreatEvent(
                    rule_id="T1071.004-B",
                    name="Excessive DNS Queries",
                    description=f"{count} queries to {domain} — possible tunneling",
                    severity="medium",
                    mitre_tactic="Command and Control",
                    mitre_technique="T1071.004 — DNS",
                    timestamp=None,
                    source_ip=None,
                    dest_ip=None,
                    source_port=None,
                    dest_port=53,
                    host="network",
                    process="pcap",
                    evidence=[f"{count} queries to {domain}"],
                    tags=["c2","dns","exfiltration"],
                    raw_entries=[],
                ))
        return events

    def _detect_suspicious_flows(self, flows: Dict, summary: PcapSummary) -> List[ThreatEvent]:
        events = []
        for (proto, src_ip, sport, dst_ip, dport), flow in flows.items():
            reason = None
            severity = "low"
            if dport in SUSPICIOUS_PORTS:
                reason = f"Suspicious port {dport}: {SUSPICIOUS_PORTS[dport]}"
                severity = "high"
            elif not _is_private_ip(dst_ip) and dport in (4444,1337,31337,6667):
                reason = f"External C2 port {dport}"
                severity = "critical"
            if reason:
                summary.suspicious_ips.add(src_ip)
                flow.is_suspicious = True
                flow.suspicion_reason = reason
                events.append(ThreatEvent(
                    rule_id="T1095",
                    name="Suspicious Network Connection",
                    description=reason,
                    severity=severity,
                    mitre_tactic="Command and Control",
                    mitre_technique="T1095 — Non-Application Layer Protocol",
                    timestamp=flow.first_seen,
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    source_port=sport,
                    dest_port=dport,
                    host="network",
                    process="pcap",
                    evidence=[reason, f"Flow: {src_ip}:{sport} → {dst_ip}:{dport}"],
                    tags=["c2","suspicious-port"],
                    raw_entries=[],
                ))
        return events

    def _detect_arp_poisoning(self, packets: List[Dict], summary: PcapSummary) -> List[ThreatEvent]:
        events = []
        arp_by_ip: Dict[str, Set[str]] = defaultdict(set)
        for pkt in packets:
            arp = pkt.get("arp", {})
            if arp and arp.get("spa") and arp.get("sha"):
                arp_by_ip[arp["spa"]].add(arp["sha"])
        for ip, macs in arp_by_ip.items():
            if len(macs) > 1:
                events.append(ThreatEvent(
                    rule_id="T1557.002",
                    name="ARP Cache Poisoning",
                    description=f"IP {ip} mapped to multiple MACs: {macs}",
                    severity="high",
                    mitre_tactic="Credential Access",
                    mitre_technique="T1557.002 — ARP Cache Poisoning",
                    timestamp=None,
                    source_ip=None,
                    dest_ip=None,
                    source_port=None,
                    dest_port=None,
                    host="network",
                    process="pcap",
                    evidence=[f"IP {ip} → MACs: {', '.join(macs)}"],
                    tags=["mitm","arp","credential-access"],
                    raw_entries=[],
                ))
        return events

    def _detect_c2_indicators(self, flows: Dict, summary: PcapSummary) -> List[ThreatEvent]:
        events = []
        # Long-lived connections to external IPs on odd ports
        for (proto, src_ip, sport, dst_ip, dport), flow in flows.items():
            if (not _is_private_ip(dst_ip) and
                flow.first_seen and flow.last_seen and
                (flow.last_seen - flow.first_seen).total_seconds() > 3600 and
                dport not in (80, 443, 22, 25, 587, 993, 995)):
                events.append(ThreatEvent(
                    rule_id="T1571",
                    name="Long-Lived Non-Standard Port Connection",
                    description=f"Persistent connection to {dst_ip}:{dport} for {(flow.last_seen-flow.first_seen).total_seconds()/3600:.1f}h",
                    severity="medium",
                    mitre_tactic="Command and Control",
                    mitre_technique="T1571 — Non-Standard Port",
                    timestamp=flow.first_seen,
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    source_port=sport,
                    dest_port=dport,
                    host="network",
                    process="pcap",
                    evidence=[f"Duration: {(flow.last_seen-flow.first_seen).total_seconds():.0f}s"],
                    tags=["c2","non-standard-port"],
                    raw_entries=[],
                ))
        return events

    def _detect_http_attacks_pcap(self, packets: List[Dict]) -> List[ThreatEvent]:
        events = []
        sqli_re = re.compile(r"(?:union\s+select|or\s+1=1|' or |--|%27)", re.I)
        xss_re = re.compile(r"(?:<script|javascript:|onerror=|alert\()", re.I)
        lfi_re = re.compile(r"(?:\.\.%2f|%2e%2e|/etc/passwd)", re.I)
        log4shell_re = re.compile(r"\$\{jndi:", re.I)

        for pkt in packets:
            http = pkt.get("http", {})
            ip = pkt.get("ip", {})
            if not http or not ip:
                continue
            uri = http.get("uri", "")
            for pat, name, rule_id in [
                (sqli_re, "SQL Injection (PCAP)", "T1190-SQLi-PCAP"),
                (xss_re, "XSS (PCAP)", "T1059.007-PCAP"),
                (lfi_re, "LFI (PCAP)", "T1083-PCAP"),
                (log4shell_re, "Log4Shell (PCAP)", "T1190-L4J-PCAP"),
            ]:
                if pat.search(uri):
                    events.append(ThreatEvent(
                        rule_id=rule_id,
                        name=name,
                        description=f"HTTP attack in PCAP: {name}",
                        severity="high",
                        mitre_tactic="Initial Access",
                        mitre_technique="T1190 — Exploit Public-Facing Application",
                        timestamp=pkt.get("timestamp"),
                        source_ip=ip.get("src"),
                        dest_ip=ip.get("dst"),
                        source_port=pkt.get("tcp", {}).get("sport"),
                        dest_port=pkt.get("tcp", {}).get("dport"),
                        host="network",
                        process="pcap",
                        evidence=[uri[:300]],
                        tags=["web-attack","initial-access","pcap"],
                        raw_entries=[],
                    ))
                    break
        return events


# ──────────────────────────────────────────────────────────────────────────────
# Correlation engine
# ──────────────────────────────────────────────────────────────────────────────

class CorrelationEngine:
    """Correlates log events with PCAP data, builds timeline and IP intel."""

    def correlate(
        self,
        log_entries: List[LogEntry],
        log_threats: List[ThreatEvent],
        pcap_summary: Optional[PcapSummary],
        pcap_threats: List[ThreatEvent],
    ) -> Tuple[List[ThreatEvent], List[Dict], Dict[str, Dict]]:
        all_threats = log_threats + pcap_threats

        # Deduplicate threats (same rule + same IP + same minute)
        seen: Set[str] = set()
        unique_threats: List[ThreatEvent] = []
        for t in all_threats:
            ts_str = t.timestamp.strftime("%Y%m%d%H%M") if t.timestamp else ""
            key = f"{t.rule_id}:{t.source_ip}:{ts_str}"
            if key not in seen:
                seen.add(key)
                unique_threats.append(t)

        # Build timeline
        timeline_items: List[Dict] = []
        for entry in log_entries:
            if entry.log_level in ("error", "critical", "warning"):
                timeline_items.append({
                    "type": "log",
                    "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
                    "severity": entry.log_level,
                    "host": entry.host,
                    "message": entry.message[:120],
                    "process": entry.process,
                    "source": entry.source_file,
                })
        for threat in unique_threats:
            timeline_items.append({
                "type": "threat",
                "timestamp": threat.timestamp.isoformat() if threat.timestamp else None,
                "severity": threat.severity,
                "name": threat.name,
                "source_ip": threat.source_ip,
                "mitre": threat.mitre_technique,
                "evidence": threat.evidence[0] if threat.evidence else "",
            })
        # Sort by timestamp
        timeline_items.sort(key=lambda x: (x.get("timestamp") or "").replace("+00:00","").replace("Z","")[:19])

        # IP correlation — merge data from both sources
        ip_intel: Dict[str, Dict] = defaultdict(lambda: {
            "appearances": 0,
            "log_threats": 0,
            "pcap_threats": 0,
            "is_private": False,
            "ports_seen": [],
            "threat_names": [],
            "bytes_sent": 0,
            "first_seen": None,
            "last_seen": None,
        })

        for threat in log_threats:
            if threat.source_ip:
                ip = threat.source_ip
                ip_intel[ip]["appearances"] += 1
                ip_intel[ip]["log_threats"] += 1
                ip_intel[ip]["is_private"] = _is_private_ip(ip)
                ip_intel[ip]["threat_names"].append(threat.name)

        if pcap_summary:
            for ip, mac in pcap_summary.arp_table.items():
                ip_intel[ip]["mac"] = mac
            for src_ip, bytes_count in pcap_summary.top_talkers:
                ip_intel[src_ip]["bytes_sent"] += bytes_count
                ip_intel[src_ip]["is_private"] = _is_private_ip(src_ip)
            for ip in pcap_summary.suspicious_ips:
                ip_intel[ip]["pcap_threats"] += 1
                ip_intel[ip]["appearances"] += 1

        for threat in pcap_threats:
            for ip in filter(None, [threat.source_ip, threat.dest_ip]):
                ip_intel[ip]["threat_names"].append(threat.name)
                if threat.dest_port:
                    ip_intel[ip]["ports_seen"].append(threat.dest_port)

        return unique_threats, timeline_items, dict(ip_intel)


# ──────────────────────────────────────────────────────────────────────────────
# Scoring engine
# ──────────────────────────────────────────────────────────────────────────────

def calculate_severity_score(threats: List[ThreatEvent]) -> Tuple[int, str]:
    """Calculate a 0-100 severity score from threat events."""
    if not threats:
        return 0, "None"
    score = 0
    weights = {"info": 1, "low": 5, "medium": 15, "high": 35, "critical": 60}
    for t in threats:
        score += weights.get(t.severity, 5)
    score = min(score, 100)
    if score >= 80:
        return score, "Critical"
    if score >= 60:
        return score, "High"
    if score >= 30:
        return score, "Medium"
    if score >= 10:
        return score, "Low"
    return score, "Informational"


def generate_recommendations(threats: List[ThreatEvent], stats: Dict) -> List[str]:
    """Generate contextual remediation recommendations."""
    recs: List[str] = []
    seen_rules: Set[str] = set()
    rule_map = {
        "T1110.001": "Implement account lockout policy and rate limiting on SSH. Use fail2ban or equivalent. Consider key-based auth only.",
        "T1046": "Review firewall rules. Implement network segmentation. Enable intrusion detection (Snort/Suricata).",
        "T1071.004": "Inspect DNS traffic with RPZ or DNS firewall. Restrict outbound DNS to authorised resolvers only.",
        "T1071.001": "Block or proxy C2 beaconing hosts. Implement EDR and network-level SSL inspection.",
        "T1557.002": "Enable Dynamic ARP Inspection (DAI) on managed switches. Implement 802.1X port authentication.",
        "T1548.003": "Audit sudoers file. Remove unnecessary NOPASSWD entries. Implement PAM hardening.",
        "T1190-SQLi": "Patch web application. Use parameterised queries. Deploy WAF (ModSecurity/NAXSI).",
        "T1190-L4J": "Update Log4j to 2.17.1+. Apply JVM mitigations: -Dlog4j2.formatMsgNoLookups=true.",
        "T1070": "Enable immutable logging (auditd). Forward logs to SIEM. Restrict log file permissions.",
        "T1136": "Audit user accounts. Remove unauthorised accounts. Review /etc/passwd and /etc/group.",
        "T1499": "Tune ulimits. Review resource-intensive processes. Enable cgroups resource limits.",
        "T1053.003": "Audit cron jobs system-wide. Monitor /etc/cron.* and user crontabs. Restrict cron to authorised users.",
    }
    for t in threats:
        if t.rule_id in rule_map and t.rule_id not in seen_rules:
            recs.append(rule_map[t.rule_id])
            seen_rules.add(t.rule_id)

    # General recommendations
    if stats.get("error_count", 0) > 100:
        recs.append("High error rate detected. Review application health and resource limits.")
    if not recs:
        recs.append("No critical threats detected. Continue monitoring and ensure regular patching.")
    return recs[:10]


# ──────────────────────────────────────────────────────────────────────────────
# Helper utilities
# ──────────────────────────────────────────────────────────────────────────────

def _normalize_dt(dt) -> "Optional[datetime]":
    """Strip timezone info from datetime to ensure naive UTC throughout."""
    if dt is None:
        return None
    if hasattr(dt, 'tzinfo') and dt.tzinfo is not None:
        try:
            from datetime import timezone as _tz
            return dt.astimezone(_tz.utc).replace(tzinfo=None)
        except Exception:
            return dt.replace(tzinfo=None)
    return dt


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = Counter(s.lower())
    total = len(s)
    return -sum((c/total) * math.log2(c/total) for c in freq.values())


def _port_to_service(port: int) -> Optional[str]:
    table = {
        20:"FTP-data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",
        53:"DNS",67:"DHCP",68:"DHCP",80:"HTTP",110:"POP3",
        143:"IMAP",443:"HTTPS",445:"SMB",3306:"MySQL",3389:"RDP",
        5432:"PostgreSQL",5900:"VNC",6379:"Redis",8080:"HTTP-proxy",
        8443:"HTTPS-alt",27017:"MongoDB",
    }
    return table.get(port)


def _extract_ips_from_text(text: str) -> List[str]:
    pat = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    candidates = pat.findall(text)
    valid = []
    for ip in candidates:
        try:
            ipaddress.ip_address(ip)
            valid.append(ip)
        except ValueError:
            pass
    return valid
