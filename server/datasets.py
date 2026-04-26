from __future__ import annotations

import csv
import io
import json
import os
import re
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

# Prevent OOM: cap lines ingested per upload (tune with env on large Spaces)
MAX_LOG_ENTRIES = max(1, int(os.environ.get("MAX_LOG_ENTRIES", "500000")))


@dataclass
class UploadedLogEntry:
    ts_ms: int
    source: str
    raw: str
    fields: Dict[str, Any]


UPLOADED_LOGS: List[UploadedLogEntry] = []


def _lower_map(data: Dict[str, Any]) -> Dict[str, Any]:
    lowered: Dict[str, Any] = {}
    for key, value in data.items():
        lowered[str(key).strip().lower()] = value
    return lowered


def _first_present(data: Dict[str, Any], keys: List[str], default: Any = "") -> Any:
    for key in keys:
        if key in data and data[key] not in ("", None):
            return data[key]
    return default


def _infer_category(raw_blob: str, fields: Dict[str, Any]) -> str:
    blob = f"{raw_blob.lower()} {json.dumps(fields, ensure_ascii=True).lower()}"
    if any(token in blob for token in ("login", "authentication", "ssh", "signin", "credential")):
        return "authentication"
    if any(token in blob for token in ("firewall", "dns", "tcp", "udp", "syn", "packet", "netflow")):
        return "network"
    if any(token in blob for token in ("http", "nginx", "apache", "status_code", "request", "user-agent")):
        return "web"
    if any(token in blob for token in ("malware", "edr", "defender", "siem", "xdr", "powershell")):
        return "security"
    if any(token in blob for token in ("iam", "cloudtrail", "aws", "azure", "gcp", "bucket", "s3")):
        return "cloud"
    return "generic"


def normalize_log_fields(raw: str, fields: Dict[str, Any]) -> Dict[str, Any]:
    source_fields = _lower_map(fields)
    raw_compact = raw.strip()

    method_match = re.search(r"\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b", raw_compact, flags=re.IGNORECASE)
    status_match = re.search(r"\b([1-5][0-9]{2})\b", raw_compact)
    ip_match = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", raw_compact)

    normalized: Dict[str, Any] = dict(source_fields)
    normalized["timestamp"] = _first_present(
        source_fields, ["timestamp", "event_time", "ts", "time", "@timestamp"], ""
    )
    normalized["src_ip"] = _first_present(source_fields, ["src_ip", "source_ip", "client_ip", "ip"], "")
    if not normalized["src_ip"] and ip_match:
        normalized["src_ip"] = ip_match[0]
    normalized["dst_ip"] = _first_present(source_fields, ["dst_ip", "destination_ip", "server_ip"], "")
    if not normalized["dst_ip"] and len(ip_match) > 1:
        normalized["dst_ip"] = ip_match[1]
    normalized["user"] = _first_present(source_fields, ["user", "username", "account", "principal"], "")
    normalized["event_type"] = _first_present(source_fields, ["event_type", "event", "action", "activity"], "")
    normalized["status_code"] = _first_present(source_fields, ["status_code", "status", "http_status"], "")
    if not normalized["status_code"] and status_match:
        normalized["status_code"] = status_match.group(1)
    normalized["bytes_out"] = _first_present(
        source_fields, ["bytes_out", "bytes_sent", "egress_bytes", "outbound_bytes"], 0
    )
    normalized["country"] = _first_present(source_fields, ["country", "geo_country", "src_country"], "")
    normalized["service"] = _first_present(source_fields, ["service", "app", "application"], "")
    normalized["method"] = _first_present(source_fields, ["method", "http_method"], "")
    if not normalized["method"] and method_match:
        normalized["method"] = method_match.group(1).upper()
    normalized["path"] = _first_present(source_fields, ["path", "uri", "url", "endpoint"], "")
    normalized["domain"] = _first_present(source_fields, ["domain", "host", "hostname", "query_name"], "")
    normalized["port"] = _first_present(source_fields, ["port", "dst_port", "destination_port"], "")
    normalized["protocol"] = _first_present(source_fields, ["protocol", "proto"], "")
    normalized["result"] = _first_present(source_fields, ["result", "outcome", "status"], "")
    normalized["log_category"] = _infer_category(raw_compact, normalized)
    return normalized


def _to_entry(source: str, raw: str, fields: Dict[str, Any] | None = None) -> UploadedLogEntry:
    normalized = normalize_log_fields(raw.strip(), fields or {})
    return UploadedLogEntry(
        ts_ms=int(time.time() * 1000),
        source=source,
        raw=raw.strip(),
        fields=normalized,
    )


def add_logs_from_content(filename: str, content: bytes) -> Tuple[int, Optional[str]]:
    """
    Ingest file into UPLOADED_LOGS. Returns (inserted_count, optional_warning).
    Line-based formats stream over bytes to avoid double-buffering a huge decode().
    """
    lower = filename.lower()
    before = len(UPLOADED_LOGS)
    warning: Optional[str] = None

    def at_cap() -> bool:
        return (len(UPLOADED_LOGS) - before) >= MAX_LOG_ENTRIES

    if at_cap():
        return 0, "In-memory log cap reached; use POST /api/datasets/logs/clear or lower MAX_LOG_ENTRIES."

    if lower.endswith(".csv"):
        stream = io.TextIOWrapper(
            io.BytesIO(content), encoding="utf-8", errors="replace", newline=""
        )
        try:
            reader = csv.DictReader(stream)
            for row in reader:
                if at_cap():
                    warning = (
                        f"Import stopped at {MAX_LOG_ENTRIES:,} rows (safety cap MAX_LOG_ENTRIES). "
                        "For huge CSV, split the file or raise the cap via env (watch RAM)."
                    )
                    break
                raw = ", ".join(f"{k}={v}" for k, v in (row or {}).items())
                UPLOADED_LOGS.append(_to_entry(filename, raw, dict(row or {})))
        finally:
            stream.detach()

    elif lower.endswith(".json") or lower.endswith(".jsonl"):
        # One JSON per line; stream lines from bytes
        for raw_line in io.BytesIO(content):
            if at_cap():
                warning = (
                    f"Import stopped at {MAX_LOG_ENTRIES:,} lines (safety cap MAX_LOG_ENTRIES). "
                    "For very large .jsonl, split or increase MAX_LOG_ENTRIES (watch memory)."
                )
                break
            line = raw_line.rstrip(b"\r\n").decode("utf-8", errors="ignore").strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
                if isinstance(payload, dict):
                    UPLOADED_LOGS.append(_to_entry(filename, json.dumps(payload), payload))
                else:
                    UPLOADED_LOGS.append(_to_entry(filename, str(payload)))
            except json.JSONDecodeError:
                UPLOADED_LOGS.append(_to_entry(filename, line))

    else:
        for raw_line in io.BytesIO(content):
            if at_cap():
                warning = (
                    f"Import stopped at {MAX_LOG_ENTRIES:,} lines (safety cap). "
                    "Use smaller samples, split files, or raise MAX_LOG_ENTRIES (watch memory)."
                )
                break
            line = raw_line.rstrip(b"\r\n").decode("utf-8", errors="ignore").strip()
            if line:
                UPLOADED_LOGS.append(_to_entry(filename, line))

    inserted = len(UPLOADED_LOGS) - before
    return inserted, warning


def clear_uploaded_logs() -> None:
    UPLOADED_LOGS.clear()


def search_uploaded_logs(query: str, max_results: int = 50) -> List[Dict[str, Any]]:
    q = (query or "").lower().strip()
    if not q:
        return [asdict(entry) for entry in UPLOADED_LOGS[:max_results]]

    hits: List[Dict[str, Any]] = []
    for entry in UPLOADED_LOGS:
        blob = f"{entry.raw} {json.dumps(entry.fields, ensure_ascii=True)}".lower()
        if q in blob:
            hits.append(asdict(entry))
            if len(hits) >= max_results:
                break
    return hits


_SPL_NOISE = re.compile(
    r"\b(search|index|sourcetype|source|as|by|earliest|latest|head|where|sort|"
    r"dedup|stats|count|table|or|and|not|true|false|main)\b",
    re.IGNORECASE,
)


def _query_search_terms(text: str) -> List[str]:
    """Tokenize a Splunk line or free-text query for substring log search."""
    if not (text or "").strip():
        return []
    s = (text or "").lower()
    cleaned = _SPL_NOISE.sub(" ", s)
    out: List[str] = []
    for m in re.finditer(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", cleaned):
        out.append(m.group(0))
    for m in re.finditer(r"\b[aA]-[0-9A-Za-z\-]{2,}\b", text):
        out.append(m.group(0))
    for token in re.findall(r"[A-Za-z0-9@._%+\-]+", text):
        tl = token.lower()
        if len(tl) < 3 or tl in ("main", "all", "and", "the", "for", "not", "or"):
            continue
        out.append(token)
    seen: set = set()
    uniq: List[str] = []
    for t in out:
        k = t.lower()
        if k in seen:
            continue
        seen.add(k)
        uniq.append(t)
    return uniq[:20]


def _alert_probe_terms(alert: Optional[Dict[str, Any]]) -> List[str]:
    if not alert:
        return []
    keys = ("ip", "id", "user", "hash", "type", "target", "hostname", "source")
    out: List[str] = []
    for k in keys:
        v = str(alert.get(k) or "").strip()
        if v:
            out.append(v)
    return out


def search_uploaded_logs_best_effort(
    query: str,
    max_results: int = 10,
    alert: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Match ingested logs against a Spl/SPL-style or natural query.
    Tries the full string, decomposed terms, and alert fields; if uploads exist
    but nothing matches, returns a head sample (same as empty search).
    """
    candidates: List[str] = []
    q0 = (query or "").strip()
    if q0:
        candidates.append(q0)
    candidates.extend(_query_search_terms(query or ""))
    candidates.extend(_alert_probe_terms(alert))

    seen_c: set = set()
    ordered: List[str] = []
    for c in candidates:
        c = (c or "").strip()
        if not c:
            continue
        k = c.lower()
        if k in seen_c:
            continue
        seen_c.add(k)
        ordered.append(c)

    out: List[Dict[str, Any]] = []
    seen_row: set = set()
    for c in ordered:
        for row in search_uploaded_logs(c, max_results=max_results):
            key = (row.get("source"), row.get("ts_ms"), row.get("raw"))
            if key in seen_row:
                continue
            seen_row.add(key)
            out.append(row)
            if len(out) >= max_results:
                return out
    if not out and UPLOADED_LOGS:
        return search_uploaded_logs("", max_results=max_results)
    return out


def uploaded_logs_summary() -> Dict[str, Any]:
    sources: Dict[str, int] = {}
    for item in UPLOADED_LOGS:
        sources[item.source] = sources.get(item.source, 0) + 1
    return {"total_logs": len(UPLOADED_LOGS), "sources": sources}
