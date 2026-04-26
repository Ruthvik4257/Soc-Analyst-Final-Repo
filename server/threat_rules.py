from __future__ import annotations

import copy
import math
from dataclasses import dataclass
from datetime import datetime
from statistics import mean, pstdev
from typing import Any, Dict, List, Optional, Tuple


DECISION_FALSE_POSITIVE = "false_positive"
DECISION_ESCALATE = "escalate_tier2"
DECISION_BLOCK = "block_if_malicious"

@dataclass
class ThreatValidationResult:
    recommended_decision: str
    score: float
    factors: List[str]
    confidence: float
    severity: str
    rule_hits: List[Dict[str, Any]]
    anomaly_signals: List[Dict[str, Any]]
    ioc_hits: List[str]


DEFAULT_RULE_CONFIG: Dict[str, Any] = {
    "auth_failed_login_threshold_60s": 5,
    "auth_spray_user_threshold_60s": 4,
    "auth_off_hours_start": 0,
    "auth_off_hours_end": 5,
    "network_port_scan_unique_ports": 15,
    "network_syn_flood_min_events": 10,
    "network_egress_spike_multiplier": 3.0,
    "network_beacon_min_hits": 4,
    "web_404_threshold": 12,
    "web_500_threshold": 5,
    "web_req_rate_threshold": 80,
    "security_multi_alert_threshold": 3,
    "cloud_failed_api_auth_threshold": 6,
    "cloud_data_exfil_threshold_bytes": 50_000_000,
}

RULE_CONFIG: Dict[str, Any] = copy.deepcopy(DEFAULT_RULE_CONFIG)
RULE_RUNTIME_STATS: Dict[str, Any] = {
    "evaluations": 0,
    "high_severity": 0,
    "last_score": 0.0,
}

KNOWN_BAD_IOCS = {"203.0.113.5", "198.51.100.66", "malicious.example.com"}
SQLI_PATTERNS = (" union ", " select ", "' or 1=1", "drop table", "--")
XSS_PATTERNS = ("<script", "javascript:", "onerror=", "onload=")
SUSPICIOUS_PROCESS_PATTERNS = ("powershell -enc", "mimikatz", "rundll32", "regsvr32")
MALWARE_KEYWORDS = ("emotet", "trojan", "ransomware", "c2", "beacon", "payload", "credential dump")
BENIGN_TRAVEL_HINTS = ("zscaler", "vpn gateway", "corporate vpn", "trusted vpn")


def _safe_lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _extract_field(entry: Dict[str, Any], *names: str) -> str:
    fields = entry.get("fields") or {}
    for name in names:
        if name in fields and fields[name] is not None:
            return str(fields[name])
    return ""


def _extract_numeric(entry: Dict[str, Any], *names: str) -> float:
    value = _extract_field(entry, *names)
    try:
        return float(value)
    except ValueError:
        return 0.0


def _parse_event_time(entry: Dict[str, Any]) -> Optional[datetime]:
    return _parse_iso_timestamp(_extract_field(entry, "timestamp", "event_time", "ts", "time"))


def _blob(entry: Dict[str, Any]) -> str:
    return f"{_safe_lower(entry.get('raw'))} {json_like(entry.get('fields'))}"


def json_like(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(f"{_safe_lower(k)}={_safe_lower(v)}" for k, v in value.items())
    return _safe_lower(value)


def _to_decision(score: float) -> str:
    if score >= 0.8:
        return DECISION_BLOCK
    if score >= 0.35:
        return DECISION_ESCALATE
    return DECISION_FALSE_POSITIVE


def _severity(score: float) -> str:
    if score >= 1.0:
        return "critical"
    if score >= 0.75:
        return "high"
    if score >= 0.35:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def _parse_iso_timestamp(raw: str) -> Optional[datetime]:
    text = _safe_lower(raw)
    if not text:
        return None
    if text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _geo_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    # Haversine distance.
    radius_km = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    )
    return 2 * radius_km * math.asin(math.sqrt(max(0.0, min(1.0, a))))


def _impossible_travel_score(entries: List[Dict[str, Any]]) -> Tuple[float, List[str]]:
    # Looks for two logins from distant geos in short interval.
    points: List[Tuple[datetime, float, float, str]] = []
    for row in entries:
        ts = _parse_iso_timestamp(_extract_field(row, "timestamp", "event_time", "ts", "time"))
        lat_text = _extract_field(row, "lat", "latitude")
        lon_text = _extract_field(row, "lon", "longitude", "lng")
        src = _safe_lower(row.get("raw"))
        if ts is None or not lat_text or not lon_text:
            continue
        try:
            points.append((ts, float(lat_text), float(lon_text), src))
        except ValueError:
            continue

    if len(points) < 2:
        return 0.0, []

    points.sort(key=lambda x: x[0])
    best_speed = 0.0
    factors: List[str] = []
    for idx in range(1, len(points)):
        prev = points[idx - 1]
        cur = points[idx]
        hours = max(1e-6, (cur[0] - prev[0]).total_seconds() / 3600.0)
        distance = _geo_distance_km(prev[1], prev[2], cur[1], cur[2])
        speed = distance / hours
        if speed > best_speed:
            best_speed = speed
        if speed > 900.0:
            factors.append(f"Impossible travel detected: ~{int(speed)} km/h")

    if best_speed > 900.0:
        return 0.45, factors
    if best_speed > 700.0:
        return 0.2, [f"Unusually high travel speed: ~{int(best_speed)} km/h"]
    return 0.0, []


def _rule_hit(name: str, category: str, score: float, detail: str) -> Dict[str, Any]:
    return {"rule": name, "category": category, "score": round(score, 4), "detail": detail}


def _evaluate_auth_rules(logs: List[Dict[str, Any]], cfg: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]], List[str]]:
    score = 0.0
    hits: List[Dict[str, Any]] = []
    iocs: List[str] = []
    failures_by_ip: Dict[str, List[datetime]] = {}
    failures_by_user: Dict[str, int] = {}
    success_after_fail = False
    disabled_login = False
    root_external = False

    for row in logs:
        blob = _blob(row)
        ts = _parse_event_time(row)
        src_ip = _extract_field(row, "src_ip", "ip", "source_ip")
        user = _extract_field(row, "user", "username", "account")
        is_failure = any(token in blob for token in ("failed login", "invalid password", "authentication failure"))
        is_success = "login success" in blob or "authentication success" in blob
        if is_failure and src_ip:
            failures_by_ip.setdefault(src_ip, [])
            if ts:
                failures_by_ip[src_ip].append(ts)
            failures_by_user[user or "unknown"] = failures_by_user.get(user or "unknown", 0) + 1
        if is_success and sum(failures_by_user.values()) > 0:
            success_after_fail = True
        if "disabled account" in blob and ("login" in blob or "auth" in blob):
            disabled_login = True
        if user.lower() in ("root", "admin") and src_ip and not src_ip.startswith("10.") and not src_ip.startswith("192.168."):
            root_external = True
        if src_ip in KNOWN_BAD_IOCS:
            iocs.append(src_ip)

    for ip, times in failures_by_ip.items():
        if len(times) < cfg["auth_failed_login_threshold_60s"]:
            continue
        times.sort()
        window_hit = False
        for idx in range(len(times)):
            end_idx = idx + cfg["auth_failed_login_threshold_60s"] - 1
            if end_idx >= len(times):
                break
            delta = (times[end_idx] - times[idx]).total_seconds()
            if delta <= 60:
                window_hit = True
                break
        if window_hit:
            score += 0.35
            hits.append(_rule_hit("auth_bruteforce_60s", "authentication", 0.35, f"{ip} exceeded failed-login threshold"))

    sprayed_users = [u for u, cnt in failures_by_user.items() if cnt >= 1 and u != "unknown"]
    if len(sprayed_users) >= cfg["auth_spray_user_threshold_60s"]:
        score += 0.25
        hits.append(_rule_hit("auth_password_spray", "authentication", 0.25, "Many users targeted by failures"))
    if success_after_fail:
        score += 0.15
        hits.append(_rule_hit("auth_success_after_failures", "authentication", 0.15, "Login succeeded after failures"))
    if disabled_login:
        score += 0.2
        hits.append(_rule_hit("auth_disabled_account_login", "authentication", 0.2, "Disabled account login attempt"))
    if root_external:
        score += 0.3
        hits.append(_rule_hit("auth_root_external", "authentication", 0.3, "Privileged login from external IP"))
    return score, hits, iocs


def _evaluate_network_rules(logs: List[Dict[str, Any]], cfg: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]], List[str]]:
    score = 0.0
    hits: List[Dict[str, Any]] = []
    iocs: List[str] = []
    ports_by_ip: Dict[str, set] = {}
    syn_count = 0
    ack_count = 0
    outbound_values: List[float] = []
    connection_targets: Dict[str, set] = {}
    domain_lengths: List[int] = []

    for row in logs:
        blob = _blob(row)
        src_ip = _extract_field(row, "src_ip", "ip")
        dst_ip = _extract_field(row, "dst_ip", "destination_ip")
        port = _extract_field(row, "port", "dst_port", "destination_port")
        bytes_out = _extract_numeric(row, "bytes_out", "bytes_sent", "egress_bytes")
        domain = _extract_field(row, "domain", "query_name", "host")
        outbound_values.append(bytes_out)
        if src_ip and port:
            ports_by_ip.setdefault(src_ip, set()).add(port)
        if src_ip and dst_ip:
            connection_targets.setdefault(src_ip, set()).add(dst_ip)
        if "syn" in blob:
            syn_count += 1
        if "ack" in blob:
            ack_count += 1
        if domain:
            domain_lengths.append(len(domain))
        for ioc in KNOWN_BAD_IOCS:
            if ioc in blob:
                iocs.append(ioc)

    for ip, ports in ports_by_ip.items():
        if len(ports) >= cfg["network_port_scan_unique_ports"]:
            score += 0.3
            hits.append(_rule_hit("network_port_scan", "network", 0.3, f"{ip} touched {len(ports)} ports"))
    if syn_count >= cfg["network_syn_flood_min_events"] and (ack_count == 0 or syn_count / max(1, ack_count) > 3.0):
        score += 0.25
        hits.append(_rule_hit("network_syn_flood_ratio", "network", 0.25, "SYN volume far exceeds ACK"))
    for src, dsts in connection_targets.items():
        if len(dsts) >= 20:
            score += 0.2
            hits.append(_rule_hit("network_many_external_peers", "network", 0.2, f"{src} contacted {len(dsts)} peers"))
    if domain_lengths and mean(domain_lengths) > 28:
        score += 0.12
        hits.append(_rule_hit("network_dns_tunneling_shape", "network", 0.12, "Long/random DNS labels observed"))
    return score, hits, iocs


def _evaluate_web_rules(logs: List[Dict[str, Any]], cfg: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]], List[str]]:
    score = 0.0
    hits: List[Dict[str, Any]] = []
    iocs: List[str] = []
    status_404 = 0
    status_500 = 0
    req_by_ip: Dict[str, int] = {}

    for row in logs:
        blob = _blob(row)
        status = _extract_field(row, "status_code", "status", "http_status")
        src_ip = _extract_field(row, "src_ip", "ip")
        path = _extract_field(row, "path", "uri", "url")
        method = _extract_field(row, "method", "http_method").upper()
        if status == "404":
            status_404 += 1
        if status == "500":
            status_500 += 1
        if src_ip:
            req_by_ip[src_ip] = req_by_ip.get(src_ip, 0) + 1
        if any(pat in blob for pat in SQLI_PATTERNS):
            score += 0.3
            hits.append(_rule_hit("web_sqli_pattern", "web", 0.3, "SQL injection pattern found"))
        if any(pat in blob for pat in XSS_PATTERNS):
            score += 0.25
            hits.append(_rule_hit("web_xss_pattern", "web", 0.25, "XSS payload pattern found"))
        if path and any(p in path.lower() for p in ("/admin", "/etc/passwd", "/.env")):
            score += 0.2
            hits.append(_rule_hit("web_sensitive_path_access", "web", 0.2, f"Sensitive path hit: {path}"))
        if method in ("PUT", "DELETE") and "/api/" not in path.lower():
            score += 0.12
            hits.append(_rule_hit("web_method_misuse", "web", 0.12, f"Unexpected method {method} on {path}"))

    if status_404 >= cfg["web_404_threshold"]:
        score += 0.2
        hits.append(_rule_hit("web_404_enumeration", "web", 0.2, f"{status_404} not-found responses"))
    if status_500 >= cfg["web_500_threshold"]:
        score += 0.15
        hits.append(_rule_hit("web_500_spike", "web", 0.15, f"{status_500} server errors"))
    for ip, count in req_by_ip.items():
        if count >= cfg["web_req_rate_threshold"]:
            score += 0.25
            hits.append(_rule_hit("web_high_req_rate_ip", "web", 0.25, f"{ip} sent {count} requests"))
        if ip in KNOWN_BAD_IOCS:
            iocs.append(ip)
    return score, hits, iocs


def _evaluate_security_rules(logs: List[Dict[str, Any]], cfg: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]], List[str]]:
    score = 0.0
    hits: List[Dict[str, Any]] = []
    iocs: List[str] = []
    alerts_by_host: Dict[str, int] = {}

    for row in logs:
        blob = _blob(row)
        host = _extract_field(row, "host", "hostname", "device", "endpoint") or "unknown"
        if any(token in blob for token in MALWARE_KEYWORDS):
            score += 0.35
            hits.append(_rule_hit("security_malware_alert", "security", 0.35, "Malware indicator present"))
            alerts_by_host[host] = alerts_by_host.get(host, 0) + 1
        if "privilege escalation" in blob or "sudoers modified" in blob:
            score += 0.3
            hits.append(_rule_hit("security_priv_escalation", "security", 0.3, "Privilege escalation signal"))
        if "endpoint protection disabled" in blob or "antivirus disabled" in blob:
            score += 0.28
            hits.append(_rule_hit("security_protection_disabled", "security", 0.28, "Protection disabled"))
        if any(term in blob for term in SUSPICIOUS_PROCESS_PATTERNS):
            score += 0.24
            hits.append(_rule_hit("security_suspicious_process", "security", 0.24, "Suspicious tool execution"))
        for ioc in KNOWN_BAD_IOCS:
            if ioc in blob:
                iocs.append(ioc)

    for host, count in alerts_by_host.items():
        if count >= cfg["security_multi_alert_threshold"]:
            score += 0.2
            hits.append(_rule_hit("security_multi_alert_host", "security", 0.2, f"{host} generated {count} alerts"))
    return score, hits, iocs


def _evaluate_cloud_rules(logs: List[Dict[str, Any]], cfg: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]], List[str]]:
    score = 0.0
    hits: List[Dict[str, Any]] = []
    iocs: List[str] = []
    failed_api_auth = 0
    data_exfil = 0.0

    for row in logs:
        blob = _blob(row)
        src_ip = _extract_field(row, "src_ip", "ip")
        country = _extract_field(row, "country", "geo_country")
        bytes_out = _extract_numeric(row, "bytes_out", "egress_bytes", "bytes_sent")
        data_exfil += bytes_out

        if "createuser" in blob or "create access key" in blob or "create-access-key" in blob:
            score += 0.25
            hits.append(_rule_hit("cloud_iam_key_or_user_created", "cloud", 0.25, "New IAM principal/key created"))
        if "assumerole" in blob and ("admin" in blob or "poweruser" in blob):
            score += 0.2
            hits.append(_rule_hit("cloud_role_priv_escalation", "cloud", 0.2, "High-privilege role assumption"))
        if "stoplogging" in blob or "disable cloudtrail" in blob or "monitoring disabled" in blob:
            score += 0.35
            hits.append(_rule_hit("cloud_logging_disabled", "cloud", 0.35, "Logging/monitoring disabled"))
        if "public-read" in blob or "bucket policy public" in blob or "acl public" in blob:
            score += 0.3
            hits.append(_rule_hit("cloud_public_bucket_exposure", "cloud", 0.3, "Public data exposure"))
        if "authfailure" in blob or "failed authentication" in blob or "invalidclienttokenid" in blob:
            failed_api_auth += 1
        if src_ip in KNOWN_BAD_IOCS:
            iocs.append(src_ip)
        if country and country.lower() in ("ru", "kp", "ir"):
            score += 0.08
            hits.append(_rule_hit("cloud_unusual_geo", "cloud", 0.08, f"Unusual source country: {country}"))

    if failed_api_auth >= cfg["cloud_failed_api_auth_threshold"]:
        score += 0.2
        hits.append(_rule_hit("cloud_failed_api_auth_spike", "cloud", 0.2, f"{failed_api_auth} failed API auth events"))
    if data_exfil >= cfg["cloud_data_exfil_threshold_bytes"]:
        score += 0.3
        hits.append(_rule_hit("cloud_large_data_egress", "cloud", 0.3, f"{int(data_exfil)} bytes outbound"))
    return score, hits, iocs


def _evaluate_anomalies(logs: List[Dict[str, Any]], cfg: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]]]:
    signals: List[Dict[str, Any]] = []
    score = 0.0
    bytes_series: List[float] = []
    per_ip_count: Dict[str, int] = {}
    timestamped: List[datetime] = []

    for row in logs:
        bytes_series.append(_extract_numeric(row, "bytes_out", "bytes_sent", "egress_bytes"))
        ip = _extract_field(row, "src_ip", "ip")
        if ip:
            per_ip_count[ip] = per_ip_count.get(ip, 0) + 1
        ts = _parse_event_time(row)
        if ts:
            timestamped.append(ts)

    if len(bytes_series) >= 6:
        avg = mean(bytes_series)
        std = pstdev(bytes_series) if len(bytes_series) > 1 else 0.0
        mx = max(bytes_series) if bytes_series else 0.0
        if std > 0 and mx > avg + (2.5 * std):
            signals.append({"signal": "anomaly_egress_spike", "detail": f"max={mx:.0f}, baseline={avg:.0f}", "score": 0.2})
            score += 0.2
        elif avg > 0 and mx / avg >= cfg["network_egress_spike_multiplier"]:
            signals.append({"signal": "anomaly_egress_multiplier", "detail": f"max/baseline={mx/avg:.2f}", "score": 0.15})
            score += 0.15

    for ip, count in per_ip_count.items():
        if count >= 120:
            signals.append({"signal": "anomaly_request_burst", "detail": f"{ip} generated {count} events", "score": 0.2})
            score += 0.2

    # Lightweight beaconing heuristic: near-periodic event intervals.
    if len(timestamped) >= cfg["network_beacon_min_hits"]:
        timestamped.sort()
        deltas = [
            max(1, int((timestamped[idx] - timestamped[idx - 1]).total_seconds()))
            for idx in range(1, len(timestamped))
        ]
        if deltas:
            d_avg = mean(deltas)
            d_std = pstdev(deltas) if len(deltas) > 1 else 0.0
            if d_avg > 0 and d_std <= (0.2 * d_avg):
                signals.append({"signal": "anomaly_beaconing_periodic", "detail": f"interval_mean={d_avg:.1f}s std={d_std:.1f}", "score": 0.16})
                score += 0.16

    return score, signals


def rules_catalog() -> Dict[str, Any]:
    return {
        "categories": ["authentication", "network", "web", "security", "cloud"],
        "config": copy.deepcopy(RULE_CONFIG),
        "decisions": [DECISION_FALSE_POSITIVE, DECISION_ESCALATE, DECISION_BLOCK],
    }


def update_rule_config(patch: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in (patch or {}).items():
        if key in RULE_CONFIG:
            RULE_CONFIG[key] = value
    return copy.deepcopy(RULE_CONFIG)


def rules_status() -> Dict[str, Any]:
    return {
        "evaluations": RULE_RUNTIME_STATS["evaluations"],
        "high_severity": RULE_RUNTIME_STATS["high_severity"],
        "last_score": RULE_RUNTIME_STATS["last_score"],
        "active_config": copy.deepcopy(RULE_CONFIG),
    }


def validate_decision(
    alert: Dict[str, Any],
    candidate_logs: List[Dict[str, Any]],
    config: Optional[Dict[str, Any]] = None,
) -> ThreatValidationResult:
    cfg = copy.deepcopy(RULE_CONFIG)
    if config:
        cfg.update(config)

    logs = candidate_logs or []
    alert_blob = _safe_lower(alert)
    rule_hits: List[Dict[str, Any]] = []
    anomaly_signals: List[Dict[str, Any]] = []
    ioc_hits: List[str] = []
    total_score = 0.0

    for evaluator in (
        _evaluate_auth_rules,
        _evaluate_network_rules,
        _evaluate_web_rules,
        _evaluate_security_rules,
        _evaluate_cloud_rules,
    ):
        s, hits, iocs = evaluator(logs, cfg)
        total_score += s
        rule_hits.extend(hits)
        ioc_hits.extend(iocs)

    travel_score, travel_factors = _impossible_travel_score(logs)
    if travel_score > 0:
        total_score += travel_score
        for detail in travel_factors:
            rule_hits.append(_rule_hit("auth_impossible_travel", "authentication", travel_score, detail))

    if "impossible_travel" in alert_blob:
        benign_hits = sum(1 for row in logs if any(token in _blob(row) for token in BENIGN_TRAVEL_HINTS))
        if benign_hits > 0:
            total_score -= 0.25
            rule_hits.append(
                _rule_hit(
                    "auth_trusted_vpn_context",
                    "authentication",
                    -0.25,
                    "Trusted VPN/corporate gateway lowered risk",
                )
            )

    anomaly_score, anomaly_signals = _evaluate_anomalies(logs, cfg)
    total_score += anomaly_score

    total_score = max(-0.4, min(2.0, total_score))
    decision = _to_decision(total_score)
    severity = _severity(total_score)
    confidence = max(0.2, min(0.99, 0.45 + (abs(total_score) * 0.22)))
    factors = [hit["detail"] for hit in sorted(rule_hits, key=lambda h: h["score"], reverse=True)[:6]]
    if not factors:
        factors = ["No strong threat indicators found in available evidence."]

    RULE_RUNTIME_STATS["evaluations"] += 1
    RULE_RUNTIME_STATS["last_score"] = round(total_score, 4)
    if severity in ("high", "critical"):
        RULE_RUNTIME_STATS["high_severity"] += 1

    return ThreatValidationResult(
        recommended_decision=decision,
        score=round(total_score, 4),
        factors=factors,
        confidence=round(confidence, 4),
        severity=severity,
        rule_hits=rule_hits,
        anomaly_signals=anomaly_signals,
        ioc_hits=sorted(set(ioc_hits)),
    )

