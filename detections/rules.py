"""
Detection rules for the AWS Cloud Detection Lab.

Each rule is a function that takes a list of events and returns a list of findings.
Add new rules by defining a function and registering it in RULES.
"""

from collections import defaultdict
from datetime import datetime, timezone


def _ts():
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# CloudTrail rules
# ---------------------------------------------------------------------------

def detect_iam_privilege_escalation(events):
    """
    Flags API calls associated with privilege escalation attempts:
    AttachUserPolicy, PutUserPolicy, CreateAccessKey on other users,
    AddUserToGroup targeting admin groups.
    """
    ESCALATION_EVENTS = {
        "AttachUserPolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "AttachRolePolicy",
        "CreateAccessKey",
        "AddUserToGroup",
        "UpdateAssumeRolePolicy",
        "CreateLoginProfile",
        "UpdateLoginProfile",
    }
    findings = []
    for e in events:
        if e.get("source") != "cloudtrail":
            continue
        if e.get("event_name") in ESCALATION_EVENTS:
            findings.append({
                "rule": "IAM privilege escalation attempt",
                "severity": "HIGH",
                "time": e.get("time"),
                "detail": f"{e.get('event_name')} called by {e.get('user')} from {e.get('source_ip')}",
                "mitre": "T1078 - Valid Accounts / T1098 - Account Manipulation",
                "raw_event": e,
            })
    return findings


def detect_repeated_auth_failures(events, threshold=5):
    """
    Detects repeated AccessDenied or auth failures from the same IP,
    which may indicate credential stuffing or enumeration.
    """
    failures = defaultdict(list)
    for e in events:
        if e.get("source") != "cloudtrail":
            continue
        if e.get("error_code") in ("AccessDenied", "AuthFailure", "InvalidClientTokenId"):
            ip = e.get("source_ip", "unknown")
            failures[ip].append(e)

    findings = []
    for ip, evts in failures.items():
        if len(evts) >= threshold:
            findings.append({
                "rule": "Repeated auth failures",
                "severity": "MEDIUM",
                "time": _ts(),
                "detail": f"{len(evts)} auth failures from {ip} (threshold: {threshold})",
                "mitre": "T1110 - Brute Force",
                "raw_event": evts[0],
            })
    return findings


def detect_root_account_usage(events):
    root_events = [e for e in events if e.get("source") == "cloudtrail" and e.get("user_type") == "Root"]
    if not root_events:
        return []

    unique_actions = {}
    for e in root_events:
        name = e.get("event_name")
        if name not in unique_actions:
            unique_actions[name] = e

    return [{
        "rule": "Root account usage",
        "severity": "HIGH",
        "time": min(e.get("time", "") for e in root_events),
        "detail": f"Root account made {len(root_events)} API calls ({len(unique_actions)} unique actions) from {root_events[0].get('source_ip')}. Actions: {', '.join(sorted(unique_actions.keys())[:10])}{'...' if len(unique_actions) > 10 else ''}",
        "mitre": "T1078.004 - Cloud Accounts",
        "raw_event": root_events[0],
    }]


def detect_cloudtrail_tampering(events):
    """
    Detects attempts to disable or modify CloudTrail, a common
    defense evasion technique.
    """
    TAMPER_EVENTS = {
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
        "PutEventSelectors",
    }
    findings = []
    for e in events:
        if e.get("source") != "cloudtrail":
            continue
        if e.get("event_name") in TAMPER_EVENTS:
            findings.append({
                "rule": "CloudTrail tampering",
                "severity": "CRITICAL",
                "time": e.get("time"),
                "detail": f"{e.get('event_name')} by {e.get('user')} from {e.get('source_ip')}",
                "mitre": "T1562.008 - Disable Cloud Logs",
                "raw_event": e,
            })
    return findings


def detect_unusual_region_activity(events, home_region="eu-central-1"):
    """
    Flags API calls made from regions other than the expected home region.
    Could indicate compromised credentials used elsewhere.
    """
    findings = []
    for e in events:
        if e.get("source") != "cloudtrail":
            continue
        region = e.get("region")
        if region and region != home_region:
            findings.append({
                "rule": "Activity in unexpected region",
                "severity": "LOW",
                "time": e.get("time"),
                "detail": f"{e.get('event_name')} in {region} (expected {home_region})",
                "mitre": "T1535 - Unused/Unsupported Cloud Regions",
                "raw_event": e,
            })
    return findings


# ---------------------------------------------------------------------------
# VPC Flow Log rules
# ---------------------------------------------------------------------------

def detect_port_scan(events, threshold=15):
    """
    Detects a single source IP attempting connections to many different
    destination ports on the same target — classic horizontal port scan.
    """
    # src_ip -> dst_ip -> set of dst_ports
    scan_map = defaultdict(lambda: defaultdict(set))

    for e in events:
        if e.get("source") != "flowlog":
            continue
        if e.get("action") != "REJECT":
            continue
        src = e.get("src_addr")
        dst = e.get("dst_addr")
        port = e.get("dst_port")
        if src and dst and port and port != "-":
            scan_map[src][dst].add(port)

    findings = []
    for src, targets in scan_map.items():
        for dst, ports in targets.items():
            if len(ports) >= threshold:
                findings.append({
                    "rule": "Port scan detected",
                    "severity": "MEDIUM",
                    "time": _ts(),
                    "detail": f"{src} → {dst}: {len(ports)} rejected ports (threshold: {threshold})",
                    "mitre": "T1046 - Network Service Discovery",
                    "raw_event": None,
                })
    return findings


def detect_ssh_bruteforce(events, threshold=10):
    """
    Repeated rejected connections to port 22 from the same source IP.
    """
    ssh_attempts = defaultdict(list)
    for e in events:
        if e.get("source") != "flowlog":
            continue
        if e.get("dst_port") == "22" and e.get("action") == "REJECT":
            ssh_attempts[e.get("src_addr")].append(e)

    findings = []
    for src, evts in ssh_attempts.items():
        if len(evts) >= threshold:
            findings.append({
                "rule": "SSH brute force attempt",
                "severity": "HIGH",
                "time": _ts(),
                "detail": f"{len(evts)} rejected SSH connections from {src}",
                "mitre": "T1110.003 - Password Spraying",
                "raw_event": evts[0],
            })
    return findings


def detect_unusual_outbound(events, internal_prefix="10."):
    SUSPICIOUS_PORTS = {"4444", "4445", "5555", "6666", "7777", "8888", "9999", "1337"}
    findings = []
    for e in events:
        if e.get("source") != "flowlog":
            continue
        src = e.get("src_addr") or ""
        dst = e.get("dst_addr") or ""
        dst_port = e.get("dst_port", "")
        action = e.get("action")

        if (src.startswith(internal_prefix)
                and not dst.startswith(internal_prefix)
                and action == "ACCEPT"
                and dst_port in SUSPICIOUS_PORTS):
            findings.append({
                "rule": "Unusual outbound connection",
                "severity": "HIGH",
                "time": e.get("time"),
                "detail": f"{src} → {dst}:{dst_port} (ACCEPT) — suspicious port",
                "mitre": "T1071 - Application Layer Protocol / T1041 - Exfiltration over C2",
                "raw_event": e,
            })
    return findings


def detect_large_data_transfer(events, byte_threshold=50_000_000):
    """
    Flags single flow records with very high byte counts,
    which may indicate data exfiltration.
    """
    findings = []
    for e in events:
        if e.get("source") != "flowlog":
            continue
        try:
            b = int(e.get("bytes", 0))
        except (ValueError, TypeError):
            continue
        if b >= byte_threshold:
            findings.append({
                "rule": "Large data transfer",
                "severity": "MEDIUM",
                "time": e.get("time"),
                "detail": f"{e.get('src_addr')} → {e.get('dst_addr')}: {b:,} bytes in single flow",
                "mitre": "T1048 - Exfiltration Over Alternative Protocol",
                "raw_event": e,
            })
    return findings


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

RULES = [
    # CloudTrail
    detect_iam_privilege_escalation,
    detect_repeated_auth_failures,
    detect_root_account_usage,
    detect_cloudtrail_tampering,
    detect_unusual_region_activity,
    # Flow Logs
    detect_port_scan,
    detect_ssh_bruteforce,
    detect_unusual_outbound,
    detect_large_data_transfer,
]


def run_all(events):
    """Run all registered rules against the provided events list."""
    all_findings = []
    for rule_fn in RULES:
        try:
            findings = rule_fn(events)
            if findings:
                print(f"[Detections] {rule_fn.__name__}: {len(findings)} finding(s)")
            all_findings.extend(findings)
        except Exception as ex:
            print(f"[Detections] Error in {rule_fn.__name__}: {ex}")
    return all_findings