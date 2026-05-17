import json
import os
from datetime import datetime, timezone

OUTPUT_DIR = os.path.join(os.path.dirname(__file__))

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def write_markdown(findings, cloudtrail_count, flowlog_count):
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    now = datetime.now(timezone.utc)
    filename = os.path.join(OUTPUT_DIR, f"findings_{now.strftime('%Y%m%d_%H%M%S')}.md")

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 4))

    severity_counts = {}
    for f in findings:
        s = f.get("severity", "INFO")
        severity_counts[s] = severity_counts.get(s, 0) + 1

    lines = [
        f"# AWS Cloud Detection Lab — Findings Report",
        f"",
        f"**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"",
        f"## Summary",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| CloudTrail events processed | {cloudtrail_count} |",
        f"| Flow log records processed | {flowlog_count} |",
        f"| Total findings | {len(findings)} |",
    ]

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(sev, 0)
        lines.append(f"| {sev} findings | {count} |")

    lines += ["", "## Findings", ""]

    if not findings:
        lines.append("No findings in this run.")
    else:
        for i, f in enumerate(sorted_findings, 1):
            sev = f.get("severity", "INFO")
            lines += [
                f"### {i}. {f.get('rule')}",
                f"",
                f"- **Severity:** {sev}",
                f"- **Time:** {f.get('time', 'unknown')}",
                f"- **Detail:** {f.get('detail')}",
                f"- **MITRE ATT&CK:** `{f.get('mitre', 'N/A')}`",
                f"",
            ]

    lines += [
        "## Detection Rules Used",
        "",
        "| Rule | Source | MITRE Technique |",
        "|------|--------|-----------------|",
        "| IAM privilege escalation | CloudTrail | T1078, T1098 |",
        "| Repeated auth failures | CloudTrail | T1110 |",
        "| Root account usage | CloudTrail | T1078.004 |",
        "| CloudTrail tampering | CloudTrail | T1562.008 |",
        "| Unusual region activity | CloudTrail | T1535 |",
        "| Port scan | VPC Flow Logs | T1046 |",
        "| SSH brute force | VPC Flow Logs | T1110.003 |",
        "| Unusual outbound connections | VPC Flow Logs | T1071, T1041 |",
        "| Large data transfer | VPC Flow Logs | T1048 |",
        "",
    ]

    with open(filename, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    print(f"[Report] Written to {filename}")
    return filename