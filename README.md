# AWS Cloud Detection Lab

A cloud-native threat detection pipeline built on AWS free tier. Ingests CloudTrail and VPC Flow Log events from S3, runs detection rules mapped to MITRE ATT&CK, and produces timestamped findings reports.

Deployed and validated against real traffic — detected active internet scanning within hours of the EC2 instance going live.

---

## What it does

Pulls log data from two AWS sources on a configurable look-back window, normalises the events into a shared format, runs 9 detection rules across both sources, and writes a severity-sorted markdown findings report.

```mermaid
flowchart LR
  CT[CloudTrail<br/>(API/IAM events)] --> CTB[(CloudTrail S3 bucket)]
  FL[VPC Flow Logs<br/>(network)] --> FLB[(Flow Logs S3 bucket)]
  CTB --> ING[Ingestors]
  FLB --> ING
  ING --> RULES[Rules engine]
  RULES --> REP[Reporter]
```

The pipeline runs locally using boto3 with read-only IAM credentials. No extra AWS services required beyond the free tier infrastructure already used to generate the logs.

---

## Infrastructure

Built on AWS free tier in `eu-central-1`:

- VPC with public subnet
- EC2 t2.micro (Amazon Linux 2023)
- CloudTrail trail writing management events to S3
- VPC Flow Logs writing network records to a separate S3 bucket
- Dedicated IAM user with `s3:GetObject` and `s3:ListBucket` on both buckets only

---

## Detection rules

| Rule | Source | Severity | MITRE ATT&CK |
|------|--------|----------|--------------|
| IAM privilege escalation | CloudTrail | HIGH | T1078, T1098 |
| Repeated auth failures | CloudTrail | MEDIUM | T1110 |
| Root account usage | CloudTrail | HIGH | T1078.004 |
| CloudTrail tampering | CloudTrail | CRITICAL | T1562.008 |
| Unusual region activity | CloudTrail | LOW | T1535 |
| Port scan | VPC Flow Logs | MEDIUM | T1046 |
| SSH brute force | VPC Flow Logs | HIGH | T1110.003 |
| Unusual outbound connections | VPC Flow Logs | HIGH | T1071, T1041 |
| Large data transfer | VPC Flow Logs | MEDIUM | T1048 |

Rules are functions registered in `detections/rules.py`. Adding a new rule means writing a function and appending it to the `RULES` list — no other changes needed.

---

## Sample findings

From a real run on 2026-05-17, approximately 3 hours after the EC2 instance was launched:

```
Total findings: 10
CRITICAL: 1  |  HIGH: 1  |  MEDIUM: 8  |  LOW: 0

1. CloudTrail tampering [CRITICAL]
   PutEventSelectors by root from 79.184.227.217
   MITRE: T1562.008

2. Root account usage [HIGH]
   272 API calls (83 unique actions) from 79.184.227.217
   MITRE: T1078.004

3. Port scan detected [MEDIUM]
   51.159.110.167 -> 172.31.2.25: 196 rejected ports
   MITRE: T1046

4. Port scan detected [MEDIUM]
   79.184.227.217 -> 172.31.2.25: 590 rejected ports  <- intentional nmap test
   MITRE: T1046

5-10. Port scan detected [MEDIUM]
   5 additional external IPs scanning the instance (organic internet noise)
   MITRE: T1046
```

Findings 3 and 5-10 were not intentionally generated — they are real automated scanners that hit the public IP within hours of launch. The pipeline detected them without any additional configuration.

---

## Project structure

```
aws-cloud-detection-lab/
├── main.py                          # entry point, orchestrates everything
├── requirements.txt
├── ingestors/
│   ├── cloudtrail_ingestor.py       # boto3 S3 poller, gzip+JSON parser, state tracking
│   └── flowlog_ingestor.py          # boto3 S3 poller, space-delimited parser, state tracking
├── detections/
│   └── rules.py                     # 9 detection rules + rule registry
└── output/
    └── reporter.py                  # markdown report writer
```

State files (`.cloudtrail_state`, `.flowlog_state`) track processed S3 keys to prevent duplicate alerts across runs.

---

## Setup

**Prerequisites:** Python 3.9+, an AWS account, boto3

```bash
pip install -r requirements.txt
aws configure
# Access Key ID: <your IAM user key>
# Secret Access Key: <your IAM user secret>
# Default region: eu-central-1
# Default output format: json
```

**IAM permissions required (minimum):**

```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:ListBucket"],
  "Resource": [
    "arn:aws:s3:::your-cloudtrail-bucket",
    "arn:aws:s3:::your-cloudtrail-bucket/*",
    "arn:aws:s3:::your-flowlogs-bucket",
    "arn:aws:s3:::your-flowlogs-bucket/*"
  ]
}
```

---

## Usage

```bash
# Process last 2 hours (default)
python main.py

# Process last 24 hours
python main.py --hours 24

# Print findings to console only, no report file
python main.py --dry-run
```

Reports are written to `output/findings_YYYYMMDD_HHMMSS.md`.

---

## Generating test events

**Trigger port scan detection** (from your local machine):
```bash
nmap -sS -p 1-1000 <ec2-public-ip>
```

**Trigger CloudTrail detections** (repeated auth failures):
```powershell
for ($i=0; $i -lt 10; $i++) {
    aws iam get-role --role-name NonExistentRole 2>$null
}
```

**Trigger root account detection:** log into the AWS console as root — CloudTrail captures every API call made during the session.

Wait 10-15 minutes for logs to land in S3, then run `python main.py`.

---

## Key design decisions

**Two separate S3 buckets** — CloudTrail and VPC Flow Logs write to separate buckets. The ingestors handle each independently and merge events into a single normalised list before rules run.

**State-based deduplication** — processed S3 keys are tracked in local state files. Re-running the pipeline on the same time window will not re-alert on already-processed files.

**Alert deduplication in rules** — the root account rule groups all root API calls into a single finding with a count and unique action summary, avoiding alert fatigue from the 200+ individual API calls a typical console session generates.

**Read-only credentials** — the IAM user used at runtime has no write permissions anywhere. It cannot modify logs, delete findings, or interact with the EC2 instance.

---

## Design Decisions & Tradeoffs

**Python + boto3 instead of a heavy SIEM** — To minimize cloud compute costs while demonstrating raw API log ingestion and parsing mechanics. This keeps the lab lightweight, free-tier friendly, and focused on detection logic rather than operating a separate SIEM stack.

---

## Potential extensions

- Lambda function triggered on S3 put events (remove the polling loop entirely)
- SNS/email alerting for CRITICAL findings
- Wazuh integration to correlate with host-based events from the EC2 instance
- Additional rules: S3 bucket policy changes, new IAM user creation, security group modifications
