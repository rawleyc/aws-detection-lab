import boto3
import gzip
import os
from datetime import datetime, timezone, timedelta

BUCKET = "my-instance-logs-123599503689-eu-central-1-an"
REGION = "eu-central-1"
ACCOUNT = "123599503689"

STATE_FILE = os.path.join(os.path.dirname(__file__), ".flowlog_state")

# Default VPC flow log field order
FIELDS = [
    "version", "account_id", "interface_id", "src_addr", "dst_addr",
    "src_port", "dst_port", "protocol", "packets", "bytes",
    "start", "end", "action", "log_status"
]

PROTOCOL_MAP = {"6": "TCP", "17": "UDP", "1": "ICMP"}


def load_processed_keys():
    if not os.path.exists(STATE_FILE):
        return set()
    with open(STATE_FILE) as f:
        return set(line.strip() for line in f if line.strip())


def save_processed_key(key):
    with open(STATE_FILE, "a") as f:
        f.write(key + "\n")


def list_recent_keys(s3, hours=2):
    # Flow logs can land under various prefixes depending on setup
    prefixes = [
        f"AWSLogs/{ACCOUNT}/vpcflowlogs/{REGION}/",
        f"vpc-flow-logs/",
        "",  # fallback: scan bucket root
    ]
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    keys = []
    paginator = s3.get_paginator("list_objects_v2")

    for prefix in prefixes:
        try:
            for page in paginator.paginate(Bucket=BUCKET, Prefix=prefix):
                for obj in page.get("Contents", []):
                    if obj["LastModified"] >= cutoff and obj["Key"] not in keys:
                        keys.append(obj["Key"])
            if keys:
                break  # found files under this prefix, stop trying others
        except Exception:
            continue

    return keys


def parse_line(line, header_fields=None):
    fields = header_fields or FIELDS
    parts = line.strip().split(" ")
    if len(parts) != len(fields):
        return None
    record = dict(zip(fields, parts))

    if record.get("version") == "version":
        return None

    # Handle both hyphenated (custom header) and positional field names
    def g(hyphen, underscore):
        return record.get(hyphen) or record.get(underscore)

    return {
        "source": "flowlog",
        "time": g("start", "start"),
        "src_addr": g("srcaddr", "src_addr"),
        "dst_addr": g("dstaddr", "dst_addr"),
        "src_port": g("srcport", "src_port"),
        "dst_port": g("dstport", "dst_port"),
        "protocol": PROTOCOL_MAP.get(g("protocol", "protocol") or "", g("protocol", "protocol")),
        "protocol_num": g("protocol", "protocol"),
        "packets": g("packets", "packets"),
        "bytes": g("bytes", "bytes"),
        "action": g("action", "action"),
        "interface_id": g("interface-id", "interface_id"),
        "log_status": g("log-status", "log_status"),
        "raw": record,
    }

def fetch_events(s3, key):
    obj = s3.get_object(Bucket=BUCKET, Key=key)
    body = obj["Body"]

    if key.endswith(".gz"):
        with gzip.GzipFile(fileobj=body) as gz:
            lines = gz.read().decode("utf-8").splitlines()
    else:
        lines = body.read().decode("utf-8").splitlines()

    # Check if first line is a custom header
    header_fields = None
    if lines and lines[0].startswith("version"):
        header_fields = lines[0].strip().split(" ")
        lines = lines[1:]

    events = []
    for line in lines:
        if not line.strip() or line.startswith("#"):
            continue
        record = parse_line(line, header_fields)
        if record:
            events.append(record)
    return events


def ingest(hours=2):
    s3 = boto3.client("s3", region_name=REGION)
    processed = load_processed_keys()
    events = []

    keys = list_recent_keys(s3, hours=hours)
    new_keys = [k for k in keys if k not in processed]

    if not new_keys:
        print(f"[FlowLogs] No new log files in the last {hours}h")
        return events

    print(f"[FlowLogs] Processing {len(new_keys)} new file(s)")
    for key in new_keys:
        try:
            records = fetch_events(s3, key)
            events.extend(records)
            save_processed_key(key)
        except Exception as e:
            print(f"[FlowLogs] Error reading {key}: {e}")

    print(f"[FlowLogs] Loaded {len(events)} flow records")
    return events


if __name__ == "__main__":
    import json
    for e in ingest()[:10]:
        print(json.dumps(e, indent=2, default=str))