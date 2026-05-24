import boto3
import gzip
import json
import os
from datetime import datetime, timezone, timedelta

REGION = "eu-central-1"
ACCOUNT = "123599503689"
ssm = boto3.client("ssm", region_name=REGION)
BUCKET = ssm.get_parameter(
    Name="/logging/cloudtrail/bucket")
    ["Parameter"]["Value"]

# Tracks which keys we've already processed so we don't re-alert
STATE_FILE = os.path.join(os.path.dirname(__file__), ".cloudtrail_state")


def load_processed_keys():
    if not os.path.exists(STATE_FILE):
        return set()
    with open(STATE_FILE) as f:
        return set(line.strip() for line in f if line.strip())


def save_processed_key(key):
    with open(STATE_FILE, "a") as f:
        f.write(key + "\n")


def list_recent_keys(s3, hours=2):
    prefix = f"AWSLogs/{ACCOUNT}/CloudTrail/{REGION}/"
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    keys = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            if obj["LastModified"] >= cutoff:
                keys.append(obj["Key"])
    return keys


def fetch_events(s3, key):
    obj = s3.get_object(Bucket=BUCKET, Key=key)
    with gzip.GzipFile(fileobj=obj["Body"]) as gz:
        data = json.loads(gz.read())
    return data.get("Records", [])


def normalise(record):
    return {
        "source": "cloudtrail",
        "time": record.get("eventTime"),
        "event_name": record.get("eventName"),
        "event_source": record.get("eventSource"),
        "user": (record.get("userIdentity") or {}).get("arn", "unknown"),
        "user_type": (record.get("userIdentity") or {}).get("type", "unknown"),
        "source_ip": record.get("sourceIPAddress"),
        "region": record.get("awsRegion"),
        "error_code": record.get("errorCode"),
        "error_message": record.get("errorMessage"),
        "request_params": record.get("requestParameters"),
        "raw": record,
    }


def ingest(hours=2):
    s3 = boto3.client("s3", region_name=REGION)
    processed = load_processed_keys()
    events = []

    keys = list_recent_keys(s3, hours=hours)
    new_keys = [k for k in keys if k not in processed]

    if not new_keys:
        print(f"[CloudTrail] No new log files in the last {hours}h")
        return events

    print(f"[CloudTrail] Processing {len(new_keys)} new file(s)")
    for key in new_keys:
        try:
            records = fetch_events(s3, key)
            for r in records:
                events.append(normalise(r))
            save_processed_key(key)
        except Exception as e:
            print(f"[CloudTrail] Error reading {key}: {e}")

    print(f"[CloudTrail] Loaded {len(events)} events")
    return events


if __name__ == "__main__":
    for e in ingest():
        print(json.dumps(e, indent=2, default=str))