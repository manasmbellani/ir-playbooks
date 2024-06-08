#!/bin/bash
HEADER_FILE="timestamp,"
USAGE="
Summary:
  Script to download the GCP Logs in CSV format with useful fields pre-extracted
Pre-requisites:
  jq: for parsing JSON logs
  gcloud: for running gcp command to read logs
Examples:
  To get all DNS log changes between the date 2024-06-07 - 2024-06-08 midnight time and writing it to CSV & JSON output files: 
    CLOUDSDK_CORE_ACCOUNT=abcd@abcd.com \
    CLOUDSDK_CORE_PROJECT=citric-snow-362912 \
    CLOUDSDK_COMPUTE_REGION=us-central1 \
    CLOUDSDK_COMPUTE_ZONE=us-central1-c \
    LOGGING_QUERY='protoPayload.serviceName=\"dns.googleapis.com\" AND protoPayload.methodName=\"dns.changes.create\"' \
    OUTFILE_CSV=out-gcp-logs.csv \
    OUTFILE_JSON=out-gcp-logs.json \
    START_DATE=\"2024-06-07\" \
    END_DATE=\"2024-06-08\" \
    ./get_gcp_logs.sh
"

echo "[*] Extracting logs for logging query: $LOGGING_QUERY for the period: $START_DATE - $END_DATE..."
#logging_query='timestamp >= "2024-06-07T00:00:00Z" AND timestamp <= "2024-06-08T23:59:59Z" AND protoPayload.serviceName="dns.googleapis.com" AND protoPayload.methodName="dns.changes.create"'
gcloud logging read  "$LOGGING_QUERY" --format json > "$OUTFILE_JSON"

echo "[*] Counting number of logs obtained..."
num_logs=$(jq -r ". | length" "$OUTFILE_JSON")

echo "[*] Parsing the logs downloaded via 'jq'..."




