#!/bin/bash
# Summary
#   Script to download the GCP Logs in CSV format with useful fields pre-extracted
# Pre-requisites:
#   jq: for parsing JSON logs
#   gcloud: for running GCP commands to read logs
# Examples:
# To get all DNS log changes from the date 2024-06-07 - 2024-06-08 UTC midnight time and writing it to CSV & JSON output files:
#   CLOUDSDK_CORE_ACCOUNT=manasbellani@testgcpbusiness12345.com \
#   CLOUDSDK_CORE_PROJECT=citric-snow-362912 \
#   CLOUDSDK_COMPUTE_REGION=us-central1 \
#   CLOUDSDK_COMPUTE_ZONE=us-central1-c \
#   LOGGING_QUERY=protoPayload.serviceName="dns.googleapis.com" AND protoPayload.methodName="dns.changes.create" \
#   OUTFILE_CSV=out-gcp-logs.csv \
#   OUTFILE_JSON=out-gcp-logs.json \
#   START_DATE=2024-06-06 \
#   END_DATE=2024-06-09 \
#   ./get_gcp_logs.sh

HEADER_CSV="timestamp,log_type,log_name,severity,payload_type,principal_email,service_name,method_name,project_id,resource_name,text_payload,raw"
LOG_TYPE="gcp"

echo "[*] Creating output file: $OUTFILE_CSV if it exists..."
echo "$HEADER_CSV" > "$OUTFILE_CSV"

echo "[*] Extracting logs for logging query: $LOGGING_QUERY for the period: $START_DATE - $END_DATE..."
logging_query="timestamp >= \"$START_DATE""T00:00:00Z\" AND timestamp <= \"$END_DATE""T00:00:00Z\""
if [ ! -z "$LOGGING_QUERY" ]; then
    logging_query="$logging_query AND $LOGGING_QUERY"
fi
gcloud logging read  "$logging_query" --format json > "$OUTFILE_JSON"

echo "[*] Counting number of logs obtained..."
num_logs=$(jq -r ". | length" "$OUTFILE_JSON")
echo "[*] $num_logs GCP Logs downloaded"

echo "[*] Parsing the logs downloaded via 'jq'..."
IFS=$'\n'
for i in $(seq 0 $(($num_logs-1)) ); do
  echo "[*] Parsing log: $i via 'jq' and writing to file: $OUTFILE_CSV..."
  log=$(jq -r ".[$i]" "$OUTFILE_JSON")
  timestamp=$(echo "$log" | jq -r ".timestamp")
  log_name=$(echo "$log" | jq -r ".logName")
  severity=$(echo "$log" | jq -r ".severity")
  payload_type=$(echo "$log" | jq -r ".protoPayload.\"@type\"")
  principal_email=$(echo "$log" | jq -r ".protoPayload.authenticationInfo.principalEmail" )
  service_name=$(echo "$log" | jq -r ".protoPayload.serviceName")
  method_name=$(echo "$log" | jq -r ".protoPayload.methodName")
  project_id=$(echo "$log" | jq -r ".resource.labels.project_id")
  resource_name=$(echo "$log" | jq -r ".protoPayload.resourceName")
  text_payload=$(echo "$log" | jq -r ".textPayload")
  raw=$(echo "$log" | tr -s '\"' "'" | tr -d "\n\r")
  echo "\"$timestamp\",\"$LOG_TYPE\",\"$log_name\",\"$severity\",\"$payload_type\",\"$principal_email\",\"$service_name\",\"$method_name\",\"$project_id\",\"$resource_name\",\"$text_payload\",\"$raw\"" >> "$OUTFILE_CSV"
done
