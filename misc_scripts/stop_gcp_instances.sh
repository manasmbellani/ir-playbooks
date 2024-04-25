#!/bin/bash
for project in $(gcloud projects list --format='value[](PROJECT_ID)'); do
  for instance in $(yes | CLOUDSDK_CORE_PROJECT="$project" gcloud compute instances list --filter='status:RUNNING' --format='value[](NAME)'); do
    echo "[*] Stopping instance: $instance in project: $project..."
    yes | CLOUDSDK_CORE_PROJECT="$project" gcloud compute instances stop $instance
  done
done
