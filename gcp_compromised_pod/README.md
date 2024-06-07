# Compromised GCP Pod

## Scenario
In this document, we run through some general response steps of how to perform an Incident Response and Forensic Process for a GCP pod already assumed to be compromised. We will also extend the analysis to the associated GKE node on which pod is running to validate if the node may have been compromised.

We will endeavour to use CLI commands, where possible, to perform analysis unless it is not possible to use CLI or the information more easily available through a UI.

This scenario comprises of a GCP kubernetes cluster `test-cluster-1` running with 2 nodes, and 2 pods `test-pod1` and `test-pod2` in `us-central1` region in project `citric-snow-362912`

We will assume that detections are already in place within pods to indicate that `test-pod1` is compromised and needs to be contained, analysed and remediated/

## Pre-requisites

For this scenario, we will require:
- Access to a GCP account with sufficient privileges to setup the multi-node Kubernetes cluster in region `us-central1`
- A forensics instance with Google Rapid Response (GRR) server setup already by following the steps [here](https://grr-doc.readthedocs.io/en/latest/installing-grr-server/index.html) along with other tools
- Access to Google Cloud SDK and kubernetes tools (such as `kubectl`)
- A variety of forensics tools such as docker explorer, etc. listed in the articles below
- Firewall rules e.g. SSH port is open (Optional, if live forensics needed)

## Forensics Instance Setup

### Ubuntu

In this case, we use `gcloud` to build a compute instance within the same project or separate project. 

```
gcloud compute instances create forensics-instance \
    --project=citric-snow-362912 \
    --zone=us-central1-c \
    --machine-type=e2-standard-4 \
    --network-interface=network-tier=PREMIUM,stack-type=IPV4_ONLY,subnet=default \
    --maintenance-policy=MIGRATE \
    --provisioning-model=STANDARD \
    --create-disk=auto-delete=yes,boot=yes,device-name=forensics-instance,image=projects/ubuntu-os-cloud/global/images/ubuntu-2204-jammy-v20240228,mode=rw,size=50,type=projects/citric-snow-362912/zones/us-central1-c/diskTypes/pd-balanced \
    --tags=http-server,https-server,rdp-server \
    --no-shielded-secure-boot \
    --shielded-vtpm \
    --shielded-integrity-monitoring \
    --labels=goog-ec-src=vm_add-gcloud \
    --reservation-affinity=any
```

We use `e2-standard-4` as the CPU core because visualization tools such as `timesketch` may require slightly higher vCPU, memory and storage. Also `HTTPS` traffic is enabled for tools like `timesketch` which may require accessible web service.

We then SSH into this instance via `gcloud` and note the default username that we SSH into (defined as `$USERNAME`):

```
gcloud compute ssh forensics-instance --zone=us-central1-c
```

We execute the script to install the forensics dependencies such as `container explorer`:
```
chmod +x ./install_forensics_deps.sh
sudo ./install_forensics_deps.sh
```

To setup RDP, setup the password for the user USERNAME:
```
passwd $USERNAME
```

Use `firefox` and RDP to access the websites via the username and password set via `passwd` as described in the steps above.

## Scenario Setup

To setup the scenario, we deploy a cluster called `$CLUSTER_NAME` with running with 3 `e2-medium` nodes in `us-central1-c` zone. Note that the size of the cluster is required to enforce the network policy as described [here](https://cloud.google.com/kubernetes-engine/docs/how-to/network-policy#np_no_effect)

```
$ gcloud beta container --project "citric-snow-362912" clusters create "test-cluster-1" --no-enable-basic-auth --cluster-version "1.27.8-gke.1067004" --release-channel "regular" --machine-type "e2-medium" --image-type "COS_CONTAINERD" --disk-type "pd-balanced" --disk-size "100" --metadata disable-legacy-endpoints=true --scopes "https://www.googleapis.com/auth/devstorage.read_only","https://www.googleapis.com/auth/logging.write","https://www.googleapis.com/auth/monitoring","https://www.googleapis.com/auth/servicecontrol","https://www.googleapis.com/auth/service.management.readonly","https://www.googleapis.com/auth/trace.append" --num-nodes "3" --logging=SYSTEM,WORKLOAD --monitoring=SYSTEM --enable-ip-alias --network "projects/citric-snow-362912/global/networks/default" --subnetwork "projects/citric-snow-362912/regions/us-central1/subnetworks/default" --no-enable-intra-node-visibility --default-max-pods-per-node "110" --security-posture=standard --workload-vulnerability-scanning=disabled --no-enable-master-authorized-networks --addons HorizontalPodAutoscaling,HttpLoadBalancing,GcePersistentDiskCsiDriver --enable-autoupgrade --enable-autorepair --max-surge-upgrade 1 --max-unavailable-upgrade 0 --binauthz-evaluation-mode=DISABLED --enable-managed-prometheus --enable-shielded-nodes --node-locations "us-central1-c" --enable-network-policy --location us-central1-c
```

We invoke cloud shell within the GCP console and attempt to authenticate to the cluster to use `kubectl`:
```
$ gcloud container clusters get-credentials test-cluster-1 --zone us-central1-c --project citric-snow-362912
```

Once the cluster has been setup, we prepare the deploy 2 pods `test-pod1` and `test-pod1` in `us-central1` region using [scenario_deployment.yaml](./scenario_deployment.yaml) with the following command:
```
$ kubectl apply -f scenario_deployment.yaml
```

We validate that the scenario's pods and nodes have been setup correctly using `kubectl`:
```
$ kubectl get pods
NAME                         READY   STATUS    RESTARTS   AGE
test-pod1-5589d96985-6vccs   1/1     Running   0          5m14s
test-pod2-fb578cd5c-42k2f    1/1     Running   0          5m14s

$ kubectl get nodes
NAME                                            STATUS   ROLES    AGE   VERSION
gke-test-cluster-2-default-pool-dec81310-6g2c   Ready    <none>   73m   v1.27.8-gke.1067004
gke-test-cluster-2-default-pool-dec81310-76c5   Ready    <none>   73m   v1.27.8-gke.1067004
```

## Containment

To contain the compromised pods, we need to start by isolating likely ingress network traffic to the pods if there are any deployed services by editing the unique custom labels added to the pods.

### Update labels

We list the labels applied on the pods via `kubectl`:
```
$ kubectl describe pods test-pod1-5589d96985-6vccs
Name:             test-pod1-5589d96985-6vccs
...
Labels:           app=test-pod1
                  pod-template-hash=5589d96985
...
```

We manually remove the `app=test-pod1` and any other labels created by us via `kubectl` which opens an editor to edit the `kubectl` definition. We will keep the `pod-template-hash` label to ensure replicaset is not affected:
```
$ kubectl edit pods test-pod1-5589d96985-6vccs
```

We recheck that the labels have been removed from the pod via `kubectl`:
```
$ kubectl describe pods test-pod1-5589d96985-6vccs
```

We deploy a customized label to identify the pod as `compromised` via `kubectl`:
```
$ kubectl label pods test-pod1-5589d96985-6vccs status=compromised
```

We check that the labels are correctly applied via `kubectl`:
```
$ kubectl describe pods test-pod1-5589d96985-6vccs
```

### Create Network Policy

We then create a new network policy to block all ingress and egress from the node using a [deny network policy](./deny_affected_all.yaml) via `kubectl`:

```
$ kubectl apply -f ./deny_affected_all.yaml
```

We identify and label the node to highlight that it is under investigation via `kubectl`
```
$ kubectl describe pods test-pod1-5589d96985-6vccs | grep -i "Node:"
...
Node:             gke-test-cluster-1-default-pool-ff0c640a-zj5v/10.128.0.37
...
$ kubectl label node gke-test-cluster-1-default-pool-ff0c640a-zj5v status=quarantine
```
### Cordon node

We also cordon the node to ensure that no new pods will be created on this node via `kubectl` and validate that scheduling is disabled for this node:
```
$ kubectl cordon gke-test-cluster-1-default-pool-ff0c640a-zj5v
$ kubectl get nodes
NAME                           READY   STATUS    RESTARTS   AGE
...
test-pod2-fb578cd5c-ccxkk      1/1     Running   0          33m
```

Check if the node on which the pod was compromised has been cordoned off via `kubectl`:
```
$ kubectl describe nodes gke-test-cluster-1-default-pool-ff0c640a-zj5v | grep -i "unschedulable:"
$ kubectl get nodes gke-test-cluster-1-default-pool-ff0c640a-zj5v | grep -i "SchedulingDisabled"
```

### Remove GKE Service Account Permissions and Annotations

We check if [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity) is enabled for the GKE cluster via `gcloud`:

```
# Check for valid workload config - if set, then workload identity is enabled
gcloud container clusters describe test-cluster-1 --zone=us-central1-c --format='value(workloadIdentityConfig.workloadPool)'
```

If workload identity is enabled on the GKE server, then we check the deployment `.yaml` files for the compromised app to identify any GKE service accounts might be in use under `spec`. For eg, we have `testsa` specificed as the GKE service account.
```
apiVersion: apps/v1 # Kubernetes API version for deployments
kind: Deployment # Kind of object being defined (Deployment)
metadata:
  name: test-pod4 # Name of the deployment
spec:
  replicas: 1 # Number of pods to create
  selector:
    ...
  template:
    ...
    spec:
      containers:
      - ...
      serviceAccountName: testsa
      nodeSelector:
        iam.gke.io/gke-metadata-server-enabled: "true"
...
```

We check the annotations assigned to the specific GKE service account `testsa` to identify the GCP IAM service account via `kubectl`. From output of below command, we notice that the GCP IAM service account is `testsa-iam@citric-snow-362912.iam.gserviceaccount.com`
```
kubectl describe serviceaccount testsa
Name:                testsa
Namespace:           default
Labels:              <none>
Annotations:         iam.gke.io/gcp-service-account: testsa-iam@citric-snow-362912.iam.gserviceaccount.com
...
```

We remove the annotations for workload identity via `kubectl`
```
kubectl patch serviceaccount testsa --type merge -p '{"metadata":{"annotations":{"iam.gke.io/gcp-service-account": null}}}'
```

To complete containment, we also check and remove IAM policy bindings from GCP IAM service account which can give privileged access which can be reinstated during recovery via `gcloud`:
```
# Check IAM policy bindings to identify Service account permissions at project level
gcloud projects get-iam-policy citric-snow-362912 | grep -A3 -B3 -i testsa-iam@citric-snow-362912.iam.gserviceaccount.com

# Check IAM policy bindings to identify privileged Service account permissions at service account level
 gcloud iam service-accounts get-iam-policy testsa-iam@citric-snow-362912.iam.gserviceaccount.com

# Remove any privileged permissions (e.g at project level, if we find storage admin permissions)
gcloud projects remove-iam-policy-binding citric-snow-362912 \
    --member "serviceAccount:testsa-iam@citric-snow-362912.iam.gserviceaccount.com" \
    --role "roles/storage.admin"
```


## Collection

Get the logs for the compromised pod via `kubectl`:

```
kubectl logs test-pod1-558b84995b-djbkk
```

### Live Collection

If SSH access is allowed to the node via VPC firewall rule, we attempt to SSH into the node for live forensics via `gcloud`:
```
gcloud compute ssh gke-test-cluster-1-default-pool-fe89d68e-g3fl
```

### Offline Collection

We will attempt to take a snapshot of the disk on the compute node `gke-test-cluster-1-default-pool-fe89d68e-g3fl`, generate a disk from the node and then connect it to a separate forensics VM compute instance for analysis.

First, set the settings in which the GKE node is running via gcloud:
```
gcloud config set compute/zone us-central1-c
gcloud config set compute/region us-central1
```

We can leverage `dftimewolf` to automate majority of the manual steps, including creation of the VM that are listed below for offline collection:
```
cd /opt/dftimewolf
source venv/bin/activate
# Replace incident-id with $INCIDENT_ID
# Example: dftimewolf gcp_forensics --incident_id test-incident --instances gke-test-cluster-1-default-pool-fe89d68e-n7nz --all_disks --create_analysis_vm --zone us-central1-c citric-snow-362912 citric-snow-362912
dftimewolf gcp_forensics --incident_id $INCIDENT_ID  --instances $INSTANCE_WITH_DISKS_TO_COPY --all_disks --create_analysis_vm --zone $ANALYSIS_VM_ZONE $PROJECT_WITH_DISKS_TO_COPY ANALYSIS_VM_PROJECT
deactivate
```

If the forensics instance will be in same project and zone as the compromised node, we can create an instant snapshot of compute node `gke-test-cluster-1-default-pool-fe89d68e-n7nz` and build the disk from the instant snapshot via `gcloud`:
```
# Create an instant snapshot
gcloud compute instances describe gke-test-cluster-1-default-pool-fe89d68e-n7nz --format=json \
	| jq -r '.name' \
	| xargs -I {} gcloud beta compute instant-snapshot forensics-{} --source-disk={}

# build the disk to be attached to a forensics instance
gcloud compute instances describe gke-test-cluster-1-default-pool-fe89d68e-n7nz --format=json \
	| jq -r '.name' \
	| xargs -I {} gcloud beta compute disks create forensics-{} \
  --zone=us-central1-c \
  --source-instant-snapshot=forensics-{}
```

If the forensics instance will be in a different project to the compromised node, we need to first create a standard snapshot in the same project with compromised instance, make an image out of this snapshot, and then create a disk in the project with the forensics instance via `gcloud`:
```
# Create a standard snapshot from the instance
gcloud compute instances describe gke-test-cluster-1-default-pool-fe89d68e-n7nz --format=json \
	| jq -r '.name' \
	| xargs -I {} gcloud beta compute disks create forensics-{} \
  --zone=us-central1-c \
  --source-instant-snapshot=forensics-{}

# Create an image from the snapshot
gcloud compute instances describe gke-test-cluster-1-default-pool-fe89d68e-n7nz --format=json \
	| jq -r '.name' \
	| xargs -I {} gcloud compute images create forensics-{} --source-snapshot=forensics-{}

# Create the disk from the image into the new project (e.g. citric-rain-362912) which is different from image's project (e.g. citric-snow-362912)
gcloud compute instances describe gke-test-cluster-1-default-pool-fe89d68e-n7nz --format=json \
    | jq -r '.name' \
    | xargs -I {} gcloud compute disks create forensics-{} --image=forensics-{} --image-project=citric-snow-362912 --project=citric-rain-362912
```

Once a disk is available in the same project as the forensics instance, we attach the disk via `gcloud`: 
```
gcloud compute instances attach-disk forensics-instance \
  --disk forensics-gke-test-cluster-1-default-pool-fe89d68e-n7nz \
  --device-name forensicsdiskattachment \
  --zone us-central1-c
```

View the attached disks via `lsblk` to identify the attached partition (based on size) and then `mount` the disk. For example, we assume `/dev/sdc1` has the attached disk:
```
lsblk
sudo mkdir /mnt/data
sudo mount -o ro,noload,noexec /dev/sdc1 /mnt/data
```

## Analysis

### Live Analysis

We attempt to to get the `container ID` for compromised pod's container via `crictl` or `docker`:

```
crictl ps | grep -i 'test-pod1'
docker ps | grep -i 'test-pod1'
```

Apart from `kubectl`, we can view the logs for container from the node as well via `crictl` or `docker`:
```
sudo crictl logs 7d6fdca68f9cf
sudo docker logs 7d6fdca68f9cf
```

We can also exec into the running pod with the inbound and outbound network connectivity disabled for this pod:
```
crictl exec -it 7d6fdca68f9cf /bin/bash
docker exec -it 7d6fdca68f9cf /bin/bash
```

We can also detect changes to the container since creation from the image which can show anomalous file events via `docker`:
```
# Command only available in docker, not crictl
docker diff 7d6fdca68f9cf
```

Check the memory information to see any anomalous high CPU usage via `docker` or `crictl`: 
```
crictl stats 7d6fdca68f9cf
docker stats 7d6fdca68f9cf
```

We can then see the processes inside the systems consuming excessive CPU via `docker` or by execing into the container via `crictl`:
```
docker top 7d6fdca68f9cf
crictl exec -it 7d6fdca68f9cf /bin/bash
> top
```

### Mounting containers / disk

#### via container-explorer

After mounting the disk, we list all the containers from the mount point `/mnt/data` via `container-explorer`:
```
sudo /opt/container-explorer/bin/ce -i /mnt/data --support-container-data supportcontainer.yaml list containers > /tmp/containers.txt
# Search for the container ID for a specific container - assume it returns '0e08cb0483f0f50de38ff5796eb4fb49f8a4a54a9fccacb5c4a4bf9cec26fcf4' for 'test-pod1'
cat /tmp/containers.txt | grep -i 'test-pod1'
```

We can also mount all the containers for further analysis via `container-explorer`:
```
sudo mkdir /mnt/container
sudo /opt/container-explorer/bin/ce -i /mnt/data --support-container-data supportcontainer.yaml mount-all /mnt/container
```

### Building Timeline

#### via plaso / psteal / psort

We build a timeline for the analysis of the pod via the `psteal` command:
```
psteal.py --source /mnt/container/0e08cb0483f0f50de38ff5796eb4fb49f8a4a54a9fccacb5c4a4bf9cec26fcf4 -o l2tcsv -w /tmp/timeline.csv
```

We consolidate the logs using plaso's `psort` command on `plaso` output file from the previous command: 
```
psort.py -w test.log 20240305T004351-0e08cb0483f0f50de38ff5796eb4fb49f8a4a54a9fccacb5c4a4bf9cec26fcf4.plaso
```

Alternatively, we can use `timesketch` to also visualize the timeline by running the command below and connecting to console as described [here](https://github.com/google/timesketch/blob/master/docs/guides/admin/install.md): 

```
# Run only the first time to create a user called `timesketch` and set the password 
sudo docker compose exec timesketch-web tsctl create-user timesketch
```
#### via timesketch

We can transfer files to upload to timesketch locally (e.g. to home directory `~`) from forensics-instance if accessing via `gcloud`: 
```
gcloud compute scp forensics-instance:~/20240305T004351-0e08cb0483f0f50de38ff5796eb4fb49f8a4a54a9fccacb5c4a4bf9cec26fcf4.plaso ~ --zone=us-central1-c
```

When we have completed timeline analysis via `timesketch` we can takedown timesketch infrastructure via `docker-compose` : 
```
sudo docker compose down
```

### Check for unusual image pushes to Artifact Registry

#### via GCP Audit Logs

```
# protoPayload.resourceName contains the name of the docker image
protoPayload.methodName="Docker-StartUpload"
protoPayload.serviceName="artifactregistry.googleapis.com"
```

Taken from [here](https://kubenomicon.com/Initial_access/Compromised_image_in_registry.html)

## Eradication

## Recovery

## Automation

