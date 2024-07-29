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

Optionally, we can also create a basic container using an image `ubuntu` called `ubuntupod`:

```
kubectl run --rm -it --image=ubuntu ubuntupod /bin/bash 
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

### Remove service account permissions assigned to the node (Optional)

#### via kubectl / gcloud

```
# Identify the nodes in kubernetes to check
kubectl get nodes

# Get the service account linked with the affected kubernetes node
gcloud compute instances describe $NODE_NAME --zone=us-central1-c --format='value(serviceAccounts.email)'

# Get the policy bindings linked with this service account
gcloud iam service-accounts get-iam-policy $SERVICE_ACCOUNT
```

## Collection

### Get logs for pod

#### via kubectl

Get the logs for the compromised pod via `kubectl`:

```
kubectl logs test-pod1-558b84995b-djbkk
```

### Get all logs from GCP

#### via gcloud / get_gcp_logs.sh

To download all logs between the period `2024-06-08` and `2024-06-10` UTC time as JSON and CSV files via `get_gcp_logs.sh`:
```
CLOUDSDK_CORE_ACCOUNT=manasbellani@testgcpbusiness12345.com \
    CLOUDSDK_CORE_PROJECT=citric-snow-362912 \
    CLOUDSDK_COMPUTE_REGION=us-central1 \
    CLOUDSDK_COMPUTE_ZONE=us-central1-c \
    LOGGING_QUERY="" \
    OUTFILE_CSV=out-gcp-logs.csv \
    OUTFILE_JSON=out-gcp-logs.json \
    START_DATE=2024-06-08 \
    END_DATE=2024-06-10 \
    ./get_gcp_logs.sh
```

### Live Collection Access

#### via ssh / gcloud
If SSH access is allowed to the node via VPC firewall rule, we attempt to SSH into the node for live forensics via `gcloud`:
```
gcloud compute ssh gke-test-cluster-1-default-pool-fe89d68e-g3fl
```

### via Daemonset

Connect to the Kubernetes nodes via a daemonset if not possible to SSH into the host:
```
# Get the nodes in the cluster
kubectl get nodes

# Apply the labels on the NODE
kubectl label nodes $NODE_NAME grr=installed

# Deploy the daemonset to be used on the node
kubectl apply -f launch_forensics_daemonset.yaml

# Connect to the daemonset launched with the host mount 
kubectl exec -it $POD_NAME /bin/bash

# Get shell onto the node inside the container
chroot /hostroot /bin/bash 
```
Taken from [here](https://osdfir.blogspot.com/2020/10/deploying-grr-to-kubernetes-for.html)

### Getting cluster node backup

#### via zip

```
# Assuming we have a /hostroot mount as per privileged container
zip -ry /tmp/file.zip /hostroot/home/
```

#### via dd

See [here](../linux_compromised_host/README.md#taking-disk-image-offline)

### Getting important kubernetes (GKE) events

#### via via kubectl

```
kubectl get events --all
```

### Extract Roles and rolebindings for ALL roles

#### via kubectl

```
kubectl get rolebinding,clusterrolebinding -o json
```

### Taking Memory Image of Kubernetes Nodes (Live)

See [here](../linux_compromised_host/README.md#taking-memory-image-live)

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

We can save images of running containers for further analysis remotely(supported only in `docker`):
```
docker commit <container-id> <new-image-name>
docker save -o <path-to-save-image.tar> <new-image-name>
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

### Check mutating webhook configuration creations

- Admission controllers are used to control resource creation within a cluster prior to authentication and authorization
- Controllers are validating, where requests are accepted/denied, or mutating, where requests are modified
- Attacker can have requests sent to their mutating webhook server to potentially escalate privileges or establish persistence e.g. create pods with vulnerable images
- Request the engineers to validate if the mutating webhook configurations are expected

#### via kubectl

```
kubectl get MutatingWebhookConfiguration
```

#### via GCP Logging Explorer

```
"MutatingWebhookConfiguration" "create"
```

Taken from here: [1](https://medium.com/@noah_h/top-offensive-techniques-for-kubernetes-a71399d133b2#8c82), [2](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/abusing-roles-clusterroles-in-kubernetes#malicious-admission-controller)

### Check for unusual roles / cluster roles created

Can be indicative of abuse of cluster roles if attacker does create unusual cluster roles

#### via GCP Logging Explorer Logs

```
# Examples: protoPayload.methodName="io.k8s.authorization.rbac.v1.roles.create", protoPayload.methodName="io.k8s.authorization.rbac.v1.clusterroles.create"
protoPayload.serviceName="k8s.io"
protoPayload.methodName:"clusterroles.create" OR protoPayload.methodName:"roles.create.create"
```

### Check for impersonation attempts for cluster logs

This can be used to detect impersonation attempts such as leveraging cluster admin OR other interesting accounts to conduct activity.

#### via GCP Logging Explorer logs

```
# Look for authentication authority (impersonation) attempts when leveraging 'kubectl' commands
protoPayload.authenticationInfo.authoritySelector:*
protoPayload.serviceName="k8s.io" OR (protoPayload.requestMetadata.callerSuppliedUserAgent:* AND protoPayload.requestMetadata.callerSuppliedUserAgent:"kubectl")
```

Taken from [here](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/abusing-roles-clusterroles-in-kubernetes/kubernetes-roles-abuse-lab)

### Check for pods with common names, but running unusual images

Just naming a pod something that doesn't stand out is a great way to hide among "known good" pods.

#### via kubectl, yq

```
# Returns pods across ALL namespaces and gets the corresponding image along with the pod
# Look for pods running unusual images
kubectl get pods -A -o yaml | yq -o csv -r ".items[] | [.metadata.name,.spec.containers[].image]"
```

Taken from [here](https://kubenomicon.com/Defense_evasion/Pod_name_similarity.html)

### Check for unusual software

#### via GCP Audit Logs/

Example keyword searches to search for various software such as:
- `peirates` which can detect interesting malicious software:
```
peirates
logName="projects/citric-snow-362912/logs/stdout"
```

### Check for privileged GCP Kubernetes Pods

#### via GCP Audit logs / Audit Logs

```
protoPayload.request.spec.containers.securityContext.privileged="true"
protoPayload.methodName:"pods.create"
protoPayload.serviceName="k8s.io"
```

#### via kubectl

```
kubectl get pods priv-pod -o yaml | grep -i "privileged:"
```

#### via GCP Audit logs / Audit Logs

### Check gcloud cli commands

#### via GCP Audit Logs / user agent

```
# protoPayload.requestMetadata.callerSuppliedUserAgent has the commands run. Service can be broad for capturing commands
protoPayload.serviceName="compute.googleapis.com"
```

### Check serial Port console

#### via GCP Audit Logs

```
# Detect enabling of Serial Port Console project-wide
# protoPayload.requestMetadata.callerSuppliedUserAgent, protoPayload.authenticationInfo.principalEmail provides details about user that performed action
protoPayload.serviceName="compute.googleapis.com"
protoPayload.metadata.projectMetadataDelta.addedMetadataKeys="serial-port-enable" OR protoPayload.request."Metadata Keys Added"="serial-port-enable"
protoPayload.methodName:"compute.instances.setMetadata" OR protoPayload.methodName:"compute.projects.setCommonInstanceMetadata"
```

Addition of SSH Keys is the detection for start of serial port console, same as described [here](#ssh-attempts-on-vm-instance)

### SSH Attempts on VM Instance

#### via GCP Audit Logs / setMetadata

```
# Starting of serial port console / SSH for the first time (by addition of SSH keys to the VM instance)
protoPayload.serviceName="compute.googleapis.com"
protoPayload.methodName:"compute.instances.setMetadata"
protoPayload.metadata.instanceMetadataDelta.modifiedMetadataKeys="ssh-keys"
```

#### via GCP Audit Logs / user agent

```
protoPayload.serviceName="compute.googleapis.com"
protoPayload.requestMetadata.callerSuppliedUserAgent:"ssh"
```

### Check creation of kubernetes service accounts

#### via GCP Audit Logs

```
# protoPayload.request.metadata.name contains the name of the kubernetes service account being created
protoPayload.methodName="serviceaccounts.create"
```

### Check the Keys created for service account

#### via GCP Audit Logs

```
# Look for resource.labels.email_id field for the name of the service account for which keys are created, protoPayload.resource.name contains the ID of the service account created
protoPayload.methodName:"CreateServiceAccountKey"
```

### Check unusual activity from useragents

Can be indicative of interesting behavior when examined over a long period for eg. `(gzip),gzip(gfe)` for `prowler`

#### via GCP Audit Logs

Review the GCP Audit Logs with following fields
```
protoPayload.requestMetadata.callerSuppliedUserAgent
```

### Check unusual list activity from users or service accounts

Can be used to indicate recon / scanning activity from tools like `prowler`

#### via GCP Audit Logs

```
protoPayload.methodName: list
protoPayload.authenticationInfo.principalEmail:"iam.gserviceaccount.com"
-protoPayload.serviceName="k8s.io"
-protoPayload.authenticationInfo.principalEmail:"container-engine-robot.iam.gserviceaccount.com"
```

### Get all roles and cluster roles

Can be used to detect via the running pods and deployments any cluster abuse

#### via kubectl

```
kubectl get roles -A -o yaml
kubectl get clusterroles -A -o yaml
```

### List running containers

#### via kubectl

```
# To look for interesting container such as ones running exposed sensitive interfaces, such as dashboards
kubectl get pods -A | grep -i dash
```

Taken from [here](https://kubenomicon.com/Initial_access/Exposed_sensitive_interfaces.html)

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
cd /opt/timesketch
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

### Look for cron job persistence 

Can help detect persistence within GKE environment or cryptominer deployments.

Taken from [here](https://kubenomicon.com/Persistence/Kubernetes_cronjob.html)


#### via kubectl

```
kubectl get cronjob
```

#### via GCP Audit Logs / cronjob.create

Detect creation of Kubernetes GKE cron job

```
# protoPayload.resourcename has the name of the cronjob created, protoPayload.request.metadata.annotations.kubectl.kubernetes.io/last-applied-configuration has the details of the cronjob
protoPayload.serviceName="k8s.io"
protoPayload.methodName:"cronjobs.create"
```

#### via GCP Audit Logs / cronjob.status.update

Detect executions of Kubernetes GKE cron job

```
# protoPayload.resourcename has the name of the cronjob executed,  protoPayload.request.metadata.annotations.kubectl.kubernetes.io/last-applied-configuration has the details of the cronjob, protoPayload.response.status.lastSuccessfulTime contains the last execution time, protoPayload.status.code is whether the cron job was successful
protoPayload.serviceName="k8s.io"
protoPayload.methodName="io.k8s.batch.v1.cronjobs.status.update"
```

### Check for unusual pods deployed on kubernetes

#### via GCP Audit Logs

```
# protoPayload.resourceName contains the pod name
# protoPayload.requestMetadata.callerSuppliedUserString
protoPayload.methodName:"pods.attach.create"
protoPayload.serviceName="k8s.io"
```

### Check for unusual pods which have hostPath mount

#### via GCP Audit Logs

```
# Attribute protoPayload.request.metadata.annotations."kubectl.kubernetes.io/last-applied-configuration" has more details
protoPayload.request.metadata.annotations."kubectl.kubernetes.io/last-applied-configuration":"hostPath"
protoPayload.methodName="io.k8s.core.v1.pods.create"
protoPayload.serviceName="k8s.io"
```

Taken from [here](https://kubenomicon.com/Persistence/Writable_hostPath_mount.html)

### Check for exec attempts into kubernetes pods

#### via GCP Audit Logs

```
# protoPayload.resourceName contains the pod name
# protoPayload.requestMetadata.callerSuppliedUserString
protoPayload.methodName:"pods.exec.create"
protoPayload.serviceName="k8s.io"
```

### Check for unusual image pushes to Artifact Registry

#### via GCP Audit Logs

```
# protoPayload.resourceName contains the name of the docker image
protoPayload.methodName="Docker-StartUpload"
protoPayload.serviceName="artifactregistry.googleapis.com"
```

Taken from [here](https://kubenomicon.com/Initial_access/Compromised_image_in_registry.html)

### Check if SSH running inside pod

#### via GCP Audit Logs

```
# 
sshd
logName:"logs/stdout"
labels."k8s-pod/run":*
```

### Check if attempt made to list or get secrets

#### via GCP Audit Logs

```
# Check the user / service attempting to list secrets - protoPayload.authenticationInfo.principalEmail
protoPayload.methodName:"secrets.list"
protoPayload.serviceName="k8s.io"
```

```
# Check the user / service attempting to list secrets - protoPayload.authenticationInfo.principalEmail
# Check the secret which is being read
protoPayload.methodName:"secrets.get"
protoPayload.serviceName="k8s.io"
```

### Check for static reserved IP addresses 

External IP addresses are interesting as they could indicate external assets being created which could be compromised. Helps with asset discovery.

#### via GCP Audit Logs

```
# Asset name is present in protoPayload.resourceName
protoPayload.methodName:"compute.globalAddresses.insert"
protoPayload.serviceName="compute.googleapis.com"
```

### Check for external DNS record entry

External DNS record entry can help detect domains

#### via GCP Audit Logs

```
# `protoPayload.request.change.additions.name` contains the DNS / domain record added
protoPayload.serviceName="dns.googleapis.com"
protoPayload.methodName="dns.changes.create"
```

### Check for additional GCP domain registered

External DNS record entry can help detect new domains that were registered

#### via GCP Audit Logs
```
# protoPayload.request.domainName is the domain name that is being registered
proto_payload.method_name:"Domains.RegisterDomain"
protoPayload.serviceName="domains.googleapis.com"
```

## Eradication

### Drain the kubernetes nodes

So that any existing pods on these nodes are removed.

#### via kubectl

```
kubectl drain --ignore-daemonsets $NODE_NAME
```

Then, power-off / terminate the VM.

If we wish to undo this step, 

```
kubectl uncordon $NODE_NAME
```

### Destroy the pod

#### via kubectl

```
kubectl delete pods $POD_NAME 
```

## Recovery

## Automation

