# Compromised GCP Pod

## Scenario
In this document, we run through some general response steps of how to perform an Incident Response and Forensic Process for a GCP pod already assumed to be compromised.

We will endeavour to use CLI commands, where possible, to perform analysis unless it is not possible to use CLI or the information more easily available through a UI.

This scenario comprises of a GCP kubernetes cluster `test-cluster-1` running with 2 nodes, and 2 pods `test-pod1` and `test-pod2` in `us-central1` region in project `citric-snow-362912`

We will assume that detections are already in place within pods to indicate that `test-pod1` is compromised and needs to be contained, analysed and remediated/

## Pre-requisites

For this scenario, we will require:
- Access to a GCP account with sufficient privileges to setup the multi-node Kubernetes cluster in region `us-central1`
- A Google Rapid Response (GRR) setup already by following the steps [here](https://grr-doc.readthedocs.io/en/latest/installing-grr-server/index.html)
- Access to Google Cloud SDK and kubernetes tools (such as `kubectl`)
- A variety of forensics tools such as docker explorer, etc. listed in the articles below

## Scenario Setup

To setup the scenario, we deploy a cluster called `test-cluster-1` with running with 2 `e2-micro` nodes in `us-central1-c` zone 

```
gcloud beta container --project "citric-snow-362912" clusters create "test-cluster-1" --no-enable-basic-auth --cluster-version "1.27.8-gke.1067004" --release-channel "regular" --machine-type "e2-micro" --image-type "COS_CONTAINERD" --disk-type "pd-balanced" --disk-size "100" --metadata disable-legacy-endpoints=true --scopes "https://www.googleapis.com/auth/devstorage.read_only","https://www.googleapis.com/auth/logging.write","https://www.googleapis.com/auth/monitoring","https://www.googleapis.com/auth/servicecontrol","https://www.googleapis.com/auth/service.management.readonly","https://www.googleapis.com/auth/trace.append" --num-nodes "2" --logging=SYSTEM,WORKLOAD --monitoring=SYSTEM --enable-ip-alias --network "projects/citric-snow-362912/global/networks/default" --subnetwork "projects/citric-snow-362912/regions/us-central1/subnetworks/default" --no-enable-intra-node-visibility --default-max-pods-per-node "110" --security-posture=standard --workload-vulnerability-scanning=disabled --no-enable-master-authorized-networks --addons HorizontalPodAutoscaling,HttpLoadBalancing,GcePersistentDiskCsiDriver --enable-autoupgrade --enable-autorepair --max-surge-upgrade 1 --max-unavailable-upgrade 0 --binauthz-evaluation-mode=DISABLED --enable-managed-prometheus --enable-shielded-nodes --node-locations "us-central1-c"
```

We invoke cloud shell within the GCP console and attempt to authenticate to the cluster to use `kubectl`:
```
gcloud container clusters get-credentials test-cluster-1 --zone us-central1-c --project citric-snow-362912
```

Once the cluster has been setup, we prepare the deploy 2 pods `test-pod1` and `test-pod1` in `us-central1` region with the following command:
```
# See `scenario_deployment.yaml` file in Appendix
kubectl apply -f scenario_deployment.yaml
```

We validate that the scenario is setup using `kubectl`:
```
kubectl get pods
NAME                         READY   STATUS    RESTARTS   AGE
test-pod1-5589d96985-6vccs   1/1     Running   0          5m14s
test-pod2-fb578cd5c-42k2f    1/1     Running   0          5m14s

kubectl get nodes
NAME                                            STATUS   ROLES    AGE   VERSION
gke-test-cluster-2-default-pool-dec81310-6g2c   Ready    <none>   73m   v1.27.8-gke.1067004
gke-test-cluster-2-default-pool-dec81310-76c5   Ready    <none>   73m   v1.27.8-gke.1067004
```

## Containment

## Eradication

## Analysis

## Recovery

## Automation

## Additional TODOs
- [ ] Containment - remove pod labels and network policy to isolate a pod
- [ ] Containment - checked IAM Policy Bindings and disable them
- [ ] Containment - drain the node.
- [ ] Containment - remove the Workload Identity's IAM Binding permission to restrict access to pod
- [ ] Analysis - Get Pod events via kubectl: `kubectl events --for pod/$POD_NAME`
- [ ] Analysis - attempt debug mode via kubectl as described [here](https://stackoverflow.com/questions/64698328/add-sidecar-container-to-running-pods/77017278#77017278)

## Appendix: Scripts

### scenario_deployment.yaml

```
apiVersion: apps/v1 # Kubernetes API version for deployments
kind: Deployment # Kind of object being defined (Deployment)
metadata:
  name: test-pod1 # Name of the deployment
spec:
  replicas: 1 # Number of pods to create
  selector:
    matchLabels: # Labels to select pods for the deployment
      app: test-pod1
  template:
    metadata:
      labels: # Labels for the pod
        app: test-pod1
    spec:
      containers:
      - name: test-pod1 # Name of the container
        image: ubuntu:latest # Image to use for the container
        command: ["sleep", "infinity"]
---
apiVersion: apps/v1 # Kubernetes API version for deployments
kind: Deployment # Kind of object being defined (Deployment)
metadata:
  name: test-pod2 # Name of the deployment
spec:
  replicas: 1 # Number of pods to create
  selector:
    matchLabels: # Labels to select pods for the deployment
      app: test-pod2
  template:
    metadata:
      labels: # Labels for the pod
        app: test-pod2
    spec:
      containers:
      - name: test-pod2 # Name of the container
        image: ubuntu:latest # Image to use for the container
        command: ["sleep", "infinity"]
---
```
