# Compromised GCP Pod

## Scenario
In this document, we run through some general response steps of how to perform an Incident Response and Forensic Process for a GCP pod already assumed to be compromised.

We will endeavour to use CLI commands, where possible, to perform analysis unless it is not possible to use CLI or the information more easily available through a UI.

This scenario comprises of a GCP kubernetes cluster `test-cluster-1` running with 2 nodes, and 2 pods `test-pod1` and `test-pod2` in `us-central1` region in project `citric-snow-362912`

We will assume that detections are already in place within pods to indicate that `test-pod1` is compromised and needs to be contained, analysed and remediated/

## Pre-requisites

For this scenario, we will require:
- Access to a GCP account with sufficient privileges to setup the multi-node Kubernetes cluster in region `us-central1`
- A Google Rapid Response (GRR) server setup already by following the steps [here](https://grr-doc.readthedocs.io/en/latest/installing-grr-server/index.html)
- Access to Google Cloud SDK and kubernetes tools (such as `kubectl`)
- A variety of forensics tools such as docker explorer, etc. listed in the articles below

## Scenario Setup

To setup the scenario, we deploy a cluster called `test-cluster-1` with running with 2 `e2-micro` nodes in `us-central1-c` zone 

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

We list the labels applied on the pods via `kubectl`:
```
$ kubectl describe pods test-pod1-5589d96985-6vccs
Name:             test-pod1-5589d96985-6vccs
...
Labels:           app=test-pod1
                  pod-template-hash=5589d96985
...
```

We manually remove the `app=test-pod1` and any other labels created by us via `kubectl` which opens an editor to edit the `kubectl` definition. We will keep the `pod-template-hash` label to ensure replicaset is 
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

We then create a new network policy to all ingress and egress from the node using a (deny network policy)[./deny_affected_all.yaml]:

```
$ kubectl apply -f ./deny_affected_all.yaml
```

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
- [ ] Analysis - Include tooling from [osdfir-infrastructure](https://github.com/google/osdfir-infrastructure)
