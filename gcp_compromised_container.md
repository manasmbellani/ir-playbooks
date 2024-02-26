# Compromised GCP Pod

## Scenario
In this document, we run through some general response steps of how to perform an Incident Response and Forensic Process for a container already assumed to be compromised.

We will endeavour to use CLI commands, where possible, to perform analysis unless it is not possible to use CLI or the information more easily available through a UI.

This scenario comprises of a GCP kubernetes cluster `test-cluster-1` running with 2 nodes, and 2 pods `test-pod1` and `test-pod2` in `us-central1` region.

We will assume that detections are already in place within pods to indicate that `test-pod1` is compromised and needs to be contained, analysed and remediated/

## Pre-requisites

For this scenario, we will require:
- Access to a GCP account with sufficient privileges to setup the multi-node Kubernetes cluster in region `us-central1`
- A Google Rapid Response (GRR) setup already by following the steps [here](https://grr-doc.readthedocs.io/en/latest/installing-grr-server/index.html)
- Access to Google Cloud SDK and kubernetes tools (such as `kubectl`)
- A variety of forensics tools such as docker explorer, etc. listed in the articles below

## Scenario Setup

To setup the scenario, we deploy a cluster called `test-cluster-1` with running with 2 nodes, and 2 pods `test-pod1` and `test-pod1` in `us-central1` region with the following command:
```
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
- [ ] Analysis - attempt debug mode via kubectl as described [here](https://stackoverflow.com/questions/64698328/add-sidecar-container-to-running-pods/77017278#77017278)

