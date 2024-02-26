# Compromised GCP Pod

## Scenario
In this document, we run through some general response steps of how to perform an Incident Response and Forensic Process for a container already assumed to be compromised.

We will try to endeavour CLI commands where possible to perform analysis unless it is not possible to use CLI or the information more easily available through a UI.

This scenario comprises of a GCP kubernetes cluster `test-cluster-1` running with 2 nodes, and 2 pods `test-pod1` and `test-pod2` in `us-central1` region.

We will assume that detections are already in place within pods to indicate that `test-pod1` is compromised and needs to be contained, analysed and remediated to ensure 

## Pre-requisites

For this scenario, we will require:
- Access to a GCP account with privileges to setup multi-node Kubernetes cluster
- 

## Scenario Setup

## Containment

## Eradication

## Analysis

## Recovery

## Automation

## Additional TODOs
- [ ] Test1
- [ ] Test2
- [ ] Containment - drain the node.
