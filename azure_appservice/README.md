# Azure - Compromised App Service

This document describes the steps to perform incident response based on the IR lifecycle steps for a compromised Azure App Service.

## Pre-requisites

## Preparation

## Identification

## Containment

### Review connected events for the app service

These event subscriptions must be disconnected / disabled to ensure that any subsequent connected apps are not invoked.

Additionally, forensics review could be required as threat actors could determine connected apps via events and attempt to compromise them as well.

#### via Azure Portal UI

portal.azure.com > App Service > `Event (Preview)` > Review any active `Event Subscriptions`

## Collection

## Analysis / Pivoting

## Eradication

## Recovery
