# Azure - Compromised Account

## Pre-requisites

### Setup Windows Forensic Instance

Follow steps [here](win_compromised_host#windows) sets up the Windows Forensics instance included with dependencies to perform forensics for Azure.

## Identification

## Containment

## Collection

## Analysis

### Extract Activity Logs

#### via Microsoft-Extractor-Suite

```
Import-Module Microsoft-Extractor-Suite
Connect-AzureAZ
Get-ActivityLogs
```
More info [here](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/AzureActivityLogs.html#usage)

#### via powershell / Get-AzLog

```
Install-Module -Name Az
Connect-AzAccount
Get-AzLog -StartTime 2024-05-08
$logs | ConvertTo-Json
```

## Eradication

## Recovery
