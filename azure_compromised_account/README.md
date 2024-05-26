# Azure - Compromised Account

## Pre-requisites

### Setup Windows Forensic Instance

Follow steps [here](win_compromised_host#windows) sets up the Windows Forensics instance included with dependencies to perform forensics for Azure.

## Identification

## Containment

## Collection

## Analysis

### Extract Emails for analysis

#### via powershell / Office 365 Compliance Portal / PurView

Leverage the script [here](Invoke-ComplianceSearch.ps1) to run Office 365 email searches

#### via Office 365 Compliance Portal 

Login to the [portal](https://compliance.microsoft.com/) > eDiscovery > Standard > Create case.

Leverage the following [link](https://learn.microsoft.com/en-us/purview/ediscovery-keyword-queries-and-search-conditions) to create the content search for Compliance.

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

### Extract Microsoft 365 Unified Access Logs (UAL)

#### via Microsoft-Extractor-Suite

```
Connect-M365
Get-UALAll -UserIds manasbellani@testgcpbusiness12345.onmicrosoft.com -StartDate 2024-05-08 -Output JSON
```

```
Connect-M365
Get-UALSpecificActivity -ActivityType MailItemsAccessed -UserIds manasbellani@testgcpbusiness12345.onmicrosoft.com -StartDate 2024-05-08 -Output JSON
```

List of available Message types for extraction [here](https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/UnifiedAuditLog.html)

## Eradication

## Recovery
