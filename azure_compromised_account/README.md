# Azure - Compromised Account

## Pre-requisites

### Setup KQL Search Environment for Azure Entra ID

Setup a Log Analytics workspace in [Azure Portal](https://portal.azure.com) and forward logs via Diagnostics Settings in [Microsoft Entra Admin Center](https://entra.microsoft.com) by following this guide [here](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/tutorial-configure-log-analytics-workspace).

Wait for 15 minutes and then Logs are visible under [Microsoft Entra Admin Center](https://entra.microsoft.com) > Identity > Monitoring & Health > Log Analytics

### Setup Windows Forensic Instance

Follow steps [here](win_compromised_host#windows) sets up the Windows Forensics instance included with dependencies to perform forensics for Azure.

## Identification

## Containment

### Disable Microsoft 365 Account

#### via Microsoft Graph API

```
Import-Module Microsoft.Graph
Connect-Graph -Scopes User.ReadWrite.All
$params = @{
	accountEnabled = $false
}
Update-MgUser -UserId $UserAccount -BodyParameter $params
```

## Collection

## Analysis

### List Microsoft Security alerts (e.g. DLP alerts)

#### via Graph API cmdlets

List alerts such as Microsoft Compliance / Purview DLP alerts

```
 Connect-MgGraph -Scopes `
         "SecurityActions.ReadWrite.All", `
         "SecurityEvents.ReadWrite.All", `
         "Policy.Read.All", `
         "Application.ReadWrite.All"

Get-MgSecurityAlert
```

https://helloitsliam.com/2021/10/15/using-the-microsoft-graph-powershell-for-security-alerts/

### Show Microsoft 365 Enterprise Plan

#### via Graph API

```
Connect-Graph -Scopes Organization.Read.All
$licenses.SkuPartNumber | Format-List
$licenses.ServicePlans
```

https://learn.microsoft.com/en-us/microsoft-365/enterprise/view-licenses-and-services-with-microsoft-365-powershell?view=o365-worldwide

### Detect password brute-force / spraying

#### via Azure AD UI / Sign-in Logs

Under https://portal.azure.com > `Sign-In Logs` > Look for unusual `Status=Interrupted` or `Status=Failure` events (indicate that perhaps MFA did not go through or password was incorrect)

Tested via `Spray365` tool

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

#### via Microsoft Compliance / Purview

Search [Microsoft Compliance, Purview](https://compliance.microsoft.com) portal > Audit

#### via Powershell / Search-UnifiedAuditLog

```
Search-UnifiedAuditLog -StartDate 2024-05-31 -EndDate 2024-06-01
```

#### via Microsoft-Extractor-Suite

```
# To get statistics only
Connect-M365
Get-UALStatistics -UserIds manasbellani@testgcpbusiness12345.onmicrosoft.com -StartDate 2024-05-08 -Output JSON
```

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
