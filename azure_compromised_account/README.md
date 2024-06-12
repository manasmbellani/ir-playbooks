# Azure - Compromised Account

## Pre-requisites

### Sign-up Office 365 Business Premium 

Signup to Office 365 Business Premium from [here](https://www.microsoft.com/en-au/microsoft-365/business/microsoft-365-business-premium?activetab=pivot:overviewtab) which will provide an integrated Azure Portal environment as well. 

### Setup KQL Search Environment for Azure Entra ID

Setup a Log Analytics workspace in [Azure Portal](https://portal.azure.com) and forward logs via Diagnostics Settings in [Microsoft Entra Admin Center](https://entra.microsoft.com) by following this guide [here](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/tutorial-configure-log-analytics-workspace).

Wait for 15 minutes and then Logs are visible under [Microsoft Entra Admin Center](https://entra.microsoft.com) > Identity > Monitoring & Health > Log Analytics

### Setup Windows Forensic Instance

Follow steps [here](win_compromised_host#windows) sets up the Windows Forensics instance included with dependencies to perform forensics for Azure.

## Identification

## Containment

### Disable Microsoft 365 Account

#### via powershell / Microsoft Graph API

```
Import-Module Microsoft.Graph
Connect-Graph -Scopes User.ReadWrite.All
$params = @{
	accountEnabled = $false
}
Update-MgUser -UserId $UserAccount -BodyParameter $params
```

Taken from [here](https://learn.microsoft.com/en-us/microsoft-365/enterprise/block-user-accounts-with-microsoft-365-powershell?view=o365-worldwide#block-access-to-individual-user-accounts)

#### via powershell / Active Directory

See [here](../win_compromised_host/README.md#disable-user-account)

### Remove OAuth Consent Grant for app

#### via powershell / Remove-MgOauth2PermissionGrant

You can revoke the OAuth consent grant with PowerShell by following the steps in Remove-MgOauth2PermissionGrant

Taken from [here](https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants#how-to-stop-and-remediate-an-illicit-consent-grant-attack)

####  via powershell / Remove-MgServicePrincipalAppRoleAssignment

You can revoke the Service App Role Assignment with PowerShell by following the steps in Remove-MgServicePrincipalAppRoleAssignment.

Taken from [here](https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants#how-to-stop-and-remediate-an-illicit-consent-grant-attack)

## Collection

## Analysis

### Identify apps linked to a user

Can help to detect Illegal consents granted to apps to perform various actions

#### via Azure Portal UI

Select Azure Portal UI > Users > Select user > Applications 

#### via Get-AzureADPSPermissions

```
# Generates a CSV report of all permissions granted to all apps.
cd C:\Users\Administrator\Desktop\opt\Get-AzureADPSPermissions
Connect-MgGraph -Scopes "Application.Read.All User.Read.All DelegatedPermissionGrant.ReadWrite.All"
 .\Get-AzureADPSPermissions.ps1 -ShowProgress | Export-Csv -Path "permissions.csv" -NoTypeInformation
```

Mechanism to interpret the output is described [here](https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants#prerequisites)

### Detect Consent Grant 

These could be indicative of Illicit Consent Grant attempts due to phishing 
To prevent these attacks, configure the user consent grant permissions via [Microsoft Entra ID Admin Center](https://entra.microsoft.com) > Identity > Applications > Enterprise Accounts > Security > Consent and Permissions > "Do not allow app consents" (Preferred) OR "Allow user consent for apps from verified publishers, for selected permissions" (Less preferred) (Assuming classification also set in Security > Permission Classifications) as described [here](https://learn.microsoft.com/en-gb/entra/identity/enterprise-apps/configure-user-consent?pivots=portal)

#### via Azure Portal UI / Sign-In Logs



### Detect Device Code Flow Authentication attempts

These could be indicative of device code phishing attempts as described [here](https://www.inversecos.com/2022/12/how-to-detect-malicious-oauth-device.html) 
To prevent these attacks, enable a conditional flow policy which can block Network > Authentication Flow = Device Code Flow as described [here](https://cloudbrothers.info/en/protect-users-device-code-flow-abuse/)

#### via Azure Portal UI / Sign-In Logs

Access Azure portal > `Sign-In Logs`
```
# View 'User Agent' and 'IP Address' field 
Authentication Protocol: Device Code
```

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

### View Microsoft Office 365 Inbox Rules

Can reveal any interesting Inbox Rules created by threat actors if the account has been compromised.

#### via powershell / Get-InboxRule

```
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline
Get-InboxRule -Mailbox $Users[1].UserPrincipalName | Format-List
```

Taken from [here](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing)

#### via powershell / Search-UnifiedAuditLog

```
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline
Search-UnifiedAuditLog -StartDate 2024-06-08 -EndDate 2024-06-10 -ResultSize 5000 -Operations New-InboxRule
```

Taken from [here](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing)

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
