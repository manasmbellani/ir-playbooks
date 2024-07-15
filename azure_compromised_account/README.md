# Azure - Compromised Account

## Pre-requisites

### Sign-up Office 365 Business Premium 

Signup to Office 365 Business Premium from [here](https://www.microsoft.com/en-au/microsoft-365/business/microsoft-365-business-premium?activetab=pivot:overviewtab) which will provide an integrated Azure Portal environment as well. 

### Setup KQL Search Environment for Azure Entra ID

Setup a Log Analytics workspace in [Azure Portal](https://portal.azure.com) and forward logs via Diagnostics Settings in [Microsoft Entra Admin Center](https://entra.microsoft.com) by following this guide [here](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/tutorial-configure-log-analytics-workspace). Same steps can be followed to also enabled `MicrosoftGraphActivityLogs` as described [here](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview)

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

### Disable Azure App for sign-in

prevents sign-ins to the app - useful along with removal of oauth consent grant for an app

#### via Microsoft Entra Admin Center

from Microsoft Entra Admin Center > Identity > Enterprise Applications > Properties (left-hand) > "Enabled for users to sign-in?" > No

### Block Emails in Office 365 containing specific keywords

#### via Exchange Admin, Mail Flow

Visit [Office 365 Admin](https://admin.microsoft.com) > Exchange > Mail Flow > Rules > Create a new rule, and apply a rule to block emails containing specific keywords OR from sender.

Taken from [here](https://community.spiceworks.com/t/office-365-block-emails-containing-specific-keywords-in-subject-or-main-body/963528/10)

## Collection

### Collect Azure AD Audit Logs

#### via Powershell/AzureADPreview module

Collect the logs for Azure AD Sign-in and Directory Audit via the script [here](Get-AzureADAuditLogs.ps1)

### Collect Azure AD Environment Information

#### via HAWK

```
cd C:\Windows\Temp
mkdir C:\Windows\Temp\hawk
Connect-AzureAD
Connect-MsolService
Connect-ExchangeOnline
Start-HawkTenantInvestigation
```

https://cloudforensicator.com/documentation


### Collect MFA enabled Azure AD users list

Can help detect users with MFA enabled, MFA disabled, phone number and the type of MFA

#### via Powershell / Connect-MsolService

```
Connect-MsolService

$Result=@() 
$users = Get-MsolUser -All
$users | ForEach-Object {
$user = $_
$mfaStatus = $_.StrongAuthenticationRequirements.State 
$methodTypes = $_.StrongAuthenticationMethods 
 
if ($mfaStatus -ne $null -or $methodTypes -ne $null)
{
if($mfaStatus -eq $null)
{ 
$mfaStatus='Enabled (Conditional Access)'
}
$authMethods = $methodTypes.MethodType
$defaultAuthMethod = ($methodTypes | Where{$_.IsDefault -eq "True"}).MethodType 
$verifyEmail = $user.StrongAuthenticationUserDetails.Email 
$phoneNumber = $user.StrongAuthenticationUserDetails.PhoneNumber
$alternativePhoneNumber = $user.StrongAuthenticationUserDetails.AlternativePhoneNumber
}
Else
{
$mfaStatus = "Disabled"
$defaultAuthMethod = $null
$verifyEmail = $null
$phoneNumber = $null
$alternativePhoneNumber = $null
}
    
$Result += New-Object PSObject -property @{ 
UserName = $user.DisplayName
UserPrincipalName = $user.UserPrincipalName
MFAStatus = $mfaStatus
AuthenticationMethods = $authMethods
DefaultAuthMethod = $defaultAuthMethod
MFAEmail = $verifyEmail
PhoneNumber = $phoneNumber
AlternativePhoneNumber = $alternativePhoneNumber
}
}
$Result
```

Taken from [here](https://morgantechspace.com/2018/06/find-and-list-mfa-enabled-status-office-365-users-powershell.html)

#### via AzureADIncidentResponse

```
Import-Module AzureaDIncidentResponse
Get-AzureADIRMfaAuthMethodAnalysis -TenantId $TenantId -CsvOutput
```

Taken from: https://m365internals.com/2021/04/17/incident-response-in-a-microsoft-cloud-environment/

### Collect Azure Conditional Access Policies

#### via AzureADIncidentResponse

```
Get-AzureADIRConditionalAccessPolicy -TenantId $TenantId -All -XmlOutput
```

Taken from: https://m365internals.com/2021/04/17/incident-response-in-a-microsoft-cloud-environment/

## Analysis

### Detect self-service password resets

#### via AzureADIncidentResponse

```
Get-AzureADIRSsprUsageHistory -TenantId $TenantId
```

### Getting the tenant version

#### via Connect-AzureAD

```
Import-Module AzureAD
Connect-AzureAD
```

### Connecting to Azure Virtual Machine Serial Port

### via Azure Audit Log

```
# resourceId field contains the resource to which serial connection is attempted
operationName.value="Microsoft.SerialConsole/serialPorts/connect/action
```

### Creation of phone number based 2FA authenticator SMS in 

Could be indicative of persistence in place for 2FA. 

#### via Azure Audit Logs

```
# Target.UserPrincipalName is the username on which the authenticator was created
# In the accompanying Activity="Update User" just before this record, the 'StrongAuthenticationUserDetails' field shows the phone number as well
Status reason="User registered Mobile Phone SMS"
Activity="User registered security info"
Category="UserManagement"
```

### Deletion of 2FA authentication

Could be indicative of authentication bypass.

#### via Azure Audit Logs

```
# Status reason provides the authenticator mechanism deleted (e.g. "User deleted Authenticator App with Notification and Code")
# "IP Address" appears to be Microsoft related, so may not be accurate. May have to rely on sign-in logs.
# Target.User Principal Name is the username on which the authenticator info was deleted
Activity="User deleted security info"
Category="UserManagement"
```

### Creation of new users

Look for anamolous users being created in Azure

#### via Azure Audit Logs

```
# Target.UserPrinipalName is the username that is added in Azure
Service="Core Directory"
Category="UserManagement"
Activity Type="Add User"
```

### Identify apps linked to a user

Can help to detect Illegal consents granted to apps to perform various actions.

This information could be used to cross-check the sign-in and other activity logs seen in Azure AD.

#### via Azure Portal UI

Select Azure Portal UI > Users > Select user > Applications 

#### via AzureADIncidentResponse

```
Import-Module AzureADIncidentResponse
# To get the tenant details and set $TenantId = ....
Connect-AzureAD
Connect-AzureADIR -TenantId $TenantId
Get-AzureADIRPermission -TenantId $TenantId -CsvOutput
```

#### via Get-AzureADPSPermissions

```
# Generates a CSV report of all permissions granted to all apps.
cd C:\Users\Administrator\Desktop\opt\Get-AzureADPSPermissions
Connect-MgGraph -Scopes "Application.Read.All User.Read.All DelegatedPermissionGrant.ReadWrite.All"
 .\Get-AzureADPSPermissions.ps1 -ShowProgress | Export-Csv -Path "permissions.csv" -NoTypeInformation
```

Using tools like Eric Zimmerman's `Timeline Explorer`, Look for:
- Consent type = `AllPrincipals`, which indicates permissions granted to everyone's profile
- ClientDisplayName = Unusual display names
- Permission = `*.All` or `Read.` or `Write.` permissions

Mechanism to interpret the output is described [here](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-app-consent) and [here](https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants#prerequisites)

### Identify apps linked to Azure account

This information could be used to cross-check the sign-in and other activity logs seen in Azure AD.

#### via powershell / Get-MgServicePrincipal, Get-MgApplication

```
# Provides the AppID, ID, SignInAudience fields
Get-MgServicePrincipal
# Shows ALL registrations - generally has less results
Get-MgApplication
```

Taken from here: [1](https://learn.microsoft.com/en-us/answers/questions/270680/app-registration-vs-enterprise-applications), [2](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing#investigate-each-appid)


### Detect Oauth App Hijacking

If attacker is able to compromise the app itself by accessing existing secret or certificate / adding new secret or certificate, then they can act as the app itself
doesn't require the user to authenticate / consent to getting permissions

#### via Azure Portal UI / Audit Logs

```
# Target and Modified Properties show the app and the token name that is created. User-Agent contains the user agent string that was leveraged for the action 
Activity Type: "Update application – Certificates and secrets management"
Category: ApplicationManagement
```

### Detect Consent Grant 

These could be indicative of Illicit Consent Grant attempts due to phishing 

Types: -
1 User consent flow - When an application developer directs users to the authorization endpoint with the intent to record consent for only the current user.
2 Admin Consent Flow - When an application developer directs users to the admin consent endpoint with the intent to record consent for the entire tenant.

To prevent these attacks, configure the user consent grant permissions via [Microsoft Entra ID Admin Center](https://entra.microsoft.com) > Identity > Applications > Enterprise Accounts > Security > Consent and Permissions > "Do not allow app consents" (Preferred) OR "Allow user consent for apps from verified publishers, for selected permissions" (Less preferred) (Assuming classification also set in Security > Permission Classifications) as described [here](https://learn.microsoft.com/en-gb/entra/identity/enterprise-apps/configure-user-consent?pivots=portal)

User consent grant permissions above can also be applied via [Azure Portal](https://portal.azure.com) > Enterprise Applications > Security Settings > Consent and Permissions

#### via Azure Portal UI / Audit Logs

Access Azure portal > `Audit Logs` and filter as follows:

```
# Look for any unusual activity here e.g. unusual apps or user agents
Activity = Consent to Application
Activity = Add app role assignment grant to user
Activity = Add delegated permission grant
```

To emulate the attack, 
```
Connect-MgGraph -Scopes "Application.Read.All User.Read.All"
```

Taken from [here](https://www.cloud-architekt.net/detection-and-mitigation-consent-grant-attacks-azuread/#azure-sentinel-hunting-of-consent-to-application-operations)

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
Get-InboxRule -Mailbox "$EMAIL_ADDRESS" | Format-List
```

Taken from [here](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing)

#### via powershell / Search-UnifiedAuditLog

```
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline
Search-UnifiedAuditLog -StartDate 2024-06-08 -EndDate 2024-06-10 -ResultSize 5000 -Operations New-InboxRule,Set-InboxRule,Remove-InboxRule
```

Taken from [here](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing#review-inbox-rules)

### Determine in Microsoft 365 any forwarding rules

#### via powershell / Get-Mailbox

```
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline
Get-Mailbox  -Identity $EMAIL_ID -RecipientTypeDetails UserMailbox -ResultSize unlimited | Format-Table -Auto MicrosoftOnlineServicesID,ForwardingSmtpAddress,DeliverToMailboxAndForward
```

Taken from [here](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing#is-delegated-access-configured-on-the-mailbox)

### Determine in Microsoft 365 any Mailflow / Transport rules

#### via powershell / Get-TransportRule

```
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline
Get-TransportRule -Filter '{Description -like "*$EMAIL_ID*"}' | Format-List
```

#### via powershell / Search-UnifiedAuditLog

```
Search-UnifiedAuditLog -StartDate "2024-06-25 03:30:00Z" -EndDate "2024-06-25 06:32:00Z" -Operations New-TransportRule
```

### Determine in Microsoft 365 who received the emails

See [here](#extract-microsoft-365-emails-for-analysis)

### Extract Microsoft 365 Emails for analysis

#### via powershell / Office 365 Compliance Portal / PurView

Leverage the script [Invoke-ComplianceSearch.ps1](Invoke-ComplianceSearch.ps1) to run Office 365 email searches

#### via Office 365 Compliance Portal 

Login to the [portal](https://compliance.microsoft.com/) > eDiscovery > Standard > Create case.

Leverage the following [link](https://learn.microsoft.com/en-us/purview/ediscovery-keyword-queries-and-search-conditions) to create the content search for Compliance.

### Review the Microsoft Office 365 Emails

#### via Email headers

Useful headers to beware of: 
- SPF: IP addresses that are whitelisted based on the FROM email header
- DKIM: Public key published in DNS is compared with the signature that was added in the header created using the private key
- Originating IP
- Return-Path: Email header that indicates where the bounce-backs must be sent - generally not spoofed by threat actors

Taken from [Reddit page](https://www.reddit.com/r/sysadmin/comments/aph6ee/lets_talk_about_email_spoofing_and_prevention_alt/)

### Determine who has access / permissions to Microsoft 365 Mailbox

Look for unusual names or permission grants. Taken from [here](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing#is-delegated-access-configured-on-the-mailbox)

#### via powershell / ExchangeOnlineManagement

```
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline
# Ignore NT AUTHORITY/SELF which is the permission assigned by user to himself/herself
Get-MailboxPermission -Identity $EMAIL_ID -IncludeSoftDeletedUserPermissions -IncludeUnresolvedPermissions
```

#### via powershell / Search-UnifiedAuditLog

```
# Can detect changes such as addition/removal for mailbox permissions
# Look for Operations="*MailboxPermission*" (e.g. Add-MailboxPermission)
# Monitor 'AuditData > AppAccessContext > UserKey'
Search-UnifiedAuditLog -StartDate "2024-06-24 08:20:00" -EndDate "2024-06-24 08:30:00"
```

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

## References

- List of various Microsoft 365 Administrative Portals is at [MS Portals](https://msportals.io/)
