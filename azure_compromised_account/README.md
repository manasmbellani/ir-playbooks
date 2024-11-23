# Azure - Compromised Account

## Pre-requisites

### Sign-up Office 365 Business Premium 

Signup to Office 365 Business Premium from [here](https://www.microsoft.com/en-au/microsoft-365/business/microsoft-365-business-premium?activetab=pivot:overviewtab) which will provide an integrated Azure Portal environment as well. 

### Setup KQL Search Environment for Azure Entra ID

Setup a Log Analytics workspace in [Azure Portal](https://portal.azure.com) and forward logs via Diagnostics Settings in [Microsoft Entra Admin Center](https://entra.microsoft.com) by following this guide [here](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/tutorial-configure-log-analytics-workspace). Same steps can be followed to also enabled `MicrosoftGraphActivityLogs` as described [here](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview)

Wait for 15 minutes and then Logs are visible under [Microsoft Entra Admin Center](https://entra.microsoft.com) > Identity > Monitoring & Health > Log Analytics

### Setup Windows Forensic Instance

Follow steps [here](win_compromised_host#windows) sets up the Windows Forensics instance included with dependencies to perform forensics for Azure.

### Enable Search Query Logging for Exchange and Sharepoint for mailbox accounts

#### via powershell / ExchangeOnlineManagement

- have visibility into search activities across your Microsoft 365 environment mainly Exchange and Sharepoint, including who initiated searches, when, and what types of content they are querying.

```
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline
Set-Mailbox $USERNAME -AuditOwner @{Add="SearchQueryInitiated"}
```

https://www.linkedin.com/posts/activity-7263003610668572672-7Yvx/?utm_source=share&utm_medium=member_ios

https://learn.microsoft.com/en-gb/purview/audit-get-started#step-3-enable-searchqueryinitiated-events

## Identification

## Containment

### Remove the delegated permissions for any partner granted access

Visit Admin Center > Partners via link [here](https://admin.microsoft.com/#/partners)

### Block IP Ranges or Countries performing credential stuffing attacks

#### via Azure Named Locations / Azure Conditional Access Policies

Go to `Conditional Access` > `Named Locations` > Create a new `IP Ranges Location` or `Countries Location`

Visit `Conditional Access` > `Policies` > Select under Network > Select `IP Ranges` location that was previously created

Taken from [here](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray#block-ip-address-microsoft-entra-id-for-managed-scenario-phs-including-staging)

### Blocking Legacy Authentication Protocols

#### via Azure Conditional Access Policies

Go to `Conditional Access` > `Policies` > `New Policy` > `Conditions` > `Client Apps` > Use `Other Clients` to disable FTP, POP3, SMTP protcols.

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

### Collect Azure AD Audit Logs (Sign-In, Directory Audit)

#### via Powershell/AzureADPreview module

Collect the logs for Azure AD Sign-in and Directory Audit via the script [here](Get-AzureADAuditLogs.ps1)

#### via Microsoft Graph

```
Connect-MgGraph  -Scopes "AuditLog.Read.All,Directory.Read.All"
Get-MgAuditLogSignIn -All | Format-List | more
Get-MgAuditLogDirectoryAudit -All | Format-List | more
```

### Collect Azure Activity Logs

See [here](#extract-activity-logs)

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

Taken from [cloudfornsicator](https://cloudforensicator.com/documentation)

#### via Crowdstrike CRT for Azure

```
cd C:\Users\Administrator\Desktop\opt\crowdstrike-crt\CRT-main
.\Get-CRTReport.ps1
```

More info at [crowdstrike](https://github.com/CrowdStrike/CRT)


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

#### via roadrecon / TokenTacticsv2

```
# Windows
cd C:\Users\azureuser\Desktop\opt\TokenTacticsv2\TokenTacticsV2-main
Import-Module .\TokenTactics.psm1
Clear-Token -Token All
Get-AzureToken -Client MSGraph
$response.access_token

# Kali
roadrecon plugin policies -f road2recon.csv
```

https://trustedsec.com/blog/hacking-your-cloud-tokens-edition-2-0

### Collection of Risky Detections (eg Risk sign-ins, Risk detections)

#### via Azure Identity Protection 

If enabled, available here: https://portal.azure.com/#view/Microsoft_AAD_IAM/IdentityProtectionMenuBlade/~/RiskDetections

## Analysis

### Look for unusual activity in SIEM / Log Analytics 

#### via Microsoft Sentinel / KQL

```
AzureActivity
| where OperationNameValue startswith "MICROSOFT.SECURITYINSIGHTS"
| extend message_ = tostring(parse_json(Properties).message)
| extend resource_ = tostring(parse_json(Properties).resource)
| project TimeGenerated, OperationNameValue, Caller, ResourceId, message_, ActivityStatusValue
```

### Look for unusual links clicked in emails

- Captures Safelinks clicked URls
- Look for unusual domains in URLs:
```
# https://perception-point.io/blog/phishing-by-design-two-step-attacks-using-microsoft-visio-files/
.sharepoint.com
```
- Look for unusual extensions in URLs:
```
# https://perception-point.io/blog/phishing-by-design-two-step-attacks-using-microsoft-visio-files/
.vsdx
```

#### via Azure Microsoft Defender / Microsoft Sentinel / KQL

```
UrlClickEvents
| sort by TimeGenerated desc 
```

### Look for unusual inbound emails with attachments

- Look for unusual domains from which emails were forwarded as they could be delivering phishing or malware
  
#### via Azure Microsoft Defender / Microsoft Sentinel / KQL

By default, only visible in Microsoft Defender portal. 

```
let Timeframe = 30d;
let EmailInformation = EmailEvents
    | where TimeGenerated > ago(Timeframe)
    | where DeliveryAction != "Blocked"
    | where AttachmentCount != "0"
    | project TimeGenerated, NetworkMessageId, SenderMailFromAddress, SenderFromAddress, SenderDisplayName, ThreatNames;
EmailInformation
    | join (EmailAttachmentInfo
    | project NetworkMessageId, FileName, FileType, FileSize
) on NetworkMessageId
| sort by TimeGenerated desc
```

https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/02.ThreatDetection/recently-received-emails-with-attachments.md

### Look for unusual inbound emails

- Look for unusual domains from which emails were forwarded as they could be delivering phishing or malware

#### via Azure Microsoft Defender / Microsoft Sentinel / KQL

By default, only visible in Microsoft Defender portal. 

```
# Extract the domain name
EmailEvents
| extend SenderDomain = extract(@"@(.+)$", 1, SenderFromAddress)
| summarize count() by SenderDomain
| sort by count_ asc
```

https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/02.ThreatDetection/recently-received-emails-with-attachments.md

### Get timeline of object creation in Azure

#### via roadrecon / TokenTacticsv2

```
# Windows
cd C:\Users\azureuser\Desktop\opt\TokenTacticsv2\TokenTacticsV2-main
Import-Module .\TokenTactics.psm1
Clear-Token -Token All
Get-AzureToken -Client MSGraph
$response.access_token

# Kali
roadrecon plugin road2timeline -f road2recon.csv
```

https://trustedsec.com/blog/hacking-your-cloud-tokens-edition-2-0

### Look for unusual Authentication Changes

- Look for enabling of Temporary Access Pass (TAP) for users. In Azure AD, look for changes to the value of `modifiedPropertiesNewValueState`.

#### via AzureAD Audit Logs / Microsoft Sentinel / KQL

```
# Updating Strong Authentication
# details in the following `Update User` audit log
AuditLogs
| where Category == "UserManagement"
| where OperationName == "Disable Strong Authentication"
| sort by TimeGenerated desc

# Updating the phone number for authentication method. Details in following `Update User` operation
AuditLogs
| where Category == "UserManagement"
| where OperationName == "Update per-user multifactor authentication state"
| sort by TimeGenerated desc

# For Temporary Access pass `modifiedPropertiesNewValueState` is set to 0 OR addition of phone app for receiving push notification, if enabled.
AuditLogs
| where OperationName == "Authentication Methods Policy Update"
| extend modifiedPropertiesNewValue = tostring(parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].newValue)))
| extend modifiedPropertiesOldValue = tostring(parse_json(tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[0].oldValue)))
| extend modifiedPropertiesNewValueId = tostring(parse_json(tostring(parse_json(modifiedPropertiesNewValue).authenticationMethodConfigurations))[3].id)
| extend modifiedPropertiesOldValueId = tostring(parse_json(tostring(parse_json(modifiedPropertiesOldValue).authenticationMethodConfigurations))[3].id)
| extend modifiedPropertiesOldValueState = tostring(parse_json(tostring(parse_json(modifiedPropertiesOldValue).authenticationMethodConfigurations))[3].state)
| extend modifiedPropertiesNewValueState = tostring(parse_json(tostring(parse_json(modifiedPropertiesNewValue).authenticationMethodConfigurations))[3].state)
| sort by TimeGenerated desc
```

### Look for Unusual setup Domain Authentication attempts for Azure

#### via AzureAD Audit Logs / Microsoft Sentinel / KQL

```
AuditLogs
| where OperationName == "Set domain authentication"
| sort by TimeGenerated desc
```

https://research.splunk.com/cloud/a87cd633-076d-4ab2-9047-977751a3c1a0/


#### via Azure UI / Custom Domain Names

Search for https://portal.azure.com > `Custom Domain Names` > Check for domains with `Federated` flag set
https://portal.azure.com/#view/Microsoft_AAD_IAM/DomainsList.ReactView

### Look for unusual mailbox permission grants

#### via Microsoft Security / Unified Audit Log

- Look for Activity: `Added delegate mailbox permissions` in Unified Audit Logs in [Microsoft Security](https://security.microsoft.com)

#### via Audit Logs / Microsoft Sentinel / KQL

- Pre-requisite: requires `Microsoft 365` data connector to be setup in Sentinel.

```
OfficeActivity
| where Operation == "Add-MailboxPermission"
| where Parameters has "AccessRights=FullAccess" | project TimeGenerated, UserId, MailboxOwnerUPN, Parameters
```

### Look for unusual updates to user's security settings / information

- Creation of temporary access pass for a user to login for persistence. In `Azure AD Activity Logs`, we have `ResultDescription` field contains `"registered temporary access pass"`
- Require re-registration of existing MFA (e.g phone, SMS) configured via the console. In `Azure AD Activity Logs`, we have `ResultDescription` field contains `"Admin required re-registration of MFA authentication methods."`
- Registration of a new phone app for MFA / authentication

#### via Azure AD Audit Logs

```
AuditLogs
| where OperationName contains "registered security info" or OperationName contains "deleted security info"

# New Phone App being registered
AuditLogs
| where OperationName contains "User registered security info" and ResultDescription contains "User registered Authenticator App with Notification and Code"

```

### Look for creation of unusual Azure VM Instances

- Look for presence of interesting custom OR user metadata which can be used for persistence (may not be shown in Activity Logs). 

#### via Azure AD Activity Logs 

```
AuditLogs
| where OperationName = "Create or Update Virtual Machine"
```

### Check for unusual role assignments in Azure

Can be used to detect persistence for e.g. if serviceprincipal is being given role assignments

#### via Azure Activity Logs / Operation: "Create Role Assignment"

```
# note the 'Properties.RequestBody.PrincipalType' value
Operation name: Create role assignment
```

### Check for anomalous cross-tenant synchronization attempts

#### via Azure Sign-in Logs

```
# This may not always be accurate
Cross Tenant Access Type: B2B Collaboration
Username: <Unusual username>
```

Source [here](https://www.xintra.org/blog/lateral-movement-entraid-cross-tenant-synchronization)

#### via Azure AD Audit Logs

```
# Modified Properties > CrossTenantAccessPolicy > tenantId has the attacker's tenant 
Service: CoreDirectory
Category: CrossTenantAccessSettings
ActivityType: "Add a partner to cross-tenant access setting"

Service: CoreDirectory
Category: CrossTenantIdentitySyncSettings
ActivityType: "Create a partner cross-tenant identity sync setting"

```
Ref [here](https://www.invictus-ir.com/news/incident-response-in-azure) and [here](https://www.xintra.org/blog/lateral-movement-entraid-cross-tenant-synchronization)

### Check for partner relationships via delegated admins 

Partner relationships are partners with delegated admin privileges to the Azure account

Taken from here: [1](https://github.com/WillOram/AzureAD-incident-response), [2](https://learn.microsoft.com/en-us/microsoft-365/commerce/manage-partners?view=o365-worldwide#remove-partner-admin-roles)
#### via Azure Admin UI

[Azure Admin](https://admin.microsoft.com/#/partners) > Settings > Partner Relationships

#### via AADInternals

```
Import-Module AADInternals
Get-AADIntAccessTokenForAdmin -SaveToCache
Get-AADIntMSPartners
```

### Addition of new Applications or Service Principalsto Azure 

Can be used for persistence where both applications and service principals might be added to Azure

#### via Azure Unified Audit Logs (UAL)

```
# ModifiedProperties.DisplayName.NewValue contains the name of the application (seen in ElasticSearch)
# Refer to the ModifiedProperties.AppAddress.NewValue to identify `Address` which indicates redirect address for the application
Workload: AzureActiveDirectory
Operation: Add application

# ModifiedProperties.DisplayName.NewValue contains the name of the service principal 
# Refer to the ModifiedProperties.AppAddress.NewValue to identify `Address` which indicates redirect address for the application
Workload: AzureActiveDirectory
Operation: Add service principal
```

### Detect activity from unusual user agents 

- Look for interesting user agents like azurehound, `python-requests` (for tools like roadrecon ), axios for AITM BEC or BAV2ROPC for password spraying as described [here](https://fieldeffect.com/blog/field-effect-discovers-m365-adversary-in-the-middle-campaign)

#### via Azure AD Graph Activity Logs

```
MicrosoftGraphActivityLogs
| where (UserAgent contains "azurehound") or (UserAgent contains "python-requests")
| sort by TimeGenerated desc
```

#### via Azure Sign-in logs / KQL / Excessive number of user agents

As seen in case of `MFASweep` where within a short timeframe, multiple User agent strings are being attempted to see if MFA can be bypassed within a very short period e.g 5 minutes. This can be indicative of MFASweep scanning 

```
SigninLogs
| extend authenticationMethod_ = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod)
| project TimeGenerated, UserAgent, SignInIdentifier, Status, IPAddress, AuthenticationDetails, authenticationMethod_
| summarize countUserAgent = count_distinct(UserAgent), userAgentList=make_list(UserAgent, 5) by IPAddress
| sort by countUserAgent
```

### Detect unusual recon activity for AzureHound

#### via Azure AD Graph Activity Logs

```
MicrosoftGraphActivityLogs
| where UserAgent contains "azurehound"
| extend NormalizedRequestUri = replace_regex(RequestUri, @'/[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}/', @'/APPID/')
| extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'/roleAssignments\?.*$', @'')
| extend NormalizedRequestUri = replace_regex(NormalizedRequestUri, @'\?.*$', @'')
| summarize count() by NormalizedRequestUri, IPAddress
| sort by count_ desc
```

Typically, we should see the requests to the following logs:
```
https://graph.microsoft.com/beta/servicePrincipals/APPID/owners
https://graph.microsoft.com/v1.0/roleManagement/directory
https://graph.microsoft.com/v1.0/servicePrincipals/APPID/appRoleAssignedTo
https://graph.microsoft.com/v1.0/organization
https://graph.microsoft.com/v1.0/groups
https://graph.microsoft.com/v1.0/applications
https://graph.microsoft.com/beta/groups/APPID/owners
https://graph.microsoft.com/v1.0/servicePrincipals
https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions
https://graph.microsoft.com/v1.0/devices
https://graph.microsoft.com/v1.0/users
https://graph.microsoft.com/beta/applications/APPID/owners
https://graph.microsoft.com/beta/groups/APPID/members
```

Taken from [here](https://cloudbrothers.info/en/detect-threats-microsoft-graph-logs-part-1/)

### Detect unusual password resets, including self-service

- Look particularly closely for accounts like `SYNC_*` eg `Sync_SKIURT-JAUYEH_123123123123@domain.onmicrosoft.com` OR `MSOL_*` eg. `MSOL_<installationID>` as discussed [here](https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/phs-password-hash-sync) for abuse via `AADInternals` which abuse password hash synchronization.
- Look for the user that initiated the password reset as well

#### via AzureADIncidentResponse

```
Get-AzureADIRSsprUsageHistory -TenantId $TenantId
```

#### via Azure AD Audit Logs

```
# DisplayName, UserPrincipalName show the users that had their password reset
# Intitiated By reflects the user that initiated the password reset
Activity Type = Reset Password
Category = UserManagement

# Direct password reset by an administrator
AuditLogs
| where OperationName in~ ("Reset password (by admin)"
```

### Getting the tenant ID

#### via UI / External Identities (Cross-Tenant Synchronization Settings)

`Azure Portal UI` > `Cross-tenant Access Settings` > `Add Organization` > `Specify a Tenant ID`

#### via UI / Microsoft Entra ID

[Azure Portal](https://portal.azure.com) > `Microsoft Entra ID` > `Properties`

#### via Connect-AzureAD

```
Import-Module AzureAD
Connect-AzureAD
```

#### via AzureADIrIncidentResponse

```
Import-Module AzureADIncidentResponse
Import-Module AzureAD
Connect-AzureAD
Get-AzureADIRTenantId -DomainName $DOMAIN_NAME
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

### Detect Unusual Credentials such as Certificates, client secrets being added

- Detects `Oauth App Hijacking`: If attacker is able to compromise the app itself by accessing existing secret or certificate / adding new secret or certificate, then they can act as the app itself doesn't require the user to authenticate / consent to getting permissions

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

### Detect Unusual Authentication Flow Attempts

- Look for ROPC attacks which is an old, out-dated single factor authentication flow protocol which sometimes doesn't have MFA. See [here](https://github.com/wunderwuzzi23/ropci?tab=readme-ov-file#what-is-ropc)
- These could be indicative of device code phishing attempts as described [here](https://www.inversecos.com/2022/12/how-to-detect-malicious-oauth-device.html). To prevent these attacks, enable a conditional flow policy which can block Network > Authentication Flow = Device Code Flow as described [here](https://cloudbrothers.info/en/protect-users-device-code-flow-abuse/)

#### via Azure Portal UI / Sign-In Logs

Access Azure portal > `Sign-In Logs`
```
# View 'User Agent' and 'IP Address' field for Device Code Flow Authentication Attempts
Authentication Protocol: Device Code
# ROPC authentication protocol. Ref: https://github.com/wunderwuzzi23/ropci?tab=readme-ov-file#what-is-ropc
Authentication Protocol: ROPC
# Look for Unusually High/Interrupted Authentication attempts
Status: Failed OR Status: Interrupted
```

#### via Azure Unified Audit Logs (UAL)

```
Activity: User logged in
ExtendedProperties.RequestType: Cmsi:Cmsi 
Item: The string for Microsoft graph or whatever resource the attacker requested 
Application ID: The client id that the attacker was posing as - in our case it’s the id for Microsoft Office 
IP Address: attacker IP (again you need to try find discrepancies here)
```

Taken from [here](https://www.inversecos.com/2022/12/how-to-detect-malicious-oauth-device.html) > "Method 2: Unified Audit Logs"

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

#### via Azure Identity Protection

Pre-requisite: Requires the Microsoft Entra ID P2 license

See [here](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray#detect-password-spray-in-azure-identity-protection) for more details

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
# To get the subscriptions for a user
$SubscriptionId = (Get-AzSubscription | Select -First 10 | %{$_.Id})
# Don't specify subscription for ALL logs
# To get the activity logs for a user between particular dates, use below. 
# 'Output' Folder contains logs in JSON
$SubscriptionId | %{Get-ActivityLogs -StartDate 2024-08-01 -EndDate 2024-08-30 -Subscription $_}
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
# Load the Microsoft Powershell module
cd " C:\Users\Administrator\Desktop\opt\Microsoft-Extractor-Suite\Microsoft-Extractor-Suite-main"
Import-Module .\Microsoft-Extractor-Suite.psd1

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

### Enable Azure Custom Banned Passwords Lists for Azure logons

#### via Authentication Methods

Visit https://portal.azure.com > `Authentication Methods` > `Password Protection` > `Custom Banned Password Lists` > Enable `Enforce custom list` if not already enforced > Add Passwords to `Custom Banned Password List`

Taken from [here](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray#password-protection)

## References

- List of various Microsoft 365 Administrative Portals is at [MS Portals](https://msportals.io/)
