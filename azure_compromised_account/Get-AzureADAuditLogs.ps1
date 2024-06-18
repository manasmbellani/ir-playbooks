<#
	.SYNOPSIS
	Downloading Azure AD Audit Sign-In Logs for Analysis
#>

param(
	[string]$outfile = "out-audit-logs.csv"
)

Write-Host "[*] Importing AzureADPreview module.."
Import-Module AzureADPreview

Write-Host "[*] Connecting to Azure-AD..."
Connect-AzureAD

Write-Host "[*] Extract audit logs..."
"timestamp,log_type,Id,UserDisplayName,AppDisplayName,IpAddress,ResourceDisplayName,OperatingSystem,Browser,DeviceIsCompliant,DeviceIsManaged,SignInErrorCode,SignInFailureReason,SignInAdditionalDetails,ClientAppUsed,raw"| Out-File -FilePath "$outfile"

Write-Host "[*] Retrieving the Azure AD Audit Sign in Logs..."
Get-AzureADAuditSignInLogs -Top 10 |  %{
	$record = @{}
	$record["timestamp"] = $_.CreatedDateTime
	$record["log_type"] = "AzureADSignInLogs"
	$record["Id"] = $_.Id
	$record["UserDisplayName"] = $_.UserDisplayName
	$record["AppDisplayName"] = $_.AppDisplayName
	$record["IpAddress"] = $_.IpAddress
	$record["ResourceDisplayName"] = $_.ResourceDisplayName
	$record["OperatingSystem"] = $_.DeviceDetail.OperatingSystem
	$record["Browser"] = $_.DeviceDetail.Browser
	$record["DeviceIsCompliant"] = $_.DeviceDetail.IsCompliant
	$record["DeviceIsManaged"] = $_.DeviceDetail.IsManaged
	$record["SignInErrorCode"] = $_.Status.ErrorCode
	$record["SignInFailureReason"] = $_.Status.FailureReason
	$record["SignInAdditionalDetails"] = $_.Status.AdditionalDetails
	$record["ClientAppUsed"] = $_.ClientAppUsed
	$record["raw"] = ($_ | Out-String).Replace("`r","").Replace("`n","").Replace('"',"'")
	 
	"`"$($record['timestamp'])`",`"$($record['log_type'])`",`"$($record['Id'])`",`"$($record['UserDisplayName'])`"," + `
	"`"$($record['AppDisplayName'])`",`"$($record['IpAddress'])`",`"$($record['ResourceDisplayName'])`"," + `
	"`"$($record['OperatingSystem'])`",`"$($record['Browser'])`",`"$($record['DeviceIsCompliant'])`"," + `
	"`"$($record['DeviceIsManaged'])`",`"$($record['SignInErrorCode'])`",`"$($record['SignInFailureReason'])`"," + `
	"`"$($record['SignInAdditionalDetails'])`",`"$($record['ClientAppUsed'])`",`"$($record['raw'])`"" | Out-File -Append -FilePath "$outfile"
}

#Write-Host "{*] Retrieving AD Directory logs..."
#Get-AzureADAuditDirectoryLogs -Top 10 | more
