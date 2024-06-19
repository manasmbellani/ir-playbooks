<#
	.SYNOPSIS
	Downloading Azure AD Audit Logs for Analysis. Currently supported logs are:
	- Sign-In Logs
	- Activity Logs
	
	.PARAMETER outfile
	Output file to which to write the logs in CSV format. "out-audit-logs.csv" is the default
	
	.PARAMETER logType
	Specifies the type of logs to get e.g. "all" for ALL logs, "signin" for sign-in logs and 
	"activity" for activity logs
	
	.PARAMETER startTime
	Specify a start time in format YYYY-MM-DD e.g. 2024-06-15
	
	.PARAMETER endTime
	Specify the end time in format YYYY-MM-DD e.g. 2024-06-19
	
	.PARAMETER maxLogs
	Specify the maximum number of logs to get e.g. 10
	
	.EXAMPLE
	PS> .\Get-AzureADAuditLogs.ps1
	
	.EXAMPLE
	PS> .\Get-AzureADAuditLogs.ps1 -startTime 2024-06-15 -endTime 2024-06-20 -maxLogs 50 -logType signin
#>

param(
	[string]$outfile = "out-audit-logs.csv",
	[string]$logType = "all",
	[string]$startTime,
	[string]$endTime,
	[string]$maxLogs
)

Write-Host "[*] Importing AzureADPreview module.."
Import-Module AzureADPreview

Write-Host "[*] Connecting to Azure-AD..."
Connect-AzureAD

Write-Host "[*] Building header for audit logs to output file: $outfile..."	
"timestamp,log_type,Id,UserDisplayName,AppDisplayName,IpAddress,ResourceDisplayName,OperatingSystem,Browser,DeviceIsCompliant,DeviceIsManaged,SignInErrorCode,SignInFailureReason,SignInAdditionalDetails,ClientAppUsed,raw"| Out-File -FilePath "$outfile"


if($logType -match "all" -or $logType -match "signin") {

	
	Write-Host "[*] Preparing the filter for Sign-in logs..."
	$filter=""
	if ($startTime) {
		$filter = "CreatedDateTime ge $startTime"
	}
	if($endTime) {
		if($filter) {
			$filter="$filter and CreatedDateTime le $endTime"
		} else {
			$filter="CreatedDateTime le $endTime"
		}
	}
	
	Write-Host "[*] Retrieving the Azure AD Audit Sign-in Logs with filter: $filter, maxLogs: $maxLogs..."
	if($maxLogs) {
		if($filter) {
			$logs=(Get-AzureADAuditSignInLogs -Top $maxLogs -Filter "$filter") 
		} else {
			$logs=(Get-AzureADAuditSignInLogs -Top $maxLogs) 
		}
	} else {
		if($filter) {
			$logs=(Get-AzureADAuditSignInLogs -Filter "$filter") 
		} else {
			$logs=(Get-AzureADAuditSignInLogs)
		}
	}	
	
	Write-Host "[*] Extracting Azure AD Audit Sign-in Logs to file: $outfile..."
	$logs | %{
		$record = @{}
		$record["timestamp"] = $_.CreatedDateTime
		$record["log_type"] = "AzureADAuditSignInLogs"
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

}
#Write-Host "{*] Retrieving AD Directory logs..."
#Get-AzureADSignInLogs -Top 10 | more



