<#
  .SYNOPSIS Script to create a compliance case and run specific search
#>

# ---------- User Inputs ----------
# Add a case name here
$CaseName = "Test Case 6"

# Add the search name here
$SearchName = "Test Search 6"

# Enter the content search here 
# Ref: https://learn.microsoft.com/en-us/purview/ediscovery-keyword-queries-and-search-conditions
$ContentSearch = "from:abcxyz@gmail.com"

# Enter an action name here for exported data
$ActionName = "Test Action 6"
# ---------- User Inputs ----------


Write-Host "[*] Connect to Exchange Online..."
Import-Module ExchangeOnlineManagement
Connect-IPPSSession

Write-Host "[*] Creating a new Compliance case: $CaseName..."
$case = New-ComplianceCase -Name $CaseName

Write-Host "[*] Creating content search: $SearchName to be searched everywhere..."
New-ComplianceSearch -Name $SearchName -Case $CaseName -ContentMatchQuery $ContentSearch -ExchangeLocation All -SharePointLocation All -PublicFolderLocation All

Write-Host "[*] Initiating search: $SearchName in case: $CaseName..."
Start-ComplianceSearch -Identity $SearchName

Write-Host "[*] Waiting for compliance search: $SearchName in case: $CaseName is completed..."
$SearchStatus = ""
while ($SearchStatus -ne "Completed") {
  Sleep 5
  
  Write-Host "[*] Checking compliance search: $SearchName in case: $CaseName status..."
  $SearchStatus = (Get-ComplianceSearch -Case $CaseName -Identity $SearchName).Status
  Write-host "[*] Search Status: $SearchStatus"
}

Write-Host "[*] Initiating action: $ActionName for exporting Search data for search: $SearchName..."
New-ComplianceSearchAction -ActionName $ActionName -SearchName $SearchName -Export -Confirm:$false -Force 

$SearchActionName = $SearchName + "_Export"
Write-Host "[*] Getting status for compliance search action: $SearchActionName in case: $CaseName is completed..."
$SearchActionStatus = ""
while ($SearchActionStatus -ne "Completed") {
  Sleep 5
  
  Write-Host "[*] Checking compliance search action: $SearchActionName in case: $CaseName status..."
  $SearchActionStatus = (Get-ComplianceSearchAction -Case "Test Case 6" -Identity "Test Search 6_Export").Status
  Write-host "[*] Search Status: $SearchActionStatus"
}
