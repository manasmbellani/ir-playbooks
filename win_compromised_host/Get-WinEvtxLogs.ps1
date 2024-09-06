<#
    .SYNOPSIS
    Script to download all events to .csv file
#>

param (
    [string]$csvPath = "EventLogs.csv"
)

Write-Host "[*] Deleting output csv: $csvPath if it exists..."
if (Test-Path -Path "$csvPath") { 
    Remove-Item -Path "$csvPath"
}

Write-Host "[*] Getting list of all logs..."
$logNames = (wevtutil el)

Write-Host "[*] Adding header to file: $csvPath..."
"`"TimeGenerated`",`"EntryType`",`"Source`",`"EventID`",`"Category`",`"Message`"" `
  | Out-File -Append -FilePath "$csvPath"

$logNames | %{
    
    $logName = $_
    Write-Host "[*] Getting event logs: $logName, and selecting properties to export to file: $csvPath..."
    $eventLogs = (Get-EventLog -LogName $logName | Select-Object -Property TimeGenerated, EntryType, Source, EventID, Category, Message)

    $i = 0
    $eventLogs | %{
        $i += 1
        Write-Host "[*] Looping through event: $i from log: $logName..."
        $record = @{}
        $record['TimeGenerated'] = $_.TimeGenerated
        $record['EntryType'] = $_.EntryType
        $record['Source'] = $_.Source
        $record['EventID'] = $_.EventID
        $record['Category'] = $_.Category
        $record['Message'] = ($_.Message | Out-String) -replace "[\r\n\d]","" -replace "`"","" -replace "  "," "

        "`"$($record['TimeGenerated'])`",`"$($record['EntryType'])`",`"$($record['Source'])`",`"$($record['EventID'])`",`"$($record['Category'])`",`"$($record['Message'])`""  `
            | Out-File -Append -FilePath "$csvPath"
    }
}
