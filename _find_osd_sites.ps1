# Find OSD sites in firmware
$firmwarePath = "firmware_backup - Copy (4).bin"
$outputDir = "intel"
$osdSites = @()

# Ensure output directory exists
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

# Read firmware as byte array
$bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $firmwarePath))

# Search for pattern: 90 0B [75-77] 74 01 F0
for ($i = 0; $i -lt ($bytes.Length - 5); $i++) {
    if ($bytes[$i] -eq 0x90 -and 
        $bytes[$i+1] -eq 0x0B -and 
        ($bytes[$i+2] -ge 0x75 -and $bytes[$i+2] -le 0x77) -and 
        $bytes[$i+3] -eq 0x74 -and 
        $bytes[$i+4] -eq 0x01 -and 
        $bytes[$i+5] -eq 0xF0) {
        
        $target = "0x0B" + "{0:X2}" -f $bytes[$i+2]
        $context = $bytes[$i..($i+31)] | ForEach-Object { "{0:X2}" -f $_ }
        $context = $context -join ' '
        
        $osdSites += [PSCustomObject]@{
            FileOffset = "0x{0:X4}" -f $i
            Address = "0x{0:X4}" -f $i  # Same as file offset since base is 0x0
            Target = $target
            First32Bytes = $context
        }
        
        $i += 5  # Skip ahead to avoid overlapping matches
    }
}

# Output to JSON
$osdSites | ConvertTo-Json -Depth 2 | Out-File -FilePath "$outputDir\osd_sites.json" -Encoding utf8

# Output to Markdown table
$mdTable = "| File Offset | Address | Target | First 32 Bytes |`n"
$mdTable += "|-------------|---------|--------|----------------|`n"
foreach ($site in $osdSites) {
    $mdTable += ("| {0} | {1} | {2} | {3} |`n" -f 
        $site.FileOffset, 
        $site.Address, 
        $site.Target, 
        $site.First32Bytes)
}
$mdTable | Out-File -FilePath "$outputDir\osd_sites.md" -Encoding utf8

Write-Host "[+] Found $($osdSites.Count) OSD sites"
Write-Host "[+] Wrote $outputDir\osd_sites.json"
Write-Host "[+] Wrote $outputDir\osd_sites.md"
