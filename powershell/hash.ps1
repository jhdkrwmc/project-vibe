Param(
  [Parameter(Mandatory=$true, ValueFromRemainingArguments=$true)]
  [string[]]$Paths
)

foreach ($p in $Paths) {
  if (Test-Path -LiteralPath $p) {
    $fi = Get-Item -LiteralPath $p
    $size = $fi.Length
    $mtime = $fi.LastWriteTime.ToString('s')
    $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLower()
    Write-Output ("{0}`t{1}`t{2}`t{3}" -f $fi.FullName, $size, $mtime, $sha)
  } else {
    Write-Output ("{0}`tERROR`tNotFound" -f $p)
  }
}

