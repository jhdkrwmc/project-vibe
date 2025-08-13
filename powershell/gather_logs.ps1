Param(
  [Parameter(Mandatory=$true)]
  [string]$Output
)

$ErrorActionPreference = 'Stop'

function Get-ContentHash($text) {
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  $hashBytes = $sha256.ComputeHash($bytes)
  ($hashBytes | ForEach-Object { $_.ToString('x2') }) -join ''
}

$roots = @(
  Join-Path (Get-Location) 'logs',
  Join-Path (Get-Location) 'out',
  Join-Path (Get-Location) '25-08-10\logs',
  Join-Path (Get-Location) '25.08.11\out_v2\bad',
  Join-Path (Get-Location) '2508110204\out_v3\bad'
)

$files = @()
foreach ($r in $roots) {
  if (Test-Path $r) {
    $files += Get-ChildItem -Path $r -Recurse -File -Include *.md,*.txt
  }
}

$byHash = @{}
foreach ($f in $files) {
  try {
    $content = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
    $h = Get-ContentHash $content
    $byHash[$h] = $f
  } catch {}
}

$ordered = $byHash.GetEnumerator() | Sort-Object { $_.Value.LastWriteTime }

$header = "# ALL LOGS (deduplicated by content) — generated $(Get-Date -Format s)" + "`n`n"
Set-Content -LiteralPath $Output -Value $header -Encoding UTF8

foreach ($kv in $ordered) {
  $f = $kv.Value
  $sha = $kv.Key
  $rel = Resolve-Path -LiteralPath $f.FullName | ForEach-Object { $_ }
  $mt = $f.LastWriteTime.ToString('s')
  $size = $f.Length
  Add-Content -LiteralPath $Output -Value ("## {0} — {1} — {2} bytes — sha256={3}" -f $f.FullName, $mt, $size, $sha)
  Add-Content -LiteralPath $Output -Value "`n``````"
  Add-Content -LiteralPath $Output -Value (Get-Content -LiteralPath $f.FullName -Raw)
  Add-Content -LiteralPath $Output -Value "```````n"
}

