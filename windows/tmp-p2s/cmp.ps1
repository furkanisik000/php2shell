param([string]$A = "C:\Users\<USER>\.qwen\tmp\p2s\php-8.4.26\ext\session",
      [string]$B = "C:\Users\<USER>\.qwen\tmp\p2s\php-8.5.11\ext\session",
      [string]$File)

$fa = Join-Path $A $File
$fb = Join-Path $B $File
$ha = (Get-FileHash $fa -Algorithm SHA256).Hash
$hb = (Get-FileHash $fb -Algorithm SHA256).Hash
if ($ha -eq $hb) { Write-Output "IDENTICAL: $File"; return }
Write-Output "DIFFERS: $File ($((Get-Item $fa).Length) -> $((Get-Item $fb).Length) bytes)"
$la = Get-Content $fa
$lb = Get-Content $fb
# simple LCS-free unified-style diff via Compare-Object
$diff = Compare-Object $la $lb -PassThru
# group into contiguous hunks
$out = New-Object System.Collections.Generic.List[string]
$out.Add("--- 8.4.26/$File")
$out.Add("+++ 8.5.11/$File")
$prev = 0
$side = 0
for ($i = 0; $i -lt $diff.Count; $i++) {
    $d = $diff[$i]
    $lineNo = $d.SID
    $sideStr = if ($d.SideIndicator -eq "=>") { "+" } else { "-" }
    # find actual line number in source
    $src = if ($d.SideIndicator -eq "=>") { $lb } else { $la }
    $idx = [Array]::IndexOf($src, $d.InputObject)
    if ($idx -lt 0) { $idx = $lineNo }
    $out.Add(("{0} {1} {2}" -f $sideStr, ($idx + 1), $d.InputObject))
}
$out | ForEach-Object { Write-Output $_ }
