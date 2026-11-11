<#
.SYNOPSIS
Creates disposable test media for the SANCTUM test lab.

.DESCRIPTION
This script creates a sparse file to simulate a block device.
It does not create an actual loopback mount since Windows handles Virtual Hard Disks differently,
and a sparse file is sufficient for basic I/O testing without destructive consequences.
#>

param(
    [string]$MediaPath = "test_lab\media.img",
    [long]$SizeMB = 100
)

$Size = $SizeMB * 1024 * 1024

if (-not (Test-Path -Path (Split-Path $MediaPath))) {
    New-Item -ItemType Directory -Force -Path (Split-Path $MediaPath) | Out-Null
}

if (Test-Path -Path $MediaPath) {
    Remove-Item -Path $MediaPath -Force
}

# Create a sparse file using fsutil
fsutil file createnew $MediaPath $Size | Out-Null
fsutil sparse setflag $MediaPath | Out-Null
fsutil sparse setrange $MediaPath 0 $Size | Out-Null

Write-Host "Created test media at $MediaPath with size ${SizeMB}MB."
