<#
.SYNOPSIS
Cleans up disposable test media.
#>

param(
    [string]$MediaPath = "test_lab\media.img"
)

if (Test-Path -Path $MediaPath) {
    Remove-Item -Path $MediaPath -Force
    Write-Host "Removed test media at $MediaPath."
} else {
    Write-Host "Test media not found at $MediaPath."
}
