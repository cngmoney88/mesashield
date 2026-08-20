<#
.SYNOPSIS
  Install MesaShield on this machine (or push to remote machines) with no clicks.

.DESCRIPTION
  Runs the self-contained MesaShield-Setup.exe in silent mode. If a MesaShield.deploy.json
  sits next to the installer, the machine comes up already pointed at your shared fleet folder
  and update source. Local install needs no admin; remote push uses PowerShell remoting and
  the remote user's context.

.EXAMPLE
  # Install on this machine:
  .\Deploy-MesaShield.ps1 -Setup .\MesaShield-Setup.exe

.EXAMPLE
  # Push to several machines (requires PowerShell remoting / admin on targets):
  .\Deploy-MesaShield.ps1 -Setup .\MesaShield-Setup.exe -Computers PC-1,PC-2,SHOP-3
#>
param(
    [Parameter(Mandatory = $true)][string]$Setup,
    [string]$DeployConfig,
    [string[]]$Computers
)

$ErrorActionPreference = "Stop"
$setupPath  = (Resolve-Path $Setup).Path
$configPath = if ($DeployConfig) { (Resolve-Path $DeployConfig).Path } else { Join-Path (Split-Path $setupPath) "MesaShield.deploy.json" }

function Install-Local {
    param([string]$exe)
    Write-Host "Installing MesaShield (silent)..." -ForegroundColor Cyan
    Start-Process -FilePath $exe -ArgumentList "--silent" -Wait
    Write-Host "Done. MesaShield is installed and running in the tray." -ForegroundColor Green
}

if (-not $Computers) {
    Install-Local -exe $setupPath
    return
}

foreach ($computer in $Computers) {
    Write-Host "==> $computer" -ForegroundColor Yellow
    try {
        $dest = "\\$computer\C$\Windows\Temp\MesaShield"
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        Copy-Item $setupPath (Join-Path $dest "MesaShield-Setup.exe") -Force
        if (Test-Path $configPath) { Copy-Item $configPath (Join-Path $dest "MesaShield.deploy.json") -Force }

        Invoke-Command -ComputerName $computer -ScriptBlock {
            Start-Process -FilePath "C:\Windows\Temp\MesaShield\MesaShield-Setup.exe" -ArgumentList "--silent" -Wait
        }
        Write-Host "    installed on $computer" -ForegroundColor Green
    }
    catch {
        Write-Warning "    $computer failed: $($_.Exception.Message)"
    }
}
