param(
    [string]$InterfaceName = "",
    [switch]$GatewayMode,
    [string]$ModelPath = "model.json",
    [string]$SuricataRulesPath = $null,
    [string]$SnortRulesPath = $null,
    [string]$OtxApiKey = $env:NIDS_OTX_API_KEY,
    [string]$OtxIocFile = $null,
    [int]$OtxMaxIocs = 20000,
    [bool]$UseGeneratedOtxSuricata = $true,
    [ValidateSet("detect-only", "block-signature", "soc-queue-ml")]
    [string]$PolicyMode = "detect-only"
)

function Get-EnvFileValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [switch]$AllowRawValue
    )

    if (-not (Test-Path $Path)) {
        return $null
    }

    $lines = Get-Content $Path | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("#") }
    foreach ($line in $lines) {
        if ($line -match '^\s*([^=]+?)\s*=\s*(.*)\s*$') {
            if ($matches[1].Trim() -eq $Name) {
                $value = $matches[2].Trim()
                if (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'"))) {
                    $value = $value.Substring(1, $value.Length - 2)
                }
                return $value
            }
        }
    }

    if ($AllowRawValue -and $lines.Count -eq 1 -and $lines[0] -notmatch '=') {
        return $lines[0]
    }

    return $null
}

$workspace = $PSScriptRoot
if (-not $workspace) {
    $workspace = (Get-Location).Path
}

$localEnvFile = Join-Path $workspace ".env"
if (-not $OtxApiKey) {
    $OtxApiKey = Get-EnvFileValue -Name "NIDS_OTX_API_KEY" -Path $localEnvFile -AllowRawValue
}
if (-not $OtxApiKey) {
    $OtxApiKey = Get-EnvFileValue -Name "OTX_API_KEY" -Path $localEnvFile -AllowRawValue
}

if (-not $SuricataRulesPath -and $UseGeneratedOtxSuricata) {
    $generatedSuricataDir = Join-Path $workspace ".cache\otx-suricata"
    if (Test-Path $generatedSuricataDir) {
        $SuricataRulesPath = $generatedSuricataDir
    }
}

$pythonExe = Join-Path $workspace ".venv\Scripts\python.exe"
$runHybridScript = Join-Path $workspace "run_hybrid_nids.ps1"

if (-not (Test-Path $pythonExe)) {
    throw "Python venv tidak ditemukan di $pythonExe"
}

if (Test-Path $runHybridScript) {
    $hybridCmd = "Set-Location '$workspace'; & '$runHybridScript' -InterfaceName '$InterfaceName' -ModelPath '$ModelPath'"
    if ($SuricataRulesPath) {
        $hybridCmd += " -SuricataRulesPath '$SuricataRulesPath'"
    }
    if ($SnortRulesPath) {
        $hybridCmd += " -SnortRulesPath '$SnortRulesPath'"
    }
    if ($OtxApiKey) {
        $hybridCmd += " -OtxApiKey '$OtxApiKey'"
    }
    if ($OtxIocFile) {
        $hybridCmd += " -OtxIocFile '$OtxIocFile'"
    }
    $hybridCmd += " -OtxMaxIocs '$OtxMaxIocs'"
}
else {
    # Build iface/gateway argument
    $ifaceArg = ""
    if ($GatewayMode) {
        $ifaceArg = "--gateway"
    } elseif ($InterfaceName) {
        $ifaceArg = "--iface '$InterfaceName'"
    }

    $hybridCmd = "Set-Location '$workspace'; & '$pythonExe' '.\\nids_engine.py' $ifaceArg --model '$ModelPath' --policy-mode '$PolicyMode'"
    if ($SuricataRulesPath) {
        $hybridCmd += " --suricata-rules '$SuricataRulesPath'"
    }
    if ($SnortRulesPath) {
        $hybridCmd += " --snort-rules '$SnortRulesPath'"
    }
    if ($OtxApiKey) {
        $hybridCmd += " --otx-api-key '$OtxApiKey'"
    }
    if ($OtxIocFile) {
        $hybridCmd += " --otx-ioc-file '$OtxIocFile'"
    }
    $hybridCmd += " --otx-max-iocs '$OtxMaxIocs'"
}

$dashboardCmd = "Set-Location '$workspace'; & '$pythonExe' '.\\flask_app.py'"

Start-Process powershell -ArgumentList "-NoExit", "-Command", $hybridCmd
Start-Process powershell -ArgumentList "-NoExit", "-Command", $dashboardCmd

Write-Host "Started Hybrid NIDS engine and Flask dashboard in two new terminals." -ForegroundColor Green
Write-Host "Open browser to http://localhost:5000" -ForegroundColor Cyan
