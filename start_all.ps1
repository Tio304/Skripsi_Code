param(
    [string]$InterfaceName = "Wi-Fi",
    [string]$ModelPath = "model.json",
    [string]$SuricataRulesPath = $null,
    [string]$SnortRulesPath = $null,
    [string]$OtxApiKey = $env:NIDS_OTX_API_KEY,
    [string]$OtxIocFile = $null,
    [int]$OtxMaxIocs = 20000,
    [ValidateSet("detect-only", "block-signature", "soc-queue-ml")]
    [string]$PolicyMode = "detect-only"
)

$workspace = "c:/Visual Coding"
$pythonExe = "$workspace/.venv/Scripts/python.exe"
$runHybridScript = "$workspace/run_hybrid_nids.ps1"

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
    $hybridCmd = "Set-Location '$workspace'; & '$pythonExe' '.\\nids_engine.py' --iface '$InterfaceName' --model '$ModelPath' --policy-mode '$PolicyMode'"
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
