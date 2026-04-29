param(
    [string]$OtxApiKey = $null,
    [string]$DestinationDirectory = (Join-Path $PSScriptRoot ".cache\otx-suricata"),
    [string]$RepoDirectory = (Join-Path $PSScriptRoot ".cache\OTX-Suricata"),
    [string]$PythonExe = (Join-Path $PSScriptRoot ".venv\Scripts\python.exe"),
    [switch]$SkipIpRep,
    [switch]$SkipFileMd5
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

if (-not $OtxApiKey) {
    $envPath = Join-Path $PSScriptRoot ".env"
    $OtxApiKey = Get-EnvFileValue -Name "NIDS_OTX_API_KEY" -Path $envPath -AllowRawValue
    if (-not $OtxApiKey) {
        $OtxApiKey = Get-EnvFileValue -Name "OTX_API_KEY" -Path $envPath -AllowRawValue
    }
}

if (-not $OtxApiKey) {
    throw "OTX API key tidak ditemukan. Isi .env dengan NIDS_OTX_API_KEY=... atau OTX_API_KEY=..."
}

$OtxApiKey = $OtxApiKey.Trim()
if ($OtxApiKey.Length -lt 20) {
    throw "OTX API key terbaca tidak valid (panjang $($OtxApiKey.Length)). Cek format .env: OTX_API_KEY=<full_key>."
}

if (-not (Test-Path $PythonExe)) {
    throw "Python venv tidak ditemukan di $PythonExe"
}

$repoUrl = "https://github.com/AlienVault-OTX/OTX-Suricata.git"

if (-not (Test-Path $RepoDirectory)) {
    New-Item -ItemType Directory -Force -Path (Split-Path $RepoDirectory -Parent) | Out-Null
    git clone $repoUrl $RepoDirectory
}
else {
    Push-Location $RepoDirectory
    try {
        git pull
    }
    finally {
        Pop-Location
    }
}

if (-not (Test-Path $DestinationDirectory)) {
    New-Item -ItemType Directory -Force -Path $DestinationDirectory | Out-Null
}

Push-Location $RepoDirectory
try {
    & $PythonExe -m pip install --quiet OTXv2

    $suricataScriptCandidates = @(
        (Join-Path $RepoDirectory "suricata.py"),
        (Join-Path $RepoDirectory "otx-suricata\suricata.py")
    )
    $suricataScript = $suricataScriptCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $suricataScript) {
        throw "suricata.py tidak ditemukan di repo OTX-Suricata. Cek isi folder $RepoDirectory"
    }

    $args = @(
        $suricataScript,
        "--key", $OtxApiKey,
        "--destination-directory", $DestinationDirectory
    )
    if ($SkipIpRep) {
        $args += "--skip-iprep"
    }
    if ($SkipFileMd5) {
        $args += "--skip-filemd5"
    }

    & $PythonExe @args
    if ($LASTEXITCODE -ne 0) {
        throw "Gagal generate OTX Suricata (exit code $LASTEXITCODE)."
    }
}
finally {
    Pop-Location
}

Write-Host "Generated OTX Suricata files in: $DestinationDirectory" -ForegroundColor Green
Write-Host "Run start_all.ps1 with -SuricataRulesPath '$DestinationDirectory' (or rely on auto-detect)." -ForegroundColor Cyan
