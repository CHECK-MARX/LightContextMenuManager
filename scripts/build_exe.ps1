Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

try {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $repoRoot = Split-Path -Parent $scriptDir
    Set-Location $repoRoot

    $venvPath = Join-Path $repoRoot ".venv"
    $venvPython = Join-Path $venvPath "Scripts\python.exe"

    if (-not (Test-Path $venvPython)) {
        Write-Info "Creating virtual environment (.venv)..."
        if (Get-Command py -ErrorAction SilentlyContinue) {
            py -3 -m venv $venvPath
        }
        elseif (Get-Command python -ErrorAction SilentlyContinue) {
            python -m venv $venvPath
        }
        else {
            throw "Python interpreter not found. Please install Python 3.11+."
        }
    }
    else {
        Write-Info "Using existing virtual environment at .venv"
    }

    Write-Info "Upgrading pip..."
    & $venvPython -m pip install --upgrade pip

    Write-Info "Installing dependencies (requirements + PyInstaller)..."
    & $venvPython -m pip install -r (Join-Path $repoRoot "requirements.txt") PyInstaller

    $pyinstallerArgs = @(
        "-m", "PyInstaller",
        "-F", "-w",
        "app.py",
        "-n", "LightContextMenuManager",
        "--collect-all", "PySide6",
        "--collect-all", "shiboken6",
        "--collect-all", "qdarktheme",
        "--add-data", "presets;presets",
        "--add-data", "README.md;."
    )

    $iconPath = Join-Path $repoRoot "assets/app.ico"
    if (Test-Path $iconPath) {
        $pyinstallerArgs += @("--icon", $iconPath)
    }
    else {
        Write-Warn "assets/app.ico not found. Building without custom icon."
    }

    Write-Info "Running PyInstaller..."
    & $venvPython @pyinstallerArgs

    $distDir = Join-Path $repoRoot "dist"
    $exePath = Join-Path $distDir "LightContextMenuManager.exe"
    if (-not (Test-Path $exePath)) {
        throw "PyInstaller did not produce $exePath"
    }

    $presetSource = Join-Path $repoRoot "presets"
    if (Test-Path $presetSource) {
        $targetPresetDir = Join-Path $distDir "presets"
        if (Test-Path $targetPresetDir) {
            Remove-Item -Recurse -Force $targetPresetDir
        }
        Write-Info "Copying presets to dist folder..."
        New-Item -ItemType Directory -Force -Path $targetPresetDir | Out-Null
        Copy-Item -Path (Join-Path $presetSource "*") -Destination $targetPresetDir -Recurse -Force
    }
    else {
        Write-Warn "Presets folder not found; skipping external copy."
    }

    Write-Info "Build completed. Output: $exePath"
    exit 0
}
catch {
    Write-Error "[BUILD FAILED] $_"
    exit 1
}
