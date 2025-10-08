# PowerShell wrapper to run unit tests
# Usage: .\run_tests.ps1 [-VenvPath <path>] [-PythonExe <path or py>]
param(
    [string]$VenvPath = ".venv",
    [string]$PythonExe = "py"
)

# Resolve repo root
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
Push-Location $repoRoot

# Try to activate venv if present
$venvActivate = Join-Path $repoRoot (Join-Path $VenvPath "Scripts\Activate.ps1")
if (Test-Path $venvActivate) {
    Write-Host "Activating virtual environment at $VenvPath"
    . $venvActivate
}
else {
    Write-Warning "Virtual environment activation script not found at $venvActivate. Continuing without activation."
}

# Ensure PYTHONPATH includes src so tests import local packages
$env:PYTHONPATH = Join-Path $repoRoot "src"
Write-Host "PYTHONPATH set to: $env:PYTHONPATH"

# Run the repository test runner
Write-Host "Running unit tests..."
$ResolvePythonExe = {
    param($exe)
    # If the user passed a path to an exe file, prefer that when it exists
    if (Test-Path $exe) {
        return (Resolve-Path $exe).Path
    }

    # If a virtual environment was activated, prefer the 'python' from PATH (venv)
    if ($env:VIRTUAL_ENV) {
        $c = Get-Command 'python' -ErrorAction SilentlyContinue
        if ($c) {
            Write-Host "Detected activated virtual environment at $($env:VIRTUAL_ENV); using python from venv: $($c.Path)"
            return $c.Path
        }
    }

    # If it's a command name on PATH (like 'py' or 'python'), get its executable path
    $cmd = Get-Command $exe -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Path
    }

    # Try common launchers as fallbacks (prefer 'python' so a venv on PATH is used before the system py.exe)
    foreach ($candidate in @('python', 'py')) {
        $c = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($c) {
            Write-Warning "Provided PythonExe '$exe' not found; falling back to '$candidate' located at $($c.Path)."
            return $c.Path
        }
    }

    throw "No usable Python executable found. Tried '$exe', and fallbacks 'py' and 'python' are not available."
}

$pythonToRun = & $ResolvePythonExe $PythonExe
Write-Host "Using Python executable: $pythonToRun"
if ($pythonToRun -match "py.exe$" -or $pythonToRun -match "\\py$") {
    # Windows py launcher supports -3 to select latest Python3
    & $pythonToRun -3 scripts/run_unit_tests.py
}
else {
    & $pythonToRun scripts/run_unit_tests.py
}
$exitCode = $LASTEXITCODE

Pop-Location
exit $exitCode
