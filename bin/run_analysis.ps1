# PowerShell wrapper to run all analyzers
# Usage: .\run_analysis.ps1 [-CppcheckPath <path>] [-PythonExe <path or py>] [-NoPrompt]
param(
    [string]$VenvPath = ".venv",
    [string]$CppcheckPath = "",
    [string]$PythonExe = "py",
    [switch]$NoPrompt
)

# Resolve repo root from script location
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
Push-Location $repoRoot

# Set PYTHONPATH to include src
$env:PYTHONPATH = Join-Path $repoRoot "src"
Write-Host "PYTHONPATH set to: $env:PYTHONPATH"

# Try to activate venv if present
$venvActivate = Join-Path $repoRoot (Join-Path $VenvPath "Scripts\Activate.ps1")
if (Test-Path $venvActivate) {
    Write-Host "Activating virtual environment at $VenvPath"
    . $venvActivate
} else {
    Write-Warning "Virtual environment activation script not found at $venvActivate. Continuing without activation."
}

if (-not $NoPrompt -and -not $CppcheckPath) {
    $answer = Read-Host "If you use cppcheck, enter its full path (or press Enter to skip)"
    if ($answer) { $CppcheckPath = $answer }
}

if ($CppcheckPath) {
    if (-Not (Test-Path $CppcheckPath)) {
        Write-Warning "Provided CPPCHECK_PATH '$CppcheckPath' does not exist. Continuing without it."
    } else {
        $env:CPPCHECK_PATH = $CppcheckPath
        Write-Host "CPPCHECK_PATH set to: $env:CPPCHECK_PATH"
    }
}

# Resolve Python executable similar to run_tests.ps1 (prefer venv python when activated)
$ResolvePythonExe = {
    param($exe)
    if (Test-Path $exe) {
        return (Resolve-Path $exe).Path
    }

    if ($env:VIRTUAL_ENV) {
        $c = Get-Command 'python' -ErrorAction SilentlyContinue
        if ($c) {
            Write-Host "Detected activated virtual environment at $($env:VIRTUAL_ENV); using python from venv: $($c.Path)"
            return $c.Path
        }
    }

    $cmd = Get-Command $exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Path }

    foreach ($candidate in @('python','py')) {
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

# Determine analysis target: use the first non-parameter argument if provided, otherwise use the repository root
$targetArg = "."
if ($args.Count -ge 1) {
    $targetArg = $args[0]
} else {
    # default to repo root
    $targetArg = $repoRoot
}

Write-Host "Running analyzers on target: $targetArg"
if ($pythonToRun -match "py.exe$" -or $pythonToRun -match "\\py$") {
    & $pythonToRun -3 -m engine.analyzers.run_all_analyzers $targetArg
} else {
    & $pythonToRun -m engine.analyzers.run_all_analyzers $targetArg
}
$exitCode = $LASTEXITCODE

Pop-Location
exit $exitCode
