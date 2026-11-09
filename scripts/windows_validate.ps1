# Windows validation mode: runs the test suite, static checks, drift detection, and compliance engine.
# Designed for PowerShell 5.1+ and PowerShell 7 (pwsh).
$ErrorActionPreference = "Continue"
$py = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } else { "py" }
& $py -m autoops validate
& $py -m autoops inventory-check
& $py -m pytest
& $py -m autoops report --demo
Write-Host "`n--- drift (exit code 1 is EXPECTED: the sample data is deliberately drifted) ---"
& $py -m autoops drift --previous examples/sample_previous_state.json
Write-Host "Exit code: $LASTEXITCODE"
Write-Host "`n--- compliance (exit code 1 is EXPECTED for the sample data) ---"
& $py -m autoops compliance
Write-Host "Exit code: $LASTEXITCODE"
Write-Host "`nReminder: Ansible playbooks were NOT executed in this mode."
