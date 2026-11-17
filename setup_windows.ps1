# ==============================================================
# setup_windows.ps1
# Automated Setup & Verification for Windows
# ==============================================================

Write-Host "🛡️ Initializing SENTINEL Threat Detection System Setup..." -ForegroundColor Cyan

# 1. Unblock any marked binary files to prevent Application Control blocks
Write-Host "`n[1/4] Unblocking Python binaries & extensions..." -ForegroundColor Yellow
$pyPath = python -c "import sys; print(sys.prefix)"
if ($pyPath) {
    Get-ChildItem -Path $pyPath -Recurse -Include '*.pyd','*.dll' -ErrorAction SilentlyContinue | Unblock-File
}
Write-Host "  Done." -ForegroundColor Green

# 2. Check dependencies
Write-Host "`n[2/4] Verifying Python dependencies..." -ForegroundColor Yellow
python -m pip install -r requirements.txt --quiet
Write-Host "  Dependencies verified." -ForegroundColor Green

# 3. Verify pipeline info
Write-Host "`n[3/4] Checking model & dataset status..." -ForegroundColor Yellow
python main.py info

# 4. Run automated test suite
Write-Host "`n[4/4] Running automated test suite (Pipeline + SOC REST API)..." -ForegroundColor Yellow
python -m pytest tests/ -v

Write-Host "`n==============================================================" -ForegroundColor Green
Write-Host "  SETUP COMPLETE! Next steps:" -ForegroundColor Green
Write-Host "    - Run Live SOC Console: python main.py dashboard" -ForegroundColor Cyan
Write-Host "    - Run Cyber Range:      python main.py simulate" -ForegroundColor Cyan
Write-Host "==============================================================" -ForegroundColor Green
