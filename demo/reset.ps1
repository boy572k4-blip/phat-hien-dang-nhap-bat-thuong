# MR36 — làm sạch dữ liệu demo rồi khởi động lại: dừng demo đang chạy → dựng lại DB lad_demo + xoá Redis db 3 → demo\start.ps1.
# Chỉ đụng DB demo `lad_demo`; DB dev `lad_db` không bao giờ bị xoá (backend\scripts\demo.py tự kiểm tra tên DB).

# Windows PowerShell 5.1 biến dòng stderr của lệnh ngoài (docker, alembic) thành lỗi khi đầu ra bị chuyển hướng — kiểm mã thoát thay vì "Stop".
$ErrorActionPreference = "Continue"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"
$Root = Split-Path -Parent $PSScriptRoot
$Backend = Join-Path $Root "backend"

& (Join-Path $PSScriptRoot "stop.ps1")
Push-Location $Backend
& (Join-Path $Backend "venv\Scripts\python.exe") -m scripts.demo reset
$ok = ($LASTEXITCODE -eq 0)
Pop-Location
if (-not $ok) { Write-Host "LỖI: không làm sạch được DB demo (Docker đã bật chưa? chạy demo\start.ps1 để bật)." -ForegroundColor Red; exit 1 }
& (Join-Path $PSScriptRoot "start.ps1")
