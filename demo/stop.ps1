# MR36 — dừng backend + frontend do demo\start.ps1 mở (chỉ đúng các tiến trình đã ghi trong demo\.pids, kèm tiến trình con).
# Không tắt Docker (Postgres/Redis vẫn chạy, dữ liệu demo giữ nguyên).

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PidFile = Join-Path $PSScriptRoot ".pids"
if (-not (Test-Path $PidFile)) { Write-Host "Không có demo nào đang chạy (thiếu demo\.pids)."; exit 0 }
foreach ($id in Get-Content $PidFile) {
    if ($id -match "^\d+$") {
        taskkill /T /F /PID $id 2>$null | Out-Null
        Write-Host "đã dừng tiến trình $id và tiến trình con"
    }
}
Remove-Item $PidFile
Write-Host "Demo đã dừng."
