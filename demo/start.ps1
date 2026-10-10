# MR36 — khởi động demo MỘT lệnh: Docker → Postgres/Redis → DB demo → kiểm tra → backend + frontend (2 cửa sổ) → mở trình duyệt.
# Chạy từ PowerShell ở thư mục gốc dự án:   powershell -ExecutionPolicy Bypass -File demo\start.ps1
# Dừng: demo\stop.ps1 — Làm sạch dữ liệu demo: demo\reset.ps1 — Hướng dẫn đầy đủ: docs\demo-guide.md

# Windows PowerShell 5.1 biến dòng stderr của lệnh ngoài (docker, alembic) thành lỗi khi đầu ra bị chuyển hướng — kiểm mã thoát thay vì "Stop".
$ErrorActionPreference = "Continue"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"

$Root = Split-Path -Parent $PSScriptRoot
$Backend = Join-Path $Root "backend"
$Frontend = Join-Path $Root "frontend"
$Py = Join-Path $Backend "venv\Scripts\python.exe"
$PidFile = Join-Path $PSScriptRoot ".pids"

function Step($text) { Write-Host "`n== $text" -ForegroundColor Cyan }
function Fail($text) { Write-Host "`nLỖI: $text" -ForegroundColor Red; exit 1 }

function Test-Docker {
    $old = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"
    docker info *> $null; $ok = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = $old
    return $ok
}

if (Test-Path $PidFile) { Fail "Demo có vẻ đang chạy (có demo\.pids). Chạy demo\stop.ps1 trước." }
if (-not (Test-Path $Py)) { Fail "Không thấy $Py — cần tạo venv cho backend (docs\getting-started.md)." }

# ---------------------------------------------------------------------------------------------------------- 1. Docker
Step "1/6 Docker"
if (-not (Test-Docker)) {
    $exe = @("$env:LOCALAPPDATA\Programs\DockerDesktop\Docker Desktop.exe", "C:\Program Files\Docker\Docker\Docker Desktop.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $exe) { Fail "Docker chưa chạy và không tìm thấy Docker Desktop." }
    if (-not (Get-Process -Name "Docker Desktop" -ErrorAction SilentlyContinue)) {
        # Tắt máy/Docker không sạch để lại file socket cũ mà Docker Desktop không tự dọn được ("The file cannot be accessed by the
        # system") — gặp ngày 09/10/2026. Docker chưa chạy nên đổi tên thư mục là an toàn; Docker tự tạo lại.
        foreach ($dir in @("$env:LOCALAPPDATA\Docker\run", "$env:LOCALAPPDATA\docker-secrets-engine")) {
            if ((Test-Path $dir) -and (Get-ChildItem $dir -Force -ErrorAction SilentlyContinue | Where-Object { $_.Attributes -match "ReparsePoint" })) {
                $stale = "$dir.cu-$(Get-Date -Format yyyyMMddHHmmss)"
                Rename-Item $dir $stale
                Write-Host "   đã dời socket cũ: $dir -> $stale"
            }
        }
        Write-Host "   bật Docker Desktop..."
        Start-Process $exe
    }
    $deadline = (Get-Date).AddMinutes(4)
    while (-not (Test-Docker)) {
        if ((Get-Date) -gt $deadline) {
            $log = "$env:LOCALAPPDATA\Docker\log\host\com.docker.backend.exe.log"
            if (Test-Path $log) { Select-String -Path $log -Pattern "reporting error to user" | Select-Object -Last 1 | ForEach-Object { Write-Host $_.Line } }
            Fail "Docker không lên sau 4 phút — mở Docker Desktop xem thông báo lỗi (docs\demo-guide.md mục Sự cố)."
        }
        Start-Sleep -Seconds 5
    }
}
Write-Host "   Docker sẵn sàng."

# ------------------------------------------------------------------------------------------------ 2. Postgres + Redis
Step "2/6 Postgres + Redis"
Push-Location $Root
docker compose up -d
Pop-Location
$deadline = (Get-Date).AddSeconds(90)
while ((docker inspect -f "{{.State.Health.Status}}" lad_postgres) -ne "healthy" -or (docker inspect -f "{{.State.Health.Status}}" lad_redis) -ne "healthy") {
    if ((Get-Date) -gt $deadline) { Fail "Postgres/Redis không healthy sau 90 giây (docker ps)." }
    Start-Sleep -Seconds 2
}
Write-Host "   lad_postgres, lad_redis healthy."

# ------------------------------------------------------------------------------------------------ 3. DB demo + khoá JWT
Step "3/6 DB demo"
$Secret = Join-Path $PSScriptRoot ".jwt_secret"
if (-not (Test-Path $Secret)) {
    & $Py -c "import secrets; print(secrets.token_urlsafe(48))" | Set-Content -Path $Secret -Encoding ascii -NoNewline
    Write-Host "   đã tạo khoá JWT riêng cho máy demo (demo\.jwt_secret, không vào git)."
}
Push-Location $Backend
& $Py -m scripts.demo ensure
if ($LASTEXITCODE -ne 0) { Pop-Location; Fail "Không dựng được DB demo." }

# ---------------------------------------------------------------------------------------------------------- 4. Kiểm tra
Step "4/6 Kiểm tra"
& $Py -m scripts.demo check
$checkOk = ($LASTEXITCODE -eq 0)
Pop-Location
if (-not $checkOk) { Fail "Có mục kiểm tra chưa đạt (xem các dòng ✗ phía trên)." }

# --------------------------------------------------------------------------------------------- 5. Backend + frontend
Step "5/6 Backend + frontend"
$envLines = & $Py (Join-Path $Backend "scripts\demo.py") env
$setEnv = ($envLines | Where-Object { $_ -match "=" } | ForEach-Object { $k, $v = $_ -split "=", 2; "`$env:$k='$v'" }) -join "; "
$backendCmd = "`$Host.UI.RawUI.WindowTitle='DEMO backend :8000'; $setEnv; `$env:PYTHONIOENCODING='utf-8'; & '$Py' -m uvicorn app.main:app --host 127.0.0.1 --port 8000"
$frontendCmd = "`$Host.UI.RawUI.WindowTitle='DEMO frontend :5173'; npm run dev"
$b = Start-Process powershell -PassThru -WorkingDirectory $Backend -ArgumentList "-NoExit", "-Command", $backendCmd
$f = Start-Process powershell -PassThru -WorkingDirectory $Frontend -ArgumentList "-NoExit", "-Command", $frontendCmd
"$($b.Id)`n$($f.Id)" | Set-Content -Path $PidFile -Encoding ascii

function Wait-Url($url, $seconds) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        try { Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 3 | Out-Null; return $true } catch { Start-Sleep -Seconds 2 }
    }
    return $false
}
if (-not (Wait-Url "http://127.0.0.1:8000/health" 90)) { Fail "Backend không trả lời /health sau 90 giây — xem cửa sổ 'DEMO backend'." }
if (-not (Wait-Url "http://localhost:5173" 90)) { Fail "Frontend không lên sau 90 giây — xem cửa sổ 'DEMO frontend'." }
Write-Host "   backend http://127.0.0.1:8000, frontend http://localhost:5173 đang chạy."

# -------------------------------------------------------------------------------------------------- 6. Mở trình duyệt
Step "6/6 Mở trình duyệt"
Start-Process "http://localhost:5173/admin/login"
Start-Process "http://localhost:5173/login"

Write-Host @"

DEMO SẴN SÀNG
  Quản trị : http://localhost:5173/admin/login   admin_demo / Admin@Demo2026
  Web app  : http://localhost:5173/login         user001 ... user025 / Demo@12345
  Tấn công : cd attack-sim; ..\backend\venv\Scripts\python.exe demo_all.py
  Dừng     : demo\stop.ps1        Làm sạch dữ liệu: demo\reset.ps1
"@ -ForegroundColor Green
