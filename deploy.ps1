#!/usr/bin/env pwsh
# ==============================================================================
# CloudSentinel — One-Click Deploy to AWS EC2
# Usage:  .\deploy.ps1
#         .\deploy.ps1 -Message "Fixed login bug"
#         .\deploy.ps1 -SkipRestart
# ==============================================================================

param(
    [string]$Message = "Update CloudSentinel website",
    [string]$KeyFile = "",
    [string]$EC2Host = "",
    [switch]$SkipRestart,
    [switch]$DryRun
)

# ── Configuration ─────────────────────────────────────────────────────────────
# Update these with your actual EC2 details:
$DEFAULT_EC2_HOST = "ubuntu@<YOUR-EC2-PUBLIC-IP>"   # e.g. ubuntu@13.232.xx.xx
$DEFAULT_KEY_FILE = "$HOME\.ssh\cloudsentinel.pem"   # Path to your .pem key file
$EC2_APP_DIR      = "/home/ubuntu/CloudSentinel"
$SERVICE_NAME     = "cloudsentinel"
# ──────────────────────────────────────────────────────────────────────────────

if (-not $EC2Host)  { $EC2Host  = $DEFAULT_EC2_HOST }
if (-not $KeyFile)  { $KeyFile  = $DEFAULT_KEY_FILE }

$ErrorActionPreference = "Stop"

function Write-Step($step, $msg) {
    Write-Host "`n[$step] $msg" -ForegroundColor Cyan
}

function Write-Ok($msg) {
    Write-Host "  ✅ $msg" -ForegroundColor Green
}

function Write-Warn($msg) {
    Write-Host "  ⚠️  $msg" -ForegroundColor Yellow
}

function Write-Fail($msg) {
    Write-Host "  ❌ $msg" -ForegroundColor Red
}

# ──────────────────────────────────────────────────────────────────────────────
# STEP 0: Validate Configuration
# ──────────────────────────────────────────────────────────────────────────────
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
Write-Host "  🛡️  CloudSentinel — Deploy to AWS EC2" -ForegroundColor Magenta
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta

if ($EC2Host -match "<YOUR-EC2") {
    Write-Fail "EC2 host not configured!"
    Write-Host "  Edit deploy.ps1 and set `$DEFAULT_EC2_HOST to your EC2 IP." -ForegroundColor Yellow
    Write-Host "  Example: ubuntu@13.232.45.67" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Or pass it as a parameter:" -ForegroundColor Yellow
    Write-Host '  .\deploy.ps1 -EC2Host "ubuntu@13.232.45.67" -KeyFile "C:\path\to\key.pem"' -ForegroundColor Yellow
    exit 1
}

# ──────────────────────────────────────────────────────────────────────────────
# STEP 1: Check for local changes
# ──────────────────────────────────────────────────────────────────────────────
Write-Step "1/5" "Checking local Git status..."

$status = git status --porcelain 2>&1
if (-not $status) {
    Write-Warn "No changes detected. Nothing to deploy."
    exit 0
}

Write-Host "  Changed files:" -ForegroundColor Gray
$status | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }

if ($DryRun) {
    Write-Warn "DRY RUN — showing what would be deployed. No changes made."
    exit 0
}

# ──────────────────────────────────────────────────────────────────────────────
# STEP 2: Stage and commit all changes
# ──────────────────────────────────────────────────────────────────────────────
Write-Step "2/5" "Committing changes to Git..."

git add -A
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$commitMsg = "$Message [$timestamp]"
git commit -m $commitMsg
Write-Ok "Committed: $commitMsg"

# ──────────────────────────────────────────────────────────────────────────────
# STEP 3: Push to GitHub
# ──────────────────────────────────────────────────────────────────────────────
Write-Step "3/5" "Pushing to GitHub (origin)..."

git push origin
Write-Ok "Pushed to GitHub successfully."

# ──────────────────────────────────────────────────────────────────────────────
# STEP 4: SSH into EC2 and pull latest code
# ──────────────────────────────────────────────────────────────────────────────
Write-Step "4/5" "Pulling latest code on EC2 ($EC2Host)..."

$sshKeyArg = ""
if ($KeyFile -and (Test-Path $KeyFile)) {
    $sshKeyArg = "-i `"$KeyFile`""
    Write-Host "  Using SSH key: $KeyFile" -ForegroundColor Gray
} else {
    Write-Warn "No .pem key file found at $KeyFile — trying SSH without key (agent/config)."
}

$pullCmd = "cd $EC2_APP_DIR && git pull origin main"
$sshCmd = "ssh $sshKeyArg -o StrictHostKeyChecking=no $EC2Host `"$pullCmd`""
Write-Host "  > $sshCmd" -ForegroundColor DarkGray
Invoke-Expression $sshCmd
Write-Ok "Code updated on EC2."

# ──────────────────────────────────────────────────────────────────────────────
# STEP 5: Restart the CloudSentinel service
# ──────────────────────────────────────────────────────────────────────────────
if ($SkipRestart) {
    Write-Warn "Skipping service restart (--SkipRestart flag)."
} else {
    Write-Step "5/5" "Restarting CloudSentinel service on EC2..."

    $restartCmd = "sudo systemctl restart $SERVICE_NAME && sudo systemctl status $SERVICE_NAME --no-pager -l"
    $sshRestart = "ssh $sshKeyArg -o StrictHostKeyChecking=no $EC2Host `"$restartCmd`""
    Write-Host "  > $sshRestart" -ForegroundColor DarkGray
    Invoke-Expression $sshRestart
    Write-Ok "Service restarted successfully."
}

# ──────────────────────────────────────────────────────────────────────────────
# DONE
# ──────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  🎉 CloudSentinel deployed to AWS EC2 successfully!" -ForegroundColor Green
Write-Host "  🌐 Access at: http://$($EC2Host.Split('@')[1]):8501" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green

