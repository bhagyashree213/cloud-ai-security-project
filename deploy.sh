#!/usr/bin/env bash
# ==============================================================================
# CloudSentinel — One-Click Deploy to AWS EC2 (Linux/Mac/Git Bash)
# Usage:  ./deploy.sh
#         ./deploy.sh "Fixed login bug"
# ==============================================================================
set -e

# ── Configuration ─────────────────────────────────────────────────────────────
EC2_HOST="ubuntu@<YOUR-EC2-PUBLIC-IP>"        # e.g. ubuntu@13.232.xx.xx
KEY_FILE="$HOME/.ssh/cloudsentinel.pem"       # Path to your .pem key
EC2_APP_DIR="/home/ubuntu/CloudSentinel"
SERVICE_NAME="cloudsentinel"
# ──────────────────────────────────────────────────────────────────────────────

COMMIT_MSG="${1:-Update CloudSentinel website}"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

echo "═══════════════════════════════════════════════════════════════"
echo "  🛡️  CloudSentinel — Deploy to AWS EC2"
echo "═══════════════════════════════════════════════════════════════"

if echo "$EC2_HOST" | grep -q "<YOUR-EC2"; then
    echo "❌ EC2 host not configured!"
    echo "   Edit deploy.sh and set EC2_HOST to your EC2 IP."
    echo "   Example: ubuntu@13.232.45.67"
    exit 1
fi

# Step 1: Check changes
echo ""
echo "[1/5] Checking local Git status..."
if [ -z "$(git status --porcelain)" ]; then
    echo "  ⚠️  No changes to deploy."
    exit 0
fi
git status --short

# Step 2: Commit
echo ""
echo "[2/5] Committing changes..."
git add -A
git commit -m "$COMMIT_MSG [$TIMESTAMP]"
echo "  ✅ Committed."

# Step 3: Push
echo ""
echo "[3/5] Pushing to GitHub..."
git push origin
echo "  ✅ Pushed."

# Step 4: Pull on EC2
echo ""
echo "[4/5] Pulling latest code on EC2..."
SSH_KEY_ARG=""
if [ -f "$KEY_FILE" ]; then
    SSH_KEY_ARG="-i $KEY_FILE"
fi
ssh $SSH_KEY_ARG -o StrictHostKeyChecking=no "$EC2_HOST" "cd $EC2_APP_DIR && git pull origin main"
echo "  ✅ Code updated on EC2."

# Step 5: Restart service
echo ""
echo "[5/5] Restarting CloudSentinel service..."
ssh $SSH_KEY_ARG -o StrictHostKeyChecking=no "$EC2_HOST" "sudo systemctl restart $SERVICE_NAME && sudo systemctl status $SERVICE_NAME --no-pager -l"
echo "  ✅ Service restarted."

echo ""
echo "═══════════════════════════════════════════════════════════════"
EC2_IP=$(echo "$EC2_HOST" | cut -d'@' -f2)
echo "  🎉 Deployed! Access at: http://$EC2_IP:8501"
echo "═══════════════════════════════════════════════════════════════"

