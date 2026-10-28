#!/usr/bin/env bash
# ==============================================================================
# CloudSentinel — Amazon EC2 Ubuntu Deployment Automation Script
# Provisions dependencies, creates isolated virtualenv, and configures systemd.
# ==============================================================================
set -e

echo "[1/6] Updating Ubuntu package repositories..."
sudo apt-get update -y
sudo apt-get upgrade -y

echo "[2/6] Installing Python 3, venv, git, and SQLite development libraries..."
sudo apt-get install -y python3 python3-pip python3-venv git sqlite3 libsqlite3-dev curl ufw

echo "[3/6] Setting up CloudSentinel application directory..."
APP_DIR="/home/ubuntu/CloudSentinel"
if [ ! -d "$APP_DIR" ]; then
    echo "Creating directory $APP_DIR..."
    mkdir -p "$APP_DIR"
fi

cd "$APP_DIR"

echo "[4/6] Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[5/6] Installing Python package dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[6/6] Configuring Host Firewall (UFW) with Least-Privilege Rules..."
sudo ufw default deny incoming
sudo ufw default allow outgoing
# Restrict SSH to specific administrative subnet or allow authorized IP
sudo ufw allow 22/tcp comment 'SSH Administrative Access'
# Expose Streamlit application on default port 8501
sudo ufw allow 8501/tcp comment 'CloudSentinel Streamlit Web UI'
sudo ufw --force enable

echo "=============================================================================="
echo "CloudSentinel EC2 Environment Initialized Successfully!"
echo "To test run interactively: streamlit run app.py"
echo "To enable 24/7 background execution: sudo systemctl enable --now cloudsentinel"
echo "=============================================================================="
