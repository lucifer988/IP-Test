#!/bin/bash
set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
APP_DIR="/opt/ip-test"

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_root() {
  if [[ $EUID -ne 0 ]]; then
    error "必须以 root 运行"
  fi
}

check_deps() {
  info "检查依赖..."
  for cmd in python3 pip3 node npm google-chrome; do
    if ! command -v $cmd &>/dev/null; then
      MISSING="$MISSING $cmd"
    fi
  done
  if [[ -n "$MISSING" ]]; then
    warn "缺少系统命令:$MISSING"
    read -p "是否安装? [y/N]: " ans
    if [[ "$ans" != "y" ]]; then
      error "依赖未满足，退出"
    fi
    apt-get update
    apt-get install -y python3 python3-pip nodejs npm google-chrome-stable curl
  fi
}

check_agent_browser() {
  info "检查 agent-browser..."
  if command -v agent-browser &>/dev/null; then
    info "agent-browser 已安装"
  elif [[ -f "/root/.nvm/versions/node/v24.14.0/bin/agent-browser" ]]; then
    warn "agent-browser 存在于 /root/.nvm，但不在 PATH"
    echo 'export PATH="/root/.nvm/versions/node/v24.14.0/bin:$PATH"' >> /root/.bashrc
    info "已追加 PATH 到 /root/.bashrc"
  else
    warn "agent-browser 未安装，尝试安装..."
    bash <(curl -sL https://raw.githubusercontent.com/nicehash/NiceHashMiner/master/External/NiceHashAgentInstaller.sh) \
      AGENTBRAINS_DIR=/opt/agent-browser AGENTBRAINS_BRANCH=master 2>&1 | head -20 || true
    if [[ ! -f "/root/.nvm/versions/node/v24.14.0/bin/agent-browser" ]]; then
      warn "agent-browser 自动安装失败，请手动安装"
      warn "参考: https://github.com/nicehash/NiceHashMiner"
    fi
  fi
}

check_python_deps() {
  info "检查 Python 依赖..."
  if python3 -c "import telegram" 2>/dev/null && \
     python3 -c "import requests" 2>/dev/null; then
    info "Python 依赖已满足"
  else
    info "安装 Python 依赖 (python-telegram-bot + requests)..."
    pip3 install python-telegram-bot requests --quiet --break-system-packages
    info "Python 依赖安装完成"
  fi
}

interactive_config() {
  echo ""
  echo "========================================="
  echo "  ip test 安装配置"
  echo "========================================="
  echo ""

  echo -n "TG Bot Token: "
  read -r BOT_TOKEN
  if [[ -z "$BOT_TOKEN" ]]; then
    error "Bot Token 不能为空"
  fi

  echo -n "管理员 TG ID (数字，可留空): "
  read -r ADMIN_ID

  echo -n "itdog 持续测试等待秒数 [55]: "
  read -r WAIT_SEC
  WAIT_SEC=${WAIT_SEC:-55}
  if ! [[ "$WAIT_SEC" =~ ^[0-9]+$ ]] || [[ "$WAIT_SEC" -lt 10 ]]; then
    error "等待秒数必须是 >= 10 的数字"
  fi

  echo -n "是否仅允许管理员使用? [y/N]: "
  read -r ONLY_ADMIN
  [[ "$ONLY_ADMIN" =~ ^[yY]$ ]] && ONLY_ADMIN=true || ONLY_ADMIN=false

  CONFIG_JSON=$(cat <<EOF
{
  "telegram": {
    "bot_token": "$BOT_TOKEN",
    "admin_id": "$ADMIN_ID"
  },
  "itdog_wait_seconds": $WAIT_SEC,
  "only_admin": $ONLY_ADMIN
}
EOF
)
  echo "$CONFIG_JSON" > "$APP_DIR/config.json"
  info "配置已写入 $APP_DIR/config.json"
}

create_service() {
  info "创建 systemd 服务..."
  cat > /etc/systemd/system/ip-test.service <<EOF
[Unit]
Description=ip test Telegram Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/python3 $APP_DIR/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  info "systemd 服务已创建"
}

main() {
  echo -e "${GREEN}=========================================${NC}"
  echo -e "${GREEN}  ip test 一键安装${NC}"
  echo -e "${GREEN}=========================================${NC}"
  echo ""

  check_root
  check_deps
  check_agent_browser
  check_python_deps
  interactive_config
  create_service

  echo ""
  info "安装完成!"
  echo ""
  echo "管理命令:"
  echo "  启动: systemctl start ip-test"
  echo "  停止: systemctl stop ip-test"
  echo "  重启: systemctl restart ip-test"
  echo "  状态: systemctl status ip-test"
  echo "  日志: journalctl -u ip-test -f"
  echo ""
  echo -n "现在启动服务? [Y/n]: "
  read -r START
  if [[ "$START" != "n" ]]; then
    systemctl enable --now ip-test
    info "服务已启动"
  fi
}

main
