#!/bin/bash
set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
APP_DIR="/opt/ip-analyzer-pro"

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_root() {
  if [[ $EUID -ne 0 ]]; then
    error "必须以 root 运行"
  fi
}

stop_service() {
  if systemctl is-active --quiet ip-analyzer-pro 2>/dev/null; then
    info "停止服务..."
    systemctl stop ip-analyzer-pro
  fi
  if systemctl is-enabled --quiet ip-analyzer-pro 2>/dev/null; then
    systemctl disable ip-analyzer-pro
  fi
}

remove_service() {
  if [[ -f /etc/systemd/system/ip-analyzer-pro.service ]]; then
    info "移除 systemd 服务..."
    rm -f /etc/systemd/system/ip-analyzer-pro.service
    systemctl daemon-reload
  fi
}

remove_app() {
  if [[ -d "$APP_DIR" ]]; then
    info "删除应用目录 $APP_DIR..."
    rm -rf "$APP_DIR"
  fi
}

kill_browser_sessions() {
  info "关闭残留的 itdog 浏览器会话..."
  for sess in $(ls /tmp/.agent-browser-sessions 2>/dev/null || true); do
    rm -rf "/tmp/.agent-browser-sessions/$sess" 2>/dev/null || true
  done
  pkill -f "itdog-" 2>/dev/null || true
}

main() {
  echo -e "${RED}=========================================${NC}"
  echo -e "${RED}  IP Analyzer Pro 卸载${NC}"
  echo -e "${RED}=========================================${NC}"
  echo ""

  check_root

  echo "将执行以下操作:"
  echo "  1. 停止并禁用 systemd 服务"
  echo "  2. 删除 $APP_DIR"
  echo "  3. 清理残留浏览器会话"
  echo ""
  echo -n "确认卸载? [y/N]: "
  read -r CONFIRM
  if [[ "$CONFIRM" != "y" ]]; then
    info "取消卸载"
    exit 0
  fi

  stop_service
  remove_service
  kill_browser_sessions
  remove_app

  echo ""
  info "卸载完成，所有文件已清理"
}

main
