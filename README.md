# ip test

 Telegram IP 地址分析工具，支持多线路测速、BGP 路由分析、IP 黑名单检测。

## 功能特性

- **itdog.cn 测速** - 基于 itdog.cn 的多节点 Ping 测试
- **国内线路** - 广东、广西三网（电信/联通/移动）检测
- **海外节点** - 美国、日本、新加坡、德国四国测速
- **BGP 分析** - ASN 查询、上游运营商、T1 网络识别
- **IP 黑名单** - Spamhaus、Spamcop、Barracuda 黑名单检测
- **TG 机器人** - Telegram 命令交互

## 环境要求

- Python 3.8+
- Telegram Bot Token
- Chrome/Chromium（itdog 浏览器自动化需要）
- agent-browser（可选，用于 itdog 持续测试）

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/lucifer988/IP-.git /opt/ip-analyzer-pro
cd /opt/ip-analyzer-pro
```

### 2. 安装依赖

```bash
# 安装系统依赖
apt-get update
apt-get install -y python3 python3-pip nodejs npm curl google-chrome-stable

# 安装 Python 依赖
pip3 install python-telegram-bot requests --break-system-packages
```

### 3. 配置

创建 `config.json`：

```json
{
  "telegram": {
    "bot_token": "你的TG_Bot_Token",
    "admin_id": "你的TG_ID"
  },
  "itdog_wait_seconds": 35,
  "only_admin": false
}
```

### 4. 启动

```bash
# 直接运行
python3 /opt/ip-analyzer-pro/app.py

# 或使用 systemd 服务
systemctl start ip-analyzer-pro
```

## 一键安装

```bash
bash <(curl -sL https://raw.githubusercontent.com/lucifer988/IP-/main/install.sh)
```

安装脚本会：
1. 检查系统依赖
2. 安装 Python 依赖
3. 交互式配置 TG Bot
4. 创建 systemd 服务

## Telegram 命令

| 命令 | 说明 |
|------|------|
| `/start` | 启动机器人 |
| `/help` | 显示帮助 |
| `<IP>` | 分析单个 IP |
| `<IP1> <IP2>` | 对比两个 IP |
| `状态` | 查看服务状态 |

## 输出格式

### itdog 测试
- 国内：广东/广西三网（电信/联通/移动）测速结果
- 海外：美国、日本、新加坡、德国四国延迟

### BGP 分析
- ASN 编号
- 上游运营商
- T1 网络识别
- 互联国家

## 服务管理

```bash
# 启动
systemctl start ip-analyzer-pro

# 停止
systemctl stop ip-analyzer-pro

# 重启
systemctl restart ip-analyzer-pro

# 状态
systemctl status ip-analyzer-pro

# 日志
journalctl -u ip-analyzer-pro -f
```

## 目录结构

```
ip-analyzer-pro/
├── app.py           # 主程序
├── config.json      # 配置文件
├── install.sh       # 安装脚本
├── uninstall.sh     # 卸载脚本
└── bot.lock         # 运行锁文件
```

## 获取 Telegram Bot Token

1. 打开 @BotFather
2. 发送 `/newbot`
3. 按提示设置名称和用户名
4. 复制 Bot Token

## 获取 Telegram ID

发送 `/start` 给 @userinfobot 或 @getidsbot

## License

MIT