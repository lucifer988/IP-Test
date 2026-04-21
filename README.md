# IP Analyzer Pro (Telegram Bot)

一个可直接部署的 Telegram IP 分析机器人。
输入 `IP` 或 `域名`，返回：

- 基础归属信息（ASN / 持有者 / 国家地区 / 组织 / 路由前缀）
- DNSBL 纯净度（Spamhaus / Spamcop / Barracuda）
- itdog 国内聚焦（仅广东/广西三网）
- itdog 海外四国（美国/日本/新加坡/德国，固定顺序）
- BGP 路由情报（上游、AS Path、T1 命中）

---

## 特性

- **Telegram 交互**：直接聊天输入 IP/域名即可分析
- **国内结果聚焦**：只展示广东/广西 电信/联通/移动，信息更干净
- **海外固定四国**：美国、日本、新加坡、德国，输出统一
- **BGP 双数据源**：`bgp.tools Prefix Connectivity` + `RIPE Stat`（补充）
- **弱网兜底**：itdog 等待 + 补测择优，降低海外缺组概率
- **单实例锁**：防止多实例重复轮询导致 Telegram `Conflict`

---

## 运行要求

- Ubuntu / Debian（推荐）
- Python 3.8+
- `python-telegram-bot`、`requests`
- Google Chrome / Chromium
- `agent-browser`（用于 itdog 页面自动化）

---

## 快速安装

### 1) 克隆

```bash
git clone https://github.com/lucifer988/IP-Test.git /opt/ip-analyzer-pro
cd /opt/ip-analyzer-pro
```

### 2) 运行安装脚本

```bash
sudo bash install.sh
```

安装脚本会自动：

1. 检查并安装依赖
2. 交互写入 `config.json`
3. 创建 `systemd` 服务 `ip-analyzer-pro`
4. 可选立即启动

---

## 配置说明（config.json）

```json
{
  "telegram": {
    "bot_token": "YOUR_BOT_TOKEN_HERE",
    "admin_id": "YOUR_TG_ID_HERE"
  },
  "itdog_wait_seconds": 55,
  "only_admin": false
}
```

- `bot_token`：@BotFather 申请
- `admin_id`：管理员 TG 数字 ID（可留空）
- `itdog_wait_seconds`：itdog 等待秒数（建议 45~60）
- `only_admin`：是否仅管理员可用

---

## Bot 使用

| 输入 | 说明 |
|---|---|
| `/start` | 查看机器人说明 |
| `/status` | 查看运行参数 |
| `1.1.1.1` | 分析单个 IP |
| `example.com` | 自动解析域名并分析 |
| `1.1.1.1 8.8.8.8` | 一次分析多个目标（最多取前3个） |

---

## 输出格式（示例结构）

```text
IP 分析: 1.1.1.1

基础信息
- ASN: AS13335
- 持有者: Cloudflare, Inc.
...

itdog 国内聚焦: 广东/广西 三网，命中 6 组
- 广东电信: ...
...

itdog 海外: 美国/日本/新加坡/德国，命中 4/4 组
- 美国: ...
- 日本: ...
- 新加坡: ...
- 德国: ...

BGP 路由情报
- 数据源: bgp.tools Prefix Connectivity + RIPE Stat(补充)
- AS Path: ...
- 上游（共N条）
- T1 in Path（共N个）
```

---

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
journalctl -u ip-analyzer-pro -f --no-pager
```

---

## 卸载

```bash
sudo bash uninstall.sh
```

会停止并移除服务、删除 `/opt/ip-analyzer-pro`、清理残留浏览器会话。

---

## 项目结构

```text
IP-Test/
├── app.py
├── config.json
├── install.sh
├── uninstall.sh
├── README.md
└── .gitignore
```

---

## License

MIT
