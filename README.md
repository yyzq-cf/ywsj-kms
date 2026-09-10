# 🔑 ywsj-kms

轻量级 KMS 激活服务 + Web 监控面板，基于 [vlmcsd](https://github.com/Wind4/vlmcsd) 构建，Docker 一键部署。

支持激活 Windows Vista/7/8/8.1/10/11/Server 及 Office 2010-2021 全系列。实时查看哪些机器激活了什么产品。

## ✨ 功能特性

### KMS 激活服务
- 基于 vlmcsd（固定 commit 70e0357），支持 Windows + Office 全系列
- 激活超时 30 秒自动断开，支持高并发
- 日志实时解析入库，毫秒级记录

### Web 监控面板
- **仪表盘**：总激活次数、不同 IP/机器/工作站数、今日激活、按产品统计、24h 趋势柱状图、活跃工作站 Top 10、最近激活记录
- **日志页面**：全部激活日志，支持搜索（IP、工作站名、机器 ID）、按产品筛选、分页浏览、详情弹窗（协议版本、SKU ID、ePID、许可状态等）、原始 vlmcsd 日志
- **设置页面**：在线修改用户名、修改密码、2FA 两步验证管理
- **主题**：暗色/亮色一键切换，自动记忆
- **响应式**：手机/平板/桌面自适应

### 安全特性
- 🔐 **两步验证（2FA）**：支持 TOTP 标准（Google Authenticator / Microsoft Authenticator 等扫码绑定），登录需密码 + 验证码双重验证
- 🛡️ **CSRF 防护**：所有 POST 请求需携带 CSRF Token
- 🔒 **存储型 XSS 防护**：前端所有 API 数据经 HTML 转义，CSP 安全策略
- 🚫 **防暴力破解**：同一 IP 5 次密码错误后封禁 5 分钟，2FA 验证码最多 5 次尝试
- 🔑 **SECRET_KEY 持久化**：重启后 session 不失效
- 🍪 **Cookie 安全**：HttpOnly + SameSite=Lax
- 📋 **安全响应头**：X-Frame-Options DENY、X-Content-Type-Options nosniff、CSP、Referrer-Policy
- 👤 **非 root 运行**：容器内以 appuser (UID 1000) 运行
- 🚦 **API 限流**：认证后 API 每分钟 60 次请求限制
- 📦 **vlmcsd 版本固定**：构建时 pin 到指定 commit，防止供应链投毒
- 🚷 **no-new-privileges**：容器禁止提权
- 🔢 **分页参数校验**：非整数页码优雅降级
- 📏 **请求体大小限制**：2KB 上限防 DoS
- 🌐 **XFF 伪造防护**：直连模式下完全忽略 X-Forwarded-For

### 运维特性
- **Session 24 小时有效**：登录后关闭浏览器再打开无需重新登录
- **在线改密/改用户名**：需当前密码验证
- **数据导出**：一键导出全部激活日志 JSON
- **健康检查**：Docker HEALTHCHECK 自动监控 Web 面板存活
- **自动 CI**：push 代码自动构建 amd64 + arm64 推送到 Docker Hub

## 🚀 快速开始

**方式一：docker run**

```bash
docker run -d \
  --name ywsj-kms \
  -p 1688:1688 \
  -p 8080:8080 \
  -v ./data:/data \
  --restart always \
  ywsj/ywsj-kms:latest
```

**方式二：docker-compose.yml**（推荐）

```yaml
services:
  kms:
    image: ywsj/ywsj-kms:latest
    container_name: ywsj-kms
    restart: always
    ports:
      - "1688:1688"     # KMS服务端口
      - "8080:8080"     # Web监控面板端口
    volumes:
      - ./data:/data    # 数据持久化(数据库 + secret_key)
    environment:
      - TZ=Asia/Shanghai
      - ADMIN_USER=admin       # Web面板用户名(仅首次启动)
      - ADMIN_PASS=kms123456   # Web面板密码(首次启动后建议在设置页修改)
    security_opt:
      - no-new-privileges:true
```

```bash
docker compose up -d
```

访问 `http://your-ip:8080`，默认账号 `admin / kms123456`

> ⚠️ **安全建议**：首次登录后请到「设置」页面修改密码并启用两步验证（2FA）

## 🖥️ Web 监控面板

### 仪表盘
- 总激活次数、不同 IP/机器/工作站数、今日激活
- 按产品类型统计（Windows / Office）+ 占比
- 24 小时活动趋势柱状图
- 活跃工作站 Top 10
- 最近激活记录

### 日志页面
- 全部激活日志，支持搜索（IP、工作站名、机器 ID）
- 按产品类型筛选
- 分页浏览（每页 20 条，可自定义）
- 点击「详情」查看完整激活信息（协议版本、SKU ID、ePID、许可状态等）
- 原始 vlmcsd 日志

### 设置页面
- 查看当前账户信息
- 修改用户名（需当前密码验证）
- 修改密码（需当前密码验证）
- 两步验证（2FA）：扫码绑定 / 输入验证码确认 / 输入密码解绑

### 登录页面
- 用户名 + 密码登录
- 启用 2FA 后需输入验证码二次验证
- 防暴力破解：5 次失败后 IP 封禁 5 分钟，含倒计时
- 登录框底部 GitHub 链接

## 🔐 两步验证（2FA）

1. 登录后进入「设置」页面
2. 点击「启用两步验证」
3. 用 Google Authenticator / Microsoft Authenticator 等扫描二维码
4. 输入 APP 显示的 6 位验证码确认绑定
5. 此后每次登录需输入密码 + 验证码

**安全机制**：
- 验证码 3 分钟内有效
- 最多 5 次尝试，超限需重新登录
- 验证成功后 token 立即作废，不可重用
- 解绑需输入当前密码

## 📖 激活方法

> 以下命令在 Windows 上以**管理员身份**运行 CMD/PowerShell

### Windows 系统

```cmd
:: 1. 设置KMS服务器地址
slmgr /skms 你的服务器IP:1688

:: 2. 安装系统对应的GVLK密钥（见下方密钥表）
slmgr /ipk W269N-WFGWX-YVC9B-4J6C9-T83GX

:: 3. 激活
slmgr /ato

:: 4. 查看激活状态
slmgr /xpr
```

### Office

```cmd
:: 1. 进入Office安装目录
cd "C:\Program Files\Microsoft Office\Office16"

:: 2. 设置KMS服务器
cscript ospp.vbs /sethst:你的服务器IP
cscript ospp.vbs /setprt:1688

:: 3. 激活
cscript ospp.vbs /act

:: 4. 查看状态
cscript ospp.vbs /dstatus
```

## 🔧 常用 GVLK 密钥

| 系统/产品 | GVLK 密钥 |
|-----------|----------|
| Windows 10/11 Pro | `W269N-WFGWX-YVC9B-4J6C9-T83GX` |
| Windows 10/11 Enterprise | `NPPR9-FWDCX-D2C8J-H872K-2YT43` |
| Windows 10/11 Enterprise LTSC 2021 | `M7XTQ-FN8P6-TTKYV-9D4CC-J462D` |
| Windows Server 2022 Standard | `VDYBN-27WPP-V4HQT-9VMD4-VMK7H` |
| Windows Server 2022 Datacenter | `WX4NM-KYWYW-QJJR4-XV3QB-6VM33` |
| Windows Server 2019 Standard | `N69G4-B89J2-4G8F4-WWYCC-J464C` |
| Windows Server 2019 Datacenter | `WMDGN-G9PQG-XVVXX-R3X43-63DFG` |
| Office LTSC 2021 | `H7CNH-BH3V9-W4RQ3-3J6M9-6M2JB` |
| Office 2019 | `N3KWD-AG8YR-9W4DQ-TJK3Y-8MV92` |
| Office 2016 | `XQNVK-8JHYD-7P7M3-9F8QT-VKRB4` |

> 更多密钥请参考微软官方文档：https://learn.microsoft.com/windows-server/get-started/kms-client-activation-keys

## ⚙️ 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ADMIN_USER` | admin | Web面板用户名（仅首次启动创建账号） |
| `ADMIN_PASS` | kms123456 | Web面板密码（首次启动后建议在设置页修改） |
| `TRUSTED_PROXY_HOPS` | 0 | 受信任代理跳数（直连=0，单层nginx反代=1） |
| `API_RATE_LIMIT` | 60 | API 限流（每分钟请求数） |
| `SESSION_COOKIE_SECURE` | 0 | 是否强制 HTTPS Cookie（1=启用） |
| `KMS_SECRET_KEY` | (持久化随机) | Session加密密钥（默认自动生成并持久化到 /data/secret_key.txt） |
| `WEB_PORT` | 8080 | Web面板端口（容器内） |
| `KMS_PORT` | 1688 | KMS服务端口 |
| `TZ` | Asia/Shanghai | 时区 |

## 🐧 Linux 服务器验证

```bash
# 检查KMS端口
ss -tlnp | grep 1688

# 检查Web面板
curl -s http://127.0.0.1:8080/api/check

# 检查容器健康状态
docker inspect ywsj-kms --format '{{.State.Health.Status}}'
```

## 📁 项目结构

```
ywsj-kms/
├── app.py                 # Flask主应用(KMS启动+日志解析+API+2FA+安全)
├── templates/
│   ├── index.html         # 仪表盘页面
│   ├── logs.html          # 激活日志页面
│   └── settings.html      # 设置页面(改密+改用户名+2FA管理)
├── entrypoint.sh          # 容器入口(权限修复+降权启动)
├── requirements.txt       # Python依赖(flask+gunicorn+pyotp)
├── Dockerfile             # Multi-stage build (vlmcsd + Python, 非root)
├── docker-compose.yml     # 编排配置(含安全选项)
├── .env.example           # 环境变量模板
└── .github/workflows/
    └── docker-publish.yml # CI: amd64+arm64
```

## 🛠️ 技术栈

- **KMS核心**：[vlmcsd](https://github.com/Wind4/vlmcsd)（开源 KMS 服务器，固定 commit）
- **后端**：Flask + Gunicorn + SQLite + Werkzeug + PyOTP
- **前端**：原生 HTML/CSS/JS（亮色/暗色主题，响应式，XSS 转义防护）
- **安全**：CSRF Token + TOTP 2FA + CSP + HttpOnly Cookie + 非 root 运行
- **部署**：Docker multi-stage + GitHub Actions CI（amd64 + arm64）

## 📦 GitHub & Docker Hub

源码：https://github.com/yyzq-cf/ywsj-kms  
Docker Hub：https://hub.docker.com/r/ywsj/ywsj-kms

## 🙏 致谢

- [**vlmcsd**](https://github.com/Wind4/vlmcsd) — 核心KMS服务组件
- [**netnr/kms**](https://github.com/netnr/kms) — 激活步骤参考
- [**pyotp**](https://github.com/pyauth/pyotp) — TOTP 两步验证库

## ⚠️ 免责声明

本项目仅供学习和测试用途。请通过正规渠道获取 Windows 和 Office 许可证，支持正版软件。使用本项目产生的一切后果由使用者自行承担。

## 📝 License

MIT
