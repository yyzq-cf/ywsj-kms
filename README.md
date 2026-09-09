# 🔑 ywsj-kms

轻量级 KMS 激活服务 + Web 监控面板，基于 [vlmcsd](https://github.com/Wind4/vlmcsd) 构建，Docker 一键部署。

支持激活 Windows Vista/7/8/8.1/10/11/Server 及 Office 2010-2021 全系列。实时查看哪些机器激活了什么产品。

## ✨ 功能特性

- **KMS 激活服务**：基于 vlmcsd，支持 Windows + Office 全系列
- **Web 监控面板**：实时查看激活记录、客户端信息、产品类型
- **登录认证**：用户名密码登录，Session 验证
- **防暴力破解**：同一 IP 5 次失败后封禁 5 分钟，含倒计时提示
- **多架构**：支持 amd64 + arm64
- **极致轻量**：Alpine + Python multi-stage build
- **自动 CI**：push 代码自动构建推送到 Docker Hub

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

**方式二：docker-compose.yml**

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
      - ./data:/data    # 数据持久化(激活日志数据库)
    environment:
      - TZ=Asia/Shanghai
      - ADMIN_USER=admin       # Web面板用户名
      - ADMIN_PASS=kms123456   # Web面板密码(首次启动后建议修改)
```

```bash
docker compose up -d
```

访问 `http://your-ip:8080`，默认账号 `admin / kms123456`

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
- 分页浏览
- 点击「详情」查看完整激活信息（协议版本、SKU ID、ePID、许可状态等）
- 原始 vlmcsd 日志

### 安全
- **登录认证**：所有 API 需登录后才能访问
- **防暴力破解**：同一 IP 连续 5 次密码错误后封禁 5 分钟
- **Session 过期**：1 小时无操作自动登出
- **剩余次数提示**：每次失败显示剩余尝试次数
- **封禁倒计时**：封禁期间显示剩余解锁时间

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
| `ADMIN_USER` | admin | Web面板用户名 |
| `ADMIN_PASS` | kms123456 | Web面板密码 |
| `KMS_SECRET_KEY` | (随机生成) | Session加密密钥，生产环境建议固定 |
| `WEB_PORT` | 8080 | Web面板端口 |
| `KMS_PORT` | 1688 | KMS服务端口 |
| `TZ` | Asia/Shanghai | 时区 |

## 🐧 Linux 服务器验证

```bash
# 检查KMS端口
ss -tlnp | grep 1688

# 检查Web面板
curl -s http://127.0.0.1:8080/api/check
```

## 📁 项目结构

```
ywsj-kms/
├── app.py                 # Flask主应用(KMS启动+日志解析+API)
├── templates/
│   ├── index.html         # 仪表盘页面
│   └── logs.html          # 激活日志页面
├── requirements.txt
├── Dockerfile             # Multi-stage build (vlmcsd + Python)
├── docker-compose.yml
└── .github/workflows/
    └── docker-publish.yml # CI: amd64+arm64
```

## 🛠️ 技术栈

- **KMS核心**：[vlmcsd](https://github.com/Wind4/vlmcsd)（开源 KMS 服务器）
- **后端**：Flask + SQLite + Werkzeug
- **前端**：原生 HTML/CSS/JS（亮色/暗色主题，响应式）
- **部署**：Docker multi-stage + GitHub Actions CI

## 📦 GitHub

源码：https://github.com/yyzq-cf/ywsj-kms  
Docker Hub：https://hub.docker.com/r/ywsj/ywsj-kms

## 🙏 致谢

- [**vlmcsd**](https://github.com/Wind4/vlmcsd) — 核心KMS服务组件
- [**netnr/kms**](https://github.com/netnr/kms) — 激活步骤参考

## ⚠️ 免责声明

本项目仅供学习和测试用途。请通过正规渠道获取 Windows 和 Office 许可证，支持正版软件。使用本项目产生的一切后果由使用者自行承担。

## 📝 License

MIT
