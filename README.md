# 🔑 ywsj-kms

轻量级 KMS 激活服务，基于 [vlmcsd](https://github.com/Wind4/vlmcsd) 构建，Docker 一键部署。

支持激活 Windows Vista/7/8/8.1/10/11/Server 及 Office 2010-2021 全系列。

## 🚀 快速开始

**方式一：docker run**

```bash
docker run -d \
  --name ywsj-kms \
  -p 1688:1688 \
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
      - "1688:1688"
    environment:
      - TZ=Asia/Shanghai
```

```bash
docker compose up -d
```

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

## ✨ 特点

- **极致轻量**：基于 Alpine + vlmcsd，镜像仅 ~3MB
- **多架构**：支持 amd64 + arm64
- **非 root 运行**：容器以 kms 用户启动，更安全
- **自动 CI**：push 代码自动构建推送到 Docker Hub
- **零配置**：启动即用，无需额外参数

## 🐧 Linux 服务器验证

服务启动后，在服务器上验证：

```bash
# 检查端口是否监听
ss -tlnp | grep 1688

# 测试连接
nc -zv 127.0.0.1 1688
```

## 🛠️ 技术栈

- **KMS 核心**：[vlmcsd](https://github.com/Wind4/vlmcsd)（开源 KMS 服务器模拟器）
- **基础镜像**：Alpine Linux
- **构建**：Docker multi-stage build + GitHub Actions CI

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
