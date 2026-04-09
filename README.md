# DNS解析溯源工具（DnsDefender）

**工具中文名：DNS解析溯源工具**。

DnsDefender 是一个面向 **Windows 授权防御排查场景** 的 DNS 解析溯源工具，用于记录 DNS 请求并尽可能关联到进程信息，帮助定位“谁在解析什么域名”。

> 仅限授权环境使用（防御排查）。请勿用于未授权目标。

## 核心能力

- 多通道采集 DNS 数据：
  - ETW（主链路）
  - NameResolution ETW（增强归因）
  - DNS-Operational 日志（降级链路）
  - 网卡抓包 DNS（可选）
- 进程归因与关联：PID、进程名、可执行路径、归因状态、置信度
- 查询与筛选：按域名关键字、时间范围过滤
- 数据导出：CSV / JSON
- 图形界面：WPF 桌面应用

## 运行环境

- **支持范围（按项目目标框架）**：`net6.0-windows7.0`，最低为 Windows 7 SP1 及以上
- **Server 系统**：支持与上述内核/版本对应的 Windows Server 版本（建议使用较新受支持版本）
- 建议管理员权限运行（ETW 采集能力更完整）
- .NET SDK 8.x（用于构建）

## 各系统能力差异说明

> 以下为工程与代码路径可确认的能力差异：

- **Windows 7 SP1 / 早期 Server（同代内核）**
  - 可运行主程序（基于 `net6.0-windows7.0`）。
  - ETW 相关能力可能受系统补丁与权限限制，工具会自动尝试降级到 DNS-Operational 或抓包链路。
  - 抓包能力依赖 Npcap，需手动安装并启用兼容模式。

- **Windows 10/11 / 较新 Server**
  - 通常可获得更完整的 ETW + NameResolution + DNS-Operational + PCAP 组合能力。
  - 仍建议以管理员权限运行以保证采集稳定性。

- **共同说明**
  - 工具具备自动降级逻辑：当 ETW 不可用时，会自动切换到 DNS-Operational/PCAP 可用链路。
  - 实际可用能力以启动后的“能力探测”结果为准。

## 抓包依赖组件（最低版本）

- **Npcap：1.79+（最低推荐）**
  - 安装地址：https://npcap.com/#download
  - 安装时请勾选 **WinPcap API-compatible Mode**
  - 该最低版本要求来自代码内置提示：`src/DnsDefender.Collector/Pcap/PacketCaptureDnsWatcher.cs`

- **SharpPcap：6.3.0（项目 NuGet 依赖）**
  - 定义位置：`src/DnsDefender.Collector/DnsDefender.Collector.csproj`


## 快速开始

### 1) 直接下载 Release

1. 进入仓库 Releases 页面
2. 下载对应架构压缩包：
   - `DnsDefender-<tag>-win-x64.zip`
   - `DnsDefender-<tag>-win-x86.zip`
3. 解压后运行 exe

### 2) 本地源码运行

```bash
dotnet restore DnsDefender.sln
dotnet build DnsDefender.sln -c Release
dotnet run --project src/DnsDefender.UI/DnsDefender.UI.csproj -c Release
```

## 本地发布（生成 exe）

```bash
# win-x64
dotnet publish src/DnsDefender.UI/DnsDefender.UI.csproj \
  -c Release \
  -r win-x64 \
  --self-contained true \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true

# win-x86
dotnet publish src/DnsDefender.UI/DnsDefender.UI.csproj \
  -c Release \
  -r win-x86 \
  --self-contained true \
  -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true
```

## 自动发布（GitHub Actions）

仓库已提供 `/.github/workflows/release.yml`：

- 推送标签 `v*`（如 `v3.14.0`）后自动触发
- 自动构建 `win-x64` 与 `win-x86`
- 自动打包 zip 并上传到 GitHub Release

## 项目结构

```text
DnsDefender.sln
src/
  DnsDefender.Common/
  DnsDefender.Collector/
  DnsDefender.UI/
tests/
  DnsDefender.Collector.Tests/
```

## 测试

```bash
dotnet test tests/DnsDefender.Collector.Tests/DnsDefender.Collector.Tests.csproj -c Release
```

## 常见问题

### 为什么建议管理员权限运行？

部分 ETW 能力在非管理员权限下可能受限，程序会尝试自动降级到日志/抓包链路。

### 为什么看不到抓包网卡？

请确认本机抓包环境与驱动已正确安装，并在界面中启用“网卡抓包DNS”。

## 安全与合规

- 安全漏洞报告：见 [SECURITY.md](SECURITY.md)
- 贡献指南：见 [CONTRIBUTING.md](CONTRIBUTING.md)
- 行为准则：见 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## 许可证

本项目使用 [MIT License](LICENSE)。
