# 贡献指南

感谢你对 DnsDefender 的关注。

## 开始之前

- 请先阅读 [README.md](README.md) 与 [SECURITY.md](SECURITY.md)
- 本项目仅用于授权防御排查与安全研究场景

## 开发环境

- Windows 10/11
- .NET SDK 8.x

## 本地开发流程

```bash
dotnet restore DnsDefender.sln
dotnet build DnsDefender.sln -c Release
dotnet test tests/DnsDefender.Collector.Tests/DnsDefender.Collector.Tests.csproj -c Release
```

## 分支与提交建议

- 分支命名：`feature/*`、`fix/*`、`docs/*`
- 提交信息建议使用清晰动词开头（如：`fix:`, `feat:`, `docs:`）

## Pull Request 要求

提交 PR 前请确认：

- [ ] 已通过构建与测试
- [ ] 变更范围清晰，避免混入无关改动
- [ ] 涉及行为变化时已更新文档
- [ ] 涉及安全相关逻辑时已说明风险与验证方法

## 代码风格

- 保持与现有代码风格一致
- 避免引入不必要抽象
- 仅在必要处增加注释

## 问题反馈

- 一般缺陷/需求：使用 GitHub Issue 模板
- 安全漏洞：请走私密流程，见 [SECURITY.md](SECURITY.md)
