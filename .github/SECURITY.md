# 安全策略

这个仓库跑在别人的仓库里，漏洞的影响面通常超出本仓库本身。

管什么：支持哪些版本、漏洞走哪条渠道报、报告里该带什么、处理结论写到哪、哪些已知取舍不算漏洞。
什么时候读：发现可能的安全问题，或要判断某条报告该不该公开。

## 支持范围

本项目是一个仓库自动化模板，默认按最新发布版本（见 [Releases](https://github.com/SnowCore8/github-workflow/releases)）维护。更早的版本不做安全修复，升级方式是从新 tag 重新复制文件。

## 报告漏洞

本项目由 AI 代理团队维护，没有人工值守的安全响应团队。

**不要开公开 Issue。** 公开 Issue 会把利用方式一并公开，而这个仓库跑在别人的仓库里。

按敏感程度选一条：

1. **优先**：用 GitHub 的 [Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability) 提交私密报告。仓库开启该功能后，入口在 **Security → Report a vulnerability**。
2. 该功能不可用时，开一个公开 Issue，标题以 `[Security]` 开头，**只写影响面与联系方式**，不写复现步骤、不写 PoC。顾清会接手，并把话题转到私下渠道。

报告里请带上：

- 影响的是哪一层（工作流、脚本、凭据用法、闸门）；
- 受影响的版本或提交；
- 影响范围：能让谁拿到什么、能不能绕过闸门、能不能读到密钥；
- 修复建议（有就写，没有也行）。

## 响应承诺

- 不承诺响应时间（SLA）。这个仓库按事件驱动，没有值班表。
- 报告提交后由顾清按常规流程接手，严重问题优先标记。
- 处理结论会写进对应 Issue 或私密报告，不静默关闭。

## 注意事项

- 请勿在公开渠道披露未修复漏洞的完整利用细节。
- 密钥的值不要出现在报告、Issue、评论或日志里。需要说明是哪一类凭据时，只写变量名（如 `APP_PRIVATE_KEY_MILES`）。
- 本项目已知的残余风险写在 [README 的「安全」一节](../README.md#-安全)，报告前先确认是不是已经写在里面 —— 那部分属于设计取舍，不是新漏洞。
