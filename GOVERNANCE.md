# 治理

本仓库是公开项目，交付物由内核模块（C）、守护进程（Go）、面板（TypeScript）与契约生成器（Python）组成。

## 角色

| 角色 | 谁 | 权力 |
|------|----|------|
| 维护者 | [MAINTAINERS.md](MAINTAINERS.md) 列出的人 | 合并、发布、分配权限、裁决范围 |
| 贡献者 | 任何提交 PR 的人 | 开 Issue、提 PR、评审他人的改动 |

## 决策

- 模型：维护者主导，没有投票与共识门槛。
- 范围与优先级由维护者定；被关闭的请求会写理由，理由可被后续证据推翻。
- 架构级改动（契约、目录边界、依赖方向）先在 Issue 讨论，再动代码。
- AI 同事之间的僵持交给人裁决；人不在时取最小可行假设，并在评论里写明这是假设。

## 分支模型与合并

- 模型：主干开发（GitHub flow）。`master` 始终可发布；工作走短生命周期主题分支，分支名用 `类型/简短描述`（如 `fix/sse-stop-panic`）。
- 合并方式：只允许 squash merge。合并提交标题即 PR 标题，正文保留 PR 描述要点。
- 合并后自动删除主题分支。已合并分支的本地副本可以保留，远端不保留。
- 发布标签 `v*` 受保护：不移动、不删除、不复用。

## 审批与自审

- 代码变更按 [.github/CODEOWNERS](.github/CODEOWNERS) 路由到维护者。
- 合并前必须通过 [.github/workflows/ci.yml](.github/workflows/ci.yml) 的五项必需检查，且分支与 `master` 同步（strict）。
- 本仓库只有一名维护者，GitHub 不允许自我批准，因此必需批准数为 0。替代控制是**自审记录**：PR 描述中必须写完整 diff 已读、门禁命令与真实输出、未验证项与已知风险。缺自审记录的 PR 不合入。
- 批准后的实质性推送使旧批准失效（`dismiss_stale_reviews`）；自审记录同样需要按新 diff 重写。
- 治理文件（本文件、MAINTAINERS.md、CODE_OF_CONDUCT.md、SECURITY.md、CODEOWNERS）的修改，在 PR 里单独一节写动机与影响。

## 分支与门禁

默认分支 master 的常规入口是 Pull Request，必需检查为：代码质量检查、前端构建、编译、运行测试、浏览器端到端测试。
分支保护关闭了 force-push、默认分支删除与三条合并方式中的两条（只留 squash）。

管理员身份可以绕过以上规则（enforce_admins 关闭），这是为故障处置留的通道。每次绕过都要记录：操作者、原因、涉及提交，以及合并后复查结论。记录写在提交信息或 PR 描述里；没有记录的绕过按事故处理。

## 发布

- 推送 v* tag 触发 [.github/workflows/release.yml](.github/workflows/release.yml)；版本号来源是 [CHANGELOG.md](CHANGELOG.md)。
- 已发布的版本不重打、不复用；坏发布用新的补丁版本修正。

## 已知单点与补偿

- 单一维护者，没有第二管理员。
- 补偿：默认分支受保护、必需检查可执行、发布走 tag、历史公开可审计。
- 补齐路径：增加第二名管理员，并在 [MAINTAINERS.md](MAINTAINERS.md) 记录继任安排。
