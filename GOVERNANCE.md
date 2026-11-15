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

## 审批

- 代码变更按 [.github/CODEOWNERS](.github/CODEOWNERS) 路由到维护者。
- 合并前必须通过 [.github/workflows/ci.yml](.github/workflows/ci.yml) 的必需检查。
- 治理文件（本文件、MAINTAINERS.md、CODE_OF_CONDUCT.md、SECURITY.md、CODEOWNERS）的修改，在 PR 里单独一节写动机与影响。

## 分支与门禁

- 默认分支 master 只接受 Pull Request。
- 必需检查：代码质量检查、前端构建、编译、运行测试、浏览器端到端测试。
- 禁止 force-push，禁止删除默认分支。
- 维护者保留紧急绕过权限，绕过必须在 PR 或提交信息里写明原因。

## 发布

- 推送 v* tag 触发 [.github/workflows/release.yml](.github/workflows/release.yml)；版本号来源是 [CHANGELOG.md](CHANGELOG.md)。
- 已发布的版本不重打、不复用；坏发布用新的补丁版本修正。

## 已知单点与补偿

- 单一维护者，没有第二管理员。
- 补偿：默认分支受保护、必需检查可执行、发布走 tag、历史公开可审计。
- 补齐路径：增加第二名管理员，并在 [MAINTAINERS.md](MAINTAINERS.md) 记录继任安排。
