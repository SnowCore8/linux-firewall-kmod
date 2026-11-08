# 引擎层：现在谁在跑模型，为什么不换

状态：`run-agent` 这层接线已落地；把 `QwenLM/qwen-code-action@v1` 换成自建执行体仍是提案。
本文只记判据和还没弄清的问题，不记实施步骤。

什么时候读：要动 `.github/actions/`、给某个角色加预算，或想弄清 `qwen-code-action@v1`
替我们做了哪几步时。

## 1. 现状

`.github/actions/run-agent/action.yml` 做三件事：读 `.github/agents/<role>.json` 当 settings、
调 `QwenLM/qwen-code-action@v1`、收尾判一次「最后那段话是不是 API 报错」。四份角色工作流都走它。

action 本身不干活，真正跑的仍是 qwen CLI。四个人现在的差异只有三处：`prompt`、`settings`、
注入的环境变量。

## 2. 为什么还想换掉它

| 现在 | 后果 |
|---|---|
| 只靠 job 级 `timeout-minutes` 兜底 | 超时是 SIGKILL，评论可能只写一半，且没有失败原因 |
| `qwen_cli_version` 默认 `latest` | 每次跑的 CLI 版本可能不同，行为漂移无法复现 |
| 调用形式固定为 `qwen --yolo --prompt ...` | `--prompt` 已被 CLI 标记 deprecated，推荐用 positional |
| 中间层只认自己的 input | `--max-wall-time`、`--max-tool-calls`、`--max-session-turns` 透不出来 |

收益只有一条：每一行归我们控制。代价是 action 代劳的那几件小事要自己做一遍。

## 3. 不合并四个人

不把四个人压成一个带 `role` 输入的 job：权限模型会退化成一套。顾清是 `contents: read` +
`issues: write`，陈实是 `contents: write` + 自己的 App；合成一个 job 只能有一套权限，等于把
边界收窄成「都有写权限」。`maxSessionTurns` 也不同：陈实要跑很多轮，顾清不需要。可维护性
用共享 composite action 解决，不必动权限粒度。

## 4. 换的话，形态是什么

还是这个位置上的 composite action，内部直接调 CLI：装指定版本的 `@qwen-code/qwen-code` →
写 `.qwen/settings.json` → `qwen "<prompt>" --yolo --channel=CI --output-format json` → 取最后
一条 assistant 文本 → 归档 `out.json` / `err.log` → 映射退出码。`--yolo` 与 `--channel=CI`
都不能省：非交互环境没有审批通道，后者影响 CLI 面向 CI 的内部行为。

`.github/agents/<role>.json` 原样搬过去，包括 `tools.core` 白名单、两个 MCP 和
`maxSessionTurns`。四份工作流只保留自己的权限、App 身份和 prepare 步骤，「跑模型」这一步
继续 `uses: ./.github/actions/run-agent`。

## 5. 动手前得先弄清

- **git 身份从哪来**：`action.yml` 里没有 `git config user.name/user.email`，陈实现在能提交，
  说明身份来自 CLI 在 `--channel=CI` 下的内置默认值，或他自己执行过 `git config`。换实现前
  要在日志里确认并显式配置，否则会出现「本地能提交、CI 报 author unknown」。
- **推送凭据**：`actions/checkout` 用的是 App token，新实现不能覆盖 remote。
- **退出码 55**：CLI 的预算耗尽码（`--max-wall-time` 或 `--max-tool-calls` 触发）。要单独识别
  成「预算耗尽」并写进 step summary，不能当普通失败——这是换实现最实在的改进。
- **`Install Custom Commands` 那个 `cp`**：action 无条件执行
  `cp -r "${GITHUB_ACTION_PATH}/.github/commands/"* .qwen/commands/`，而 `v1` 标签下没有这些
  文件。它的实际行为（静默失败还是步骤失败）未核实。本仓库不存在 `.qwen/commands/`：
  四个人的岗位说明都在 `.qwen/workflows/`，所以这一行对我们拷不到任何东西。那一步如果真的
  写失败并让整个 action 失败，四个人的每一轮都会停在第一步 —— 第一次真跑时先看日志确认。
