# 合并闸门

管什么：谁能把 PR 合进主干、按什么条件判、判不过在哪儿能看到原因。
什么时候读：改 `.github/scripts/merge-gate.mjs`、`qwen-miles.yml` 的合并相关步骤、`.qwen/workflows/miles-fix.js` 的「收场」段落（申请就是在那儿写的），或遇到「PR 该合了但没合」「合了但不该合」。

## 一句话

模型判断该不该合，写一句申请；能不能合由脚本机械核对；合并这个动作由脚本执行。
模型手里没有 `gh pr merge`。

## 为什么不让模型自己合

写在提示词里的合并条件是给人读的清单：它只在执行者主动遵守时才生效，而闸门要在没人遵守时也生效。所以判据归脚本，模型只保留「申请」这一个动作。

## 分工

| 谁 | 做什么 |
|---|---|
| 陈实（模型） | 判断这一轮该不该合，写一行独占一段的 `<!-- qwen:merge-request -->`（最终回复或这轮最后那条评论都认） |
| `qwen-miles.yml` | 认出那一行（判据在 `merge-request.mjs`：先剥掉围栏与行内代码，再认独占一行的标记），把 PR 交给闸门；模型这一轮里 `gh` 被包了一层，`pr merge` 直接失败 |
| `qwen-miles.yml` 的 `gate` job | 闸门跑在模型那个 job 之后的独立 job 里，有自己的 `timeout-minutes`：等 CI 的预算不再和模型那一轮抢 |
| `merge-gate.mjs` | 逐条判定。通过就 squash 合并、删分支、把关联 Issue 的 checklist 勾上、关掉它；不通过就在 PR 上列出没过的那几条，退出码 1 |

申请只是一行标记，不是命令：模型不能指定合并方式、不能跳过某条判据。

合并之后那几步都在同一个函数里，顺带说清各自的失败处理：分支由 `gh pr merge --delete-branch` 一起删；checklist 逐行勾掉再整体回写（围栏里的示例不动，判据在 `markdown.mjs` 的 `tickCheckboxes`）；Issue 由 `gh issue close` 关闭。后两步失败都只写 stderr、不让整轮失败 —— 合并已经发生了，这时候报「闸门自己出错了」只会让人以为判据没过。checklist 一项都没勾到时也不回写，省一次写请求。

## 判据

只收能机械判的五条。「变更内容与 PR 描述一致」判不了，不在闸门里 —— 假装判了比不判更坏，这一条仍然靠模型自己看。

| id | 判什么 | 判据 |
|---|---|---|
| `approval-at-head` | 当前提交上有仍然成立的批准 | `reviews` 里存在 `commit.oid == headRefOid` 的 `APPROVED`，且比同一提交上任何 `CHANGES_REQUESTED` 新 |
| `no-stop-label` | 没有 `do-not-merge` / `manual-review` | 标签名精确匹配 |
| `not-draft` | 不是草稿 | `isDraft` |
| `not-conflicting` | 不和主干冲突 | `mergeable == 'CONFLICTING'` 才拦；`UNKNOWN` 放行 |
| `checks` | 检查跑完且没有失败 | 见下 |

`mergeable` 只拦 `CONFLICTING`：GitHub 这个字段懒计算，刚推完提交经常返回 `UNKNOWN`，按「必须是 MERGEABLE」判会让该合的 PR 永远合不了。真冲突由 `gh pr merge` 自己拒绝。

### 检查项怎么折算

每一项归成 `PENDING` / `FAILURE` / `SUCCESS`：

- `status` 不是 `COMPLETED` → `PENDING`
- `conclusion` ∈ `FAILURE`/`ERROR`/`TIMED_OUT`/`CANCELLED`/`ACTION_REQUIRED` → `FAILURE`
- 老式 `StatusContext` 用 `state` 而不是 `conclusion`，`FAILURE`/`ERROR` 同样算失败
- `SKIPPED` / `NEUTRAL` / 认不出来 → `SUCCESS`（被跳过的 job 不代表代码有问题）

`statusCheckRollup` 里两种元素混着出现，只看 `conclusion` 会把老式状态上下文里的红的说成绿的，所以单独实现，没复用 `patrol.mjs` 的 `rollupState`。

### 这些检查里得有一套真的在验脚本

`checks` 判的是「PR 上所有检查项都跑完且没有失败」，不区分是谁跑的。所以这套判据可信到什么程度，取决于 PR 上那些检查项本身有没有在验东西。

这个仓库里 `ci.yml` 已经在验代码（编译、`go test`、前端构建、契约漂移、端到端），但它**不验 `.github/scripts/` 里那层判断逻辑**——路由、巡检、闸门的判据写歪了，`ci.yml` 一条都不会红。

`.github/workflows/qwen-ci.yml` 补的就是这一环：在 PR 上跑 `.github/scripts/*.test.mjs`，外加工作流脚本与引擎配置的语法校验（`node --check .qwen/workflows/*.js`、`json.load(.github/agents/*.json)`），检查项名字是 `qwen test`。

它必须是**独立 workflow**：`withoutOwnRun()` 会按 `/runs/<runId>/` 剔掉闸门自己那次运行，塞进 `qwen-miles.yml` 的 job 会被当成自检滤掉，加了等于没加。

job 键与显示名都不能叫 `test` —— `ci.yml` 里已经有一个 `test`（显示名「运行测试」）。两个同名检查项挂在同一个提交上，看日志和写判据的人分不清是哪一条红的。

还有一条反过来要留意：`checkState()` 把 `SKIPPED` 判成 `SUCCESS`。所以 `qwen-ci.yml` 不加 `paths` 过滤 —— 按改动类型跳过，显示的是绿而不是「没跑」，那等于让闸门对着没验过的提交放行。

### 闸门自己那次运行

闸门跑在陈实那次运行里，而那次运行本身就是 PR 上的检查项（`route`、`miles / work`、`miles / gate` 等）。不剔掉的话 `isPending` 永远看到自己在跑：先白等满 `MILES_CI_WAIT_MINUTES`，再以「还有检查在跑」拦下自己 —— 每张 PR 都合不了。

闸门装在独立的 `gate` job 里，但**同一个 workflow run**，`GITHUB_RUN_ID` 一样，所以按 runId 剔除仍然把 `miles / work` 和 `miles / gate` 一起滤掉。

所以取回 `statusCheckRollup` 之后先滤掉 `detailsUrl` 里带 `/runs/$GITHUB_RUN_ID/` 的项，判据和等待都对着滤完的列表算。`GITHUB_RUN_ID` 只有 CI 里有，本地跑为空，一个都不剔。

### 主干本来就红的时候

主干已经红着的时候，按「检查没有失败」任何 PR 都合不了，而修它又得先把 PR 合进去 —— 死循环。闸门为此去 base 分支查同名检查：

```
GET /repos/{repo}/commits/{base_sha}/check-runs?check_name=<name>&filter=latest
```

base 上最新一次同名检查也失败，这一项算「预存在」，放行，并在合并说明里写明是哪一项。任一环节查不到（分支哈希取不到、接口报错）都按「不是预存在」处理 —— 宁可拦下来让人看，也不能凭空放行。

「预存在」只豁免**失败**这一种：只要有检查还在跑，就先拦，不看预存在。两种情形会同时出现（主干红着、PR 上另有一项刚被叫起来还在跑），判定的先后顺序因此是固定的：非预存在的失败 → 还在跑 → 只有预存在的失败。反过来排会让第二种情形借「主干也红」过关，「检查全部跑完」这条判据实际没生效。

REST 返回的 `conclusion` 是小写（`failure`），`gh pr view` 给的是大写（`FAILURE`），比对前统一抬成大写。

读检查项用的是工作流自己的令牌（`github.token`），不是陈实的 App 令牌：`gh pr view --json statusCheckRollup` 要三档只读权限 —— `checks`（检查本身）、`actions`（`checkSuite.workflowRun`）、`statuses`（老式状态上下文）。陈实的 App 一档都没有，拿它查会得到 `Resource not accessible by integration`，判据一条都跑不了。job 的 `permissions` 里因此显式写了 `actions: read` / `checks: read` / `statuses: read`。代价是合并的执行者显示为 `github-actions[bot]`，不是陈实的 App。

被调用的工作流不能自己抬权限：`qwen-dispatch.yml` 与 `qwen-patrol.yml` 里调用 `qwen-miles.yml` 的那两个 job 要同样给这三档，少一档整次运行就是 `startup_failure` —— 没有任何 job，日志也没有。巡检的 `scan-miles` / `scan-frank` 也在读 `statusCheckRollup`，一并给了。

## 模型为什么合不了

`no-merge-gh` 是包在 `gh` 外面的一层，挡两类动作：

- 合并入口 —— `pr merge`、`/pulls/<n>/merge`、`mergePullRequest`，一律拒绝并提示改写成申请。
- 摘闸标签 —— `pr edit --remove-label` 后面跟 `do-not-merge` / `manual-review`（含逗号列表里夹着的），一律拒绝。标签是人放的闸，被这一轮里的模型摘掉，`no-stop-label` 那一项就查不到它了。`--add-label`、普通标签的 `--remove-label`、`issue edit` 都不拦。

装法是在 `RUNNER_TEMP` 下生成一个 `gh` 转发脚本、前置到 `PATH`；装之前先自检「能透传」和「能拦住」两条，验不过就不装并打 warning，退化成只有事后检查。

**这不是安全边界**：令牌就在环境里，绕道 `curl` 照样能合。它挡的是「顺手合了」。包装器在装上前被复制进 `RUNNER_TEMP`，模型改工作区里那份源文件也影响不到已经装好的副本。

真保底是 `gate` job 末尾那道检查：PR 已经 `MERGED`，`mergedBy` 是机器人，闸门这一步却没成功 —— 整轮判失败，dispatch 会发一条出错说明。人自己合的不算，合并条件本来就该由人判断。

闸门步骤按退出码分三种结论：`0` 合并了，`1` 条件没满足（结论已经贴在 PR 上，不算出错），其它退出码是闸门自己坏了 —— 那一步会失败，因为判据根本没跑完。

## 在本地验

纯判定不需要网络，测试里全是构造数据：

```bash
/usr/bin/node --test .github/scripts/merge-gate.test.mjs
```

想连取数、评论、合并一起看（会真的调 `gh`），把假 `gh` 放到 `PATH` 前面：

```bash
/usr/bin/node .github/scripts/merge-gate.mjs <pr> --repo owner/name          # 只判定
/usr/bin/node .github/scripts/merge-gate.mjs <pr> --repo owner/name --merge  # 判定通过就合并
```

判定表打到 stdout，退出码 `0` 通过、`1` 拦下、`2` 用法错误。加 `--merge` 被拦下时会在 PR 上贴一条评论，列出没过的那几条。`--repo` 放在 PR 号前后都行，PR 号必须是数字。

## 闸门之外

- 分支保护没有开，所以没有任何 GitHub 侧的强制。闸门靠的是「合并动作不经过模型」，不是「模型不敢」。
- 改了闸门判据的 PR，需要人看一眼 —— 它是唯一能放松自己约束的代码。
- 检查还在跑时闸门会自己等，上限是 `MILES_CI_WAIT_MINUTES`（默认 10 分钟），等完还没跑完就按未完成拦下。
