//! 主链路装配：新增字节 → 行 → IP → 失败计数 → 封禁意图。
//!
//! 本模块把 [`crate::ingest`]、[`crate::parse`]、[`crate::decision`] 三层接起来，是
//! 设计文档「运行时模型」里 **pipeline 执行体** 的具体形态：单线程独占全部状态
//! （每源 splitter、每 jail 失败窗口、每 jail 规则集），因此内部无需任何锁。
//!
//! **本模块止于 [`BanIntent`]，不下发 netlink。** 下发是 `kernel` 层（2.D）的职责，
//! 装配成完整链路（`pipeline → kernel reactor`）由组合根完成。这样 2.C 可以在不依赖
//! 内核层的前提下被完整测试：喂字节进去，断言「是否产生封禁意图、意图参数是否正确」。
//!
//! 判定所依赖的两项外部事实（信誉分、历史封禁次数）通过 [`DecisionFacts`] 注入，
//! 而**不是**去读 `ip_reputation` / `BAN_HISTORY` 两个全局态——这正是旧
//! `handle_failed_attempt_for_jail` 无法单独单测的原因。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::decision::{effective_threshold, is_internal, plan_ban, BanPlan, FailureWindow};
use crate::ingest::SourceId;
use crate::parse::{LineSplitter, MatchVia, RuleSet, SplitStats};

pub mod executor;

/// 解析一行并把结果收集进 `parsed_lines`（供 `feed` / `flush` 的回调共用）。
///
/// 空行（只有 `\n`）直接跳过，与旧实现一致；`from_utf8_lossy` 容忍日志里的非法
/// 字节序列，不因一个坏字节丢掉整行。
fn collect_line(rules: &RuleSet, line: &[u8], parsed_lines: &mut Vec<(IpAddr, MatchVia)>) {
    if line.is_empty() {
        return;
    }
    if let Some(parsed) = rules.parse(&String::from_utf8_lossy(line)) {
        parsed_lines.push((parsed.ip, parsed.via));
    }
}

/// 一次封禁意图：判定做出「应当封禁」的结论，但尚未下发。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanIntent {
    /// 归属 jail。
    pub jail: Arc<str>,
    /// 触发封禁的来源 IP。
    pub ip: IpAddr,
    /// 产生该意图的日志源（轮转后仍是同一 `SourceId`）。
    pub source: SourceId,
    /// 封禁参数（时长、是否永久、过期时刻、累计次数）。
    pub plan: BanPlan,
    /// 人类可读原因（下发给内核与写入历史）。
    pub reason: String,
}

/// 一个 jail 的判定参数（来自配置，非 netlink）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JailPolicy {
    /// 失败阈值（未经系数放大的原始值）。
    pub max_retries: u32,
    /// 滑动窗口（秒）。
    pub findtime: u32,
    /// 封禁时长（秒）；负值表示配置级永久封禁。
    pub ban_time: i32,
}

impl JailPolicy {
    /// 构造判定参数。
    #[must_use]
    pub const fn new(max_retries: u32, findtime: u32, ban_time: i32) -> Self {
        Self {
            max_retries,
            findtime,
            ban_time,
        }
    }
}

/// 判定所需的外部事实。由组合根注入真实实现，测试注入固定值。
///
/// 把这两项挡在 trait 后面，是为了让判定算式（[`crate::decision::policy`]）保持
/// 纯粹：策略函数本身不查任何 store，本层也不查，查什么由调用方决定。
///
/// **调用契约**：判定层对每一行识别出的来源 IP 调用
/// [`DecisionFacts::record_failure`] **恰好一次**，**紧接着**才调用
/// [`DecisionFacts::reputation_score`] 取分数。顺序是语义的一部分——旧
/// `handle_failed_attempt_for_jail` 就是「先 `record_failure`（信誉分 -10）再取阈值
/// 乘数」，即**本次失败已经计入**之后才决定阈值。反过来（先取分再记账）会让临界
/// IP（如刚好从 80 跌到 70 的那一次）用错乘数。
pub trait DecisionFacts {
    /// 记录一次失败尝试（生产实现：信誉分 -10）。
    ///
    /// 判定层每判定一行含合法 IP 的日志即调用一次。实现若不需要记账（测试、启动
    /// 初期的 [`NoHistory`]）留空即可。
    fn record_failure(&self, ip: IpAddr);

    /// 该 IP 当前的信誉分（0–100）。
    ///
    /// 必须在同一行的 [`DecisionFacts::record_failure`] **之后**调用，返回值即
    /// 「已计入本次失败」的分数。
    fn reputation_score(&self, ip: IpAddr) -> u32;

    /// 该 IP 此前已封禁次数（用于渐进式时长）。
    fn prior_ban_count(&self, ip: IpAddr) -> u32;
}

/// 无历史、信誉满分的默认事实：用于启动初期与测试。
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHistory;

impl DecisionFacts for NoHistory {
    fn record_failure(&self, _ip: IpAddr) {}

    fn reputation_score(&self, _ip: IpAddr) -> u32 {
        100
    }

    fn prior_ban_count(&self, _ip: IpAddr) -> u32 {
        0
    }
}

/// 一轮处理的时间上下文。时钟与高峰判定都由调用方给出，本层不读系统时钟。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tick {
    /// 当前 Unix 秒。
    pub now: i64,
    /// 是否处于业务高峰期（影响阈值系数）。
    pub peak_hours: bool,
}

impl Tick {
    /// 构造时间上下文。
    #[must_use]
    pub const fn new(now: i64, peak_hours: bool) -> Self {
        Self { now, peak_hours }
    }
}

/// 主链路累计计数（供组合根发布到统计快照，本层不写全局态）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    /// 已解析的非空日志行数。
    pub lines_parsed: u64,
    /// 分割期丢弃的超长行/残段数。
    pub lines_skipped: u64,
    /// 正则命中次数。
    pub regex_matches: u64,
    /// 成功提取并校验的 IP 数。
    pub ips_extracted: u64,
    /// 产生的封禁意图数。
    pub bans_intent: u64,
}

/// 单个 jail 的运行时状态（规则集 + 判定参数 + 失败窗口）。
#[derive(Debug)]
struct JailState {
    rules: RuleSet,
    policy: JailPolicy,
    window: FailureWindow,
}

/// 一批处理中不变的行级上下文：把 `judge_line` 的参数收拢成一个借用结构，
/// 避免长参数列表（也让「同一批的 jail/源/时钟/事实必须一致」成为类型约束）。
struct LineCtx<'a> {
    jail: &'a Arc<str>,
    source: SourceId,
    tick: Tick,
    facts: &'a dyn DecisionFacts,
}

/// 主链路装配体，由 pipeline 执行体独占。
#[derive(Debug, Default)]
pub struct Pipeline {
    jails: HashMap<Arc<str>, JailState>,
    splitters: HashMap<SourceId, LineSplitter>,
    counters: Counters,
}

impl Pipeline {
    /// 新建空装配体。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册（或替换）一个 jail 的规则集与判定参数。
    ///
    /// 重载语义：整份替换规则集与参数，但**保留失败窗口**——窗口是运行期观测，
    /// 不属于配置，重载配置不该抹掉已经积累的失败计数（旧实现会连缓冲一起清空）。
    pub fn register_jail(&mut self, rules: RuleSet, policy: JailPolicy) {
        let jail = Arc::clone(rules.jail());
        let window = self
            .jails
            .remove(&jail)
            .map_or_else(FailureWindow::new, |prev| prev.window);
        self.jails.insert(
            jail,
            JailState {
                rules,
                policy,
                window,
            },
        );
    }

    /// 是否已注册该 jail。
    #[must_use]
    pub fn has_jail(&self, jail: &str) -> bool {
        self.jails.contains_key(jail)
    }

    /// 已注册的 jail 数（诊断用）。
    #[must_use]
    pub fn jail_count(&self) -> usize {
        self.jails.len()
    }

    /// 只保留 `keep` 中列出的 jail，返回被摘除的数量。
    ///
    /// 重载后配置里已消失的 jail 连同其失败窗口一并回收。旧实现靠**整体替换**
    /// `cfg.jails` 达到同样效果；本层的状态与配置分离（配置在组合根、窗口在执行体），
    /// 所以必须显式回收——否则长期运行中改过名的 jail 会一直留在表里。
    pub fn retain_jails(&mut self, keep: &[Arc<str>]) -> usize {
        let before = self.jails.len();
        self.jails.retain(|jail, _| keep.iter().any(|k| k == jail));
        before - self.jails.len()
    }

    /// 累计计数快照。
    #[must_use]
    pub fn counters(&self) -> Counters {
        self.counters
    }

    /// 当前挂起半行的源数（诊断用）。
    #[must_use]
    pub fn pending_sources(&self) -> usize {
        self.splitters.len()
    }

    /// 处理一批来自 `source` 的新增字节，把判定产生的封禁意图追加到 `out`。
    ///
    /// # Arguments
    /// - `jail`: 该源归属的 jail（由 `SourceRegistry` 提供）
    /// - `source`: 稳定源身份（决定用哪个 splitter）
    /// - `bytes`: 本轮新增字节
    /// - `tick`: 时间上下文
    /// - `facts`: 信誉分与历史次数
    /// - `out`: 产出封禁意图的追加缓冲（调用方复用，避免每批分配）
    ///
    /// 未注册的 jail 返回 `false`（调用方据此记录并丢弃），已注册返回 `true`。
    pub fn on_chunk(
        &mut self,
        jail: &Arc<str>,
        source: SourceId,
        bytes: &[u8],
        tick: Tick,
        facts: &dyn DecisionFacts,
        out: &mut Vec<BanIntent>,
    ) -> bool {
        if !self.jails.contains_key(jail) {
            return false;
        }

        // 先把本批切出的 (ip, via) 收集到局部表，再统一走判定——避免在
        // `splitter` 的闭包里同时借 `self.jails` 与 `self.counters`。
        let mut parsed_lines: Vec<(IpAddr, MatchVia)> = Vec::new();
        {
            let mut split_stats = SplitStats::default();
            let splitter = self.splitters.entry(source).or_default();
            let rules = &self.jails.get(jail).expect("已确认存在").rules;
            splitter.feed(bytes, &mut split_stats, |line| {
                collect_line(rules, line, &mut parsed_lines);
            });
            self.counters.lines_skipped += split_stats.oversized;
            self.counters.lines_parsed += split_stats.emitted;
        }

        let ctx = LineCtx {
            jail,
            source,
            tick,
            facts,
        };
        for (ip, via) in parsed_lines {
            self.judge_line(&ctx, ip, via, out);
        }

        true
    }

    /// 把某源挂起的半行当作完整行处理（不再等待换行）。
    ///
    /// 源**关闭 / 轮转 / 截断**之前调用，避免丢掉最后一个不完整行——与旧
    /// `flush_partial_line` 的时机一致。与 [`LineSplitter::flush`] 配套；
    /// 未注册的 jail 返回 `false`。
    pub fn flush_source(
        &mut self,
        jail: &Arc<str>,
        source: SourceId,
        tick: Tick,
        facts: &dyn DecisionFacts,
        out: &mut Vec<BanIntent>,
    ) -> bool {
        if !self.jails.contains_key(jail) {
            return false;
        }

        let mut parsed_lines: Vec<(IpAddr, MatchVia)> = Vec::new();
        {
            let Some(splitter) = self.splitters.get_mut(&source) else {
                return true;
            };
            let mut split_stats = SplitStats::default();
            let rules = &self.jails.get(jail).expect("已确认存在").rules;
            splitter.flush(&mut split_stats, |line| {
                collect_line(rules, line, &mut parsed_lines);
            });
            self.counters.lines_skipped += split_stats.oversized;
            self.counters.lines_parsed += split_stats.emitted;
        }

        let ctx = LineCtx {
            jail,
            source,
            tick,
            facts,
        };
        for (ip, via) in parsed_lines {
            self.judge_line(&ctx, ip, via, out);
        }

        true
    }

    /// 对一条已解析出 IP 的行做判定，必要时产出封禁意图。
    ///
    /// `on_chunk` 与 `flush_source` 共用此路径，保证「完整行」与「收尾半行」走
    /// 完全相同的判定语义（时钟、系数、窗口、渐进时长都一致）。
    fn judge_line(
        &mut self,
        ctx: &LineCtx<'_>,
        ip: IpAddr,
        via: MatchVia,
        out: &mut Vec<BanIntent>,
    ) {
        if via == MatchVia::Regex {
            self.counters.regex_matches += 1;
        }
        self.counters.ips_extracted += 1;

        let state = self.jails.get_mut(ctx.jail).expect("已确认存在");
        // 顺序是语义的一部分：先记这次失败，再取分数算阈值（见 [`DecisionFacts`]）。
        ctx.facts.record_failure(ip);
        let threshold = effective_threshold(
            state.policy.max_retries,
            ctx.tick.peak_hours,
            is_internal(ip),
            ctx.facts.reputation_score(ip),
        );
        let verdict = state
            .window
            .observe(ip, ctx.tick.now, state.policy.findtime, threshold);
        if !verdict.reached_cap {
            return;
        }

        let plan = plan_ban(
            state.policy.ban_time,
            ctx.facts.prior_ban_count(ip),
            ctx.tick.now,
            verdict.recent,
        );
        self.counters.bans_intent += 1;
        // 封禁意图已产出：清掉窗口，避免同一次攻击在下一批重复触发
        // （与旧实现「封禁成功后移除条目」一致）。
        state.window.forget(ip);
        out.push(BanIntent {
            jail: Arc::clone(ctx.jail),
            ip,
            source: ctx.source,
            plan,
            reason: format!(
                "{}: {} 次失败达到阈值 {threshold}",
                ctx.jail, verdict.recent
            ),
        });
    }

    /// 源发生轮转/截断：丢弃该源挂起的半行。
    ///
    /// 旧文件的半行不该与新文件的开头拼接。与 [`crate::ingest::Chunk::rotated`]
    /// 配套使用。
    pub fn on_source_rotated(&mut self, source: SourceId) {
        if let Some(splitter) = self.splitters.get_mut(&source) {
            splitter.clear();
        }
    }

    /// 源被摘除：连同其半行缓冲一并清理，避免缓冲表随轮转/重载无限增长。
    pub fn forget_source(&mut self, source: SourceId) {
        self.splitters.remove(&source);
    }

    /// 周期维护：清理各 jail 已完全过期的失败条目。
    ///
    /// 返回清理条数。本方法应由 `scheduler` 按固定周期调用，而**不是**挂在事件
    /// 回调上——这正是结构问题 A 的修法（维护与事件流量解耦）。
    pub fn cleanup(&mut self, now: i64) -> usize {
        let mut removed = 0;
        for state in self.jails.values_mut() {
            removed += state.window.cleanup_expired(now, state.policy.findtime);
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::Rule;

    const SSH_PATTERN: &str = r"Failed password for (?:invalid user )?[a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})";

    /// 造一个带单条 sshd 正则的规则集。
    fn sshd_rules() -> RuleSet {
        RuleSet::new(
            Arc::from("sshd"),
            vec![Rule::new("default", SSH_PATTERN).expect("正则应可编译")],
        )
    }

    /// 造一条命中 sshd 正则的失败行（**不带**换行，便于跨批切分）。
    fn failed_line(ip: &str) -> String {
        format!("Feb  7 12:00:00 host sshd[1]: Failed password for root from {ip} port 22 ssh2")
    }

    /// 同上，但补上换行，可直接作为一条完整行喂入。
    fn failed_rec(ip: &str) -> String {
        format!("{}\n", failed_line(ip))
    }

    /// 注入固定事实的判定事实源。
    struct Facts {
        score: u32,
        prior: u32,
    }

    impl DecisionFacts for Facts {
        fn record_failure(&self, _ip: IpAddr) {}
        fn reputation_score(&self, _ip: IpAddr) -> u32 {
            self.score
        }
        fn prior_ban_count(&self, _ip: IpAddr) -> u32 {
            self.prior
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("测试用 IP 必须合法")
    }

    #[test]
    fn unregistered_jail_is_rejected_without_side_effects() {
        let mut p = Pipeline::new();
        let mut out = Vec::new();
        let jail: Arc<str> = Arc::from("sshd");
        let accepted = p.on_chunk(
            &jail,
            SourceId::from_raw(0),
            b"anything\n",
            Tick::new(1_000, false),
            &NoHistory,
            &mut out,
        );
        assert!(!accepted, "未注册的 jail 应被拒");
        assert!(out.is_empty());
        assert_eq!(p.pending_sources(), 0, "被拒的批次不应留下 splitter");
        assert_eq!(p.counters(), Counters::default());
    }

    #[test]
    fn threshold_reached_produces_intent_with_base_duration() {
        let mut p = Pipeline::new();
        // 阈值 3、窗口 600、封禁 600 秒。
        p.register_jail(sshd_rules(), JailPolicy::new(3, 600, 600));
        let jail: Arc<str> = Arc::from("sshd");
        let src = SourceId::from_raw(1);
        let facts = Facts {
            score: 100,
            prior: 0,
        };
        let tick = Tick::new(10_000, false);
        let mut out = Vec::new();

        // 前两次达不到阈值，不产出意图。
        let two = format!("{}{}", failed_rec("203.0.113.7"), failed_rec("203.0.113.7"));
        assert!(p.on_chunk(&jail, src, two.as_bytes(), tick, &facts, &mut out));
        assert!(out.is_empty(), "两次失败不应触发封禁");

        // 第三次达到阈值，产出恰好一条意图。
        let third = failed_rec("203.0.113.7");
        assert!(p.on_chunk(&jail, src, third.as_bytes(), tick, &facts, &mut out));
        assert_eq!(out.len(), 1, "第三次应触发一条封禁意图");

        let intent = &out[0];
        assert_eq!(&*intent.jail, "sshd");
        assert_eq!(intent.ip, ip("203.0.113.7"));
        assert_eq!(intent.source, src, "意图应带上稳定源身份");
        assert_eq!(intent.plan.duration, 600);
        assert!(!intent.plan.is_permanent);
        assert_eq!(intent.plan.ban_count, 1);
        assert_eq!(intent.plan.fail_count, 3);

        // 触发后窗口已清空：再喂一行不应立刻再次触发。
        out.clear();
        assert!(p.on_chunk(&jail, src, third.as_bytes(), tick, &facts, &mut out));
        assert!(out.is_empty(), "封禁后窗口应被清空，避免重复计数");

        let c = p.counters();
        assert_eq!(c.lines_parsed, 4);
        assert_eq!(c.ips_extracted, 4);
        assert_eq!(c.regex_matches, 4);
        assert_eq!(c.bans_intent, 1);
    }

    #[test]
    fn internal_and_peak_multipliers_raise_the_threshold() {
        // 内网(×2.0) + 高峰(×1.5) + 信誉满分(×1.0)：阈值 3 → ceil(9.0) = 9。
        let mut p = Pipeline::new();
        p.register_jail(sshd_rules(), JailPolicy::new(3, 600, 600));
        let jail: Arc<str> = Arc::from("sshd");
        let src = SourceId::from_raw(2);
        let facts = Facts {
            score: 100,
            prior: 0,
        };
        let tick = Tick::new(1_000, true);
        let mut out = Vec::new();

        // 八次内网失败：仍差一次才到 9。
        for _ in 0..8 {
            p.on_chunk(
                &jail,
                src,
                failed_rec("10.0.0.9").as_bytes(),
                tick,
                &facts,
                &mut out,
            );
        }
        assert!(out.is_empty(), "内网+高峰下 8 次不应达到阈值 9");

        p.on_chunk(
            &jail,
            src,
            failed_rec("10.0.0.9").as_bytes(),
            tick,
            &facts,
            &mut out,
        );
        assert_eq!(out.len(), 1, "第 9 次应达到内网+高峰阈值");
        assert_eq!(out[0].plan.fail_count, 9);
    }

    #[test]
    fn lines_split_across_chunks_join_before_parsing() {
        let mut p = Pipeline::new();
        p.register_jail(sshd_rules(), JailPolicy::new(1, 600, 600));
        let jail: Arc<str> = Arc::from("sshd");
        let src = SourceId::from_raw(3);
        let facts = Facts {
            score: 100,
            prior: 0,
        };
        let tick = Tick::new(5, false);
        let mut out = Vec::new();

        let line = failed_line("198.51.100.4");
        let (head, tail) = line.split_at(20);
        // 前半段不成行：不产生解析结果。
        p.on_chunk(&jail, src, head.as_bytes(), tick, &facts, &mut out);
        assert!(out.is_empty());
        assert_eq!(p.pending_sources(), 1, "应挂起半行");

        // 补上带换行的后半段：整行拼合后才解析出 IP（阈值 1，立即触发）。
        let rest = format!("{tail}\n");
        p.on_chunk(&jail, src, rest.as_bytes(), tick, &facts, &mut out);
        assert_eq!(out.len(), 1, "跨批拼接后应解析出 IP 并触发");
        assert_eq!(out[0].ip, ip("198.51.100.4"));
    }

    #[test]
    fn flush_source_handles_the_final_unterminated_line() {
        let mut p = Pipeline::new();
        p.register_jail(sshd_rules(), JailPolicy::new(1, 600, 600));
        let jail: Arc<str> = Arc::from("sshd");
        let src = SourceId::from_raw(4);
        let facts = Facts {
            score: 100,
            prior: 0,
        };
        let tick = Tick::new(7, false);
        let mut out = Vec::new();

        // 喂一行**不带换行**的失败记录：feed 不会交出它。
        p.on_chunk(
            &jail,
            src,
            failed_line("192.0.2.55").as_bytes(),
            tick,
            &facts,
            &mut out,
        );
        assert!(out.is_empty(), "未终结的行不应在 feed 阶段被解析");

        // 关闭/轮转前 flush：这行被当作完整行处理并触发封禁。
        assert!(p.flush_source(&jail, src, tick, &facts, &mut out));
        assert_eq!(out.len(), 1, "flush 应处理最后的半行");
        assert_eq!(out[0].ip, ip("192.0.2.55"));
        assert_eq!(p.pending_sources(), 1, "flush 不删除 splitter 本身");
    }

    #[test]
    fn rotated_source_drops_the_pending_half_line() {
        let mut p = Pipeline::new();
        p.register_jail(sshd_rules(), JailPolicy::new(1, 600, 600));
        let jail: Arc<str> = Arc::from("sshd");
        let src = SourceId::from_raw(5);
        let facts = NoHistory;
        let tick = Tick::new(9, false);
        let mut out = Vec::new();

        // 挂起半行（含一个完整 IP，但未换行）。
        p.on_chunk(
            &jail,
            src,
            failed_line("203.0.113.99").as_bytes(),
            tick,
            &facts,
            &mut out,
        );
        assert!(out.is_empty());

        // 轮转：半行必须被丢弃，不能与新文件开头拼接。
        p.on_source_rotated(src);
        p.on_chunk(&jail, src, b"\n", tick, &facts, &mut out);
        assert!(out.is_empty(), "轮转后旧半行不应被补全解析");

        // flush 也拿不到任何东西（缓冲已清）。
        p.flush_source(&jail, src, tick, &facts, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn forget_source_releases_the_splitter() {
        let mut p = Pipeline::new();
        p.register_jail(sshd_rules(), JailPolicy::new(5, 600, 600));
        let jail: Arc<str> = Arc::from("sshd");
        let src = SourceId::from_raw(6);
        let mut out = Vec::new();
        p.on_chunk(
            &jail,
            src,
            b"no newline yet",
            Tick::new(1, false),
            &NoHistory,
            &mut out,
        );
        assert_eq!(p.pending_sources(), 1);
        p.forget_source(src);
        assert_eq!(p.pending_sources(), 0, "摘除源应释放其半行缓冲");
    }

    #[test]
    fn register_jail_preserves_the_failure_window_across_reload() {
        let mut p = Pipeline::new();
        p.register_jail(sshd_rules(), JailPolicy::new(3, 600, 600));
        let jail: Arc<str> = Arc::from("sshd");
        let src = SourceId::from_raw(7);
        let facts = Facts {
            score: 100,
            prior: 0,
        };
        let tick = Tick::new(100, false);
        let mut out = Vec::new();

        // 先积累两次失败。
        let two = format!("{}{}", failed_rec("203.0.113.8"), failed_rec("203.0.113.8"));
        p.on_chunk(&jail, src, two.as_bytes(), tick, &facts, &mut out);
        assert!(out.is_empty());

        // 重载配置：窗口必须保留，否则攻击者可用 SIGHUP 清零计数。
        p.register_jail(sshd_rules(), JailPolicy::new(3, 600, 600));
        assert!(p.has_jail("sshd"));

        p.on_chunk(
            &jail,
            src,
            failed_rec("203.0.113.8").as_bytes(),
            tick,
            &facts,
            &mut out,
        );
        assert_eq!(out.len(), 1, "重载后第 3 次失败仍应达到阈值");
        assert_eq!(out[0].plan.fail_count, 3);
    }

    #[test]
    fn cleanup_expires_stale_entries() {
        let mut p = Pipeline::new();
        p.register_jail(sshd_rules(), JailPolicy::new(5, 100, 600));
        let jail: Arc<str> = Arc::from("sshd");
        let src = SourceId::from_raw(8);
        let mut out = Vec::new();
        // 在 t=1000 记录一次失败。
        p.on_chunk(
            &jail,
            src,
            failed_rec("203.0.113.10").as_bytes(),
            Tick::new(1_000, false),
            &NoHistory,
            &mut out,
        );
        assert!(out.is_empty());
        // t=2000：距上次 1000 秒 > 窗口 100 秒 → 整条过期。
        assert_eq!(p.cleanup(2_000), 1);
        assert_eq!(p.cleanup(2_000), 0, "再次清理应无条目可清");
    }

    #[test]
    fn progressive_escalation_across_bans() {
        let mut p = Pipeline::new();
        p.register_jail(sshd_rules(), JailPolicy::new(1, 600, 600));
        let jail: Arc<str> = Arc::from("sshd");
        let src = SourceId::from_raw(9);
        let tick = Tick::new(50, false);
        let mut out = Vec::new();

        // 依次封禁同一 IP，prior_ban_count 递增，时长按阶梯走。
        let expected = [(600u64, false), (1800, false), (86400, false), (0, true)];
        for (prior, (dur, perm)) in expected.iter().enumerate() {
            let facts = Facts {
                score: 100,
                prior: prior as u32,
            };
            p.on_chunk(
                &jail,
                src,
                failed_rec("203.0.113.11").as_bytes(),
                tick,
                &facts,
                &mut out,
            );
            assert_eq!(out.len(), 1, "第 {prior} 次应触发封禁");
            assert_eq!(out[0].plan.duration, *dur, "第 {prior} 次时长不符");
            assert_eq!(out[0].plan.is_permanent, *perm, "第 {prior} 次永久标志不符");
            out.clear();
        }
    }

    #[test]
    fn fallback_keyword_line_still_yields_an_ip() {
        // 含 `authentication failure` 关键字但**不**匹配 sshd 正则：应走回退路径。
        let mut p = Pipeline::new();
        p.register_jail(sshd_rules(), JailPolicy::new(1, 600, 600));
        let jail: Arc<str> = Arc::from("sshd");
        let src = SourceId::from_raw(10);
        let mut out = Vec::new();
        p.on_chunk(
            &jail,
            src,
            b"Feb  7 12:00:00 host sshd[1]: authentication failure; rhost=203.0.113.12\n",
            Tick::new(1, false),
            &NoHistory,
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ip, ip("203.0.113.12"));
        assert_eq!(p.counters().regex_matches, 0, "回退命中不计入正则命中");
        assert_eq!(p.counters().ips_extracted, 1);
    }

    /// 记账顺序必须是「先 `record_failure`，后 `reputation_score`」。
    ///
    /// 算术（阈值基数 12、非高峰、外网、同批 6 行失败；信誉分自 100 起每记一次 -10）。
    /// 注意 `FailureWindow::observe` 的 `recent` 按阈值（`cap`）截断，故 `fail_count`
    /// 至多等于阈值——用「阈值 6 恰好等于行数」让两种顺序的产出可分辨：
    ///
    /// | 第 n 行 | 先记账→取分 | 系数 | 有效阈值 | 先取分→记账 | 系数 | 有效阈值 |
    /// |---|---|---|---|---|---|---|
    /// | 5 | 50 | 0.8 | 10 | 60 | 0.8 | 10 |
    /// | 6 | **40** | **0.5** | **6 → 6 次达标** | 50 | 0.8 | 10 → 6 次不达标 |
    ///
    /// 故「第 6 行产出封禁意图、`fail_count == 6`」唯一地分辨两种顺序。
    #[test]
    fn failure_is_recorded_before_the_score_is_read() {
        /// 每记一次失败扣 10 分，与生产信誉分同规则。
        struct DecayingFacts {
            score: std::sync::atomic::AtomicU32,
        }

        impl DecisionFacts for DecayingFacts {
            fn record_failure(&self, _ip: IpAddr) {
                self.score
                    .fetch_sub(10, std::sync::atomic::Ordering::SeqCst);
            }
            fn reputation_score(&self, _ip: IpAddr) -> u32 {
                self.score.load(std::sync::atomic::Ordering::SeqCst)
            }
            fn prior_ban_count(&self, _ip: IpAddr) -> u32 {
                0
            }
        }

        let mut p = Pipeline::new();
        p.register_jail(sshd_rules(), JailPolicy::new(12, 600, 600));
        let jail: Arc<str> = Arc::from("sshd");
        let src = SourceId::from_raw(11);
        let facts = DecayingFacts {
            score: std::sync::atomic::AtomicU32::new(100),
        };
        let mut out = Vec::new();

        let batch = failed_rec("203.0.113.13").repeat(6);
        p.on_chunk(
            &jail,
            src,
            batch.as_bytes(),
            Tick::new(1_000, false),
            &facts,
            &mut out,
        );

        assert_eq!(
            facts.score.load(std::sync::atomic::Ordering::SeqCst),
            40,
            "六行失败应各记一次账"
        );
        assert_eq!(
            out.len(),
            1,
            "第 6 次失败应达到「记过账之后」的阈值 6；无产出即说明取分早于记账"
        );
        assert_eq!(out[0].plan.fail_count, 6);
    }
}
