//! 单守护进程注册租约。
//!
//! 内核只承认**一个**守护进程（`fw_netlink.c`）：注册成功后它记住调用方
//! portid，此后只接受该 portid 的指令；若 30 秒（`FW_NL_DAEMON_TIMEOUT =
//! 30 * HZ`）内没再收到它的报文，内核就允许别的 portid 接管。这带来两条必须
//! 处理的后果：
//!
//! - **注册结果必须等确认**。内核用 `DaemonRegisterAck.accepted` 明确回答「接受」
//!   还是「拒绝」。旧实现既没有这个结构体、也没有解析分支，发完注册报文就当作
//!   成功——`sendto` 成功只说明报文进了内核。被拒时旧实现毫无察觉，此后每条指令
//!   都被内核静默丢弃，而界面上一片正常。
//! - **租约必须续**。静默超过租约上限，内核就会让别人接管；本进程的指令随之被拒。
//!   故持有租约期间必须周期发信号续约。
//!
//! # 本模块的边界
//!
//! 只维护**租约状态**，不决定「什么时候续约」——由 `runtime::timers` 驱动（设计
//! 文档：周期维护不再由事件驱动）。调度器只需问 [`Lease::needs_renewal`]。
//!
//! # 为什么要把「发送与确认」抽象成 trait
//!
//! 状态机（尤其是「确认失败必须转为失联」这条）需要在**没有加载内核模块**的
//! 环境里可测；真实实现要向内核 portid 发送并等回复，本机通常做不到。故
//! [`Registrar`] 把这一步隔离出来，生产用 [`Client`]，测试用脚本化的替身。

use std::time::{Duration, Instant};

use crate::kernel::client::{Client, RequestError};
use crate::kernel::codec;

/// 内核租约的存活上限。
///
/// 取自内核 `fw_netlink.c` 的 `FW_NL_DAEMON_TIMEOUT = 30 * HZ`：超过这个时间
/// 没有收到本进程的报文，内核即允许别的 portid 接管。续约周期必须显著短于它，
/// 否则网络抖动或调度延迟就足以让租约失守。
pub const KERNEL_LEASE_TTL: Duration = Duration::from_secs(30);

/// 租约状态。
///
/// 四态互斥且穷尽，「不知情」不在其中：任何时刻都能回答「内核现在认不认我」，
/// 这是上层决定「指令能不能下发」的前提。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// 尚未注册。
    Idle,
    /// 内核已确认注册，租约有效。
    Held,
    /// 内核明确拒绝注册（已有活跃守护进程持有租约）。
    Refused,
    /// 租约已失：确认超时、链路断开、或已被外部标记失效。
    Lost,
}

/// 注册报文的发送与确认。
///
/// 抽出来是为了让租约状态机可以脱离 socket 测试，见模块文档。
pub trait Registrar {
    /// 发送注册报文并等待内核确认。
    ///
    /// # Errors
    ///
    /// 报文未发出或确认未到达时返回 [`RequestError`]。
    fn register(&self, timeout: Duration) -> Result<codec::DaemonRegisterAck, RequestError>;
}

impl Registrar for Client {
    fn register(&self, timeout: Duration) -> Result<codec::DaemonRegisterAck, RequestError> {
        // 显式限定，避免与 trait 方法同名导致的解析歧义。
        Client::register(self, timeout)
    }
}

/// 注册租约状态机。
///
/// 单所有者、`&mut self` 更新，无内部锁：租约的判断与更新都来自同一条执行体
/// 序列（调度器续约、故障上报），不存在需要并发的场景。
#[derive(Debug)]
pub struct Lease {
    state: LeaseState,
    /// 最近一次**确认成功**的时刻（单调时钟，不受系统时钟回拨影响）。
    renewed_at: Option<Instant>,
    /// 进入 `Lost` 的次数。每次都意味着「有一段时间内核不认本进程」，
    /// 是必须可见的运行事件，不能只体现在某一刻的状态快照里。
    losses: u64,
}

impl Default for Lease {
    fn default() -> Self {
        Self::new()
    }
}

impl Lease {
    /// 新建一个未注册的租约。
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: LeaseState::Idle,
            renewed_at: None,
            losses: 0,
        }
    }

    /// 当前状态。
    #[must_use]
    pub fn state(&self) -> LeaseState {
        self.state
    }

    /// 最近一次确认成功的时刻；未持有租约时为 `None`。
    #[must_use]
    pub fn renewed_at(&self) -> Option<Instant> {
        self.renewed_at
    }

    /// 累计失联次数。
    #[must_use]
    pub fn losses(&self) -> u64 {
        self.losses
    }

    /// 首次注册，或从 [`LeaseState::Refused`] / [`LeaseState::Lost`] 重新争夺租约。
    ///
    /// 返回确认后的状态：`Held` 表示内核接受，`Refused` 表示内核明确拒绝。
    ///
    /// # Errors
    ///
    /// 确认未到达时返回 [`RequestError`]，并把状态转为 [`LeaseState::Lost`]。
    pub fn acquire<R: Registrar>(
        &mut self,
        registrar: &R,
        timeout: Duration,
    ) -> Result<LeaseState, RequestError> {
        self.confirm(registrar, timeout)
    }

    /// 续约。
    ///
    /// 内核把「收到注册报文」当作该 portid 的活跃信号（`fw_nl_daemon_activity =
    /// jiffies`），故续约就是重发注册报文。未持有租约时**不发报文**、原样返回
    /// 当前状态：没有租约可续，重发只会去和真正持有租约的进程抢。
    ///
    /// # Errors
    ///
    /// 确认未到达时返回 [`RequestError`]，并把状态转为 [`LeaseState::Lost`]。
    pub fn renew<R: Registrar>(
        &mut self,
        registrar: &R,
        timeout: Duration,
    ) -> Result<LeaseState, RequestError> {
        if self.state != LeaseState::Held {
            return Ok(self.state);
        }
        self.confirm(registrar, timeout)
    }

    /// 发一次注册报文并按确认结果迁移状态。
    fn confirm<R: Registrar>(
        &mut self,
        registrar: &R,
        timeout: Duration,
    ) -> Result<LeaseState, RequestError> {
        match registrar.register(timeout) {
            Ok(ack) => {
                if ack.accepted {
                    self.state = LeaseState::Held;
                    self.renewed_at = Some(Instant::now());
                } else {
                    self.mark(LeaseState::Refused);
                }
                Ok(self.state)
            }
            Err(e) => {
                // 确认失败绝不能继续假装持有租约：否则上层会毫无察觉地下发
                // 一批注定被内核拒掉的指令，而界面显示一切正常。
                self.mark(LeaseState::Lost);
                Err(e)
            }
        }
    }

    /// 外部观测到链路断开时上报（例如接收执行体已退出）。
    pub fn mark_lost(&mut self) {
        self.mark(LeaseState::Lost);
    }

    /// 距离租约到期还剩多久；未持有租约时为 `None`。
    ///
    /// `ttl` 传 [`KERNEL_LEASE_TTL`] 即可；返回值到 0 表示内核随时可能放走租约。
    #[must_use]
    pub fn remaining(&self, now: Instant, ttl: Duration) -> Option<Duration> {
        self.renewed_at
            .map(|at| ttl.saturating_sub(now.saturating_duration_since(at)))
    }

    /// 是否到了该续约的时刻。
    #[must_use]
    pub fn needs_renewal(&self, now: Instant, interval: Duration) -> bool {
        if self.state != LeaseState::Held {
            return false;
        }
        match self.renewed_at {
            Some(at) => now.saturating_duration_since(at) >= interval,
            // 状态是 Held 却没有时刻：视为立刻需要续约，而不是等到某个默认值。
            None => true,
        }
    }

    /// 状态迁移的唯一出口，保证 `renewed_at` 与 `losses` 与状态同步。
    fn mark(&mut self, next: LeaseState) {
        if next == LeaseState::Lost && self.state != LeaseState::Lost {
            self.losses += 1;
        }
        self.state = next;
        if next != LeaseState::Held {
            self.renewed_at = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// 脚本化的一次注册结果。
    #[derive(Debug, Clone, Copy)]
    enum Step {
        /// 内核接受。
        Accepted,
        /// 内核明确拒绝（已有活跃守护进程）。
        Refused,
        /// 报文发出但没有确认到达。
        Timeout,
        /// 内核链路已断。
        LinkDown,
    }

    /// 按脚本回答的注册替身。
    #[derive(Debug)]
    struct Fake {
        script: Mutex<VecDeque<Step>>,
        calls: AtomicUsize,
    }

    impl Fake {
        fn new(steps: impl IntoIterator<Item = Step>) -> Self {
            Self {
                script: Mutex::new(steps.into_iter().collect()),
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl Registrar for Fake {
        fn register(&self, _timeout: Duration) -> Result<codec::DaemonRegisterAck, RequestError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let step = self
                .script
                .lock()
                .expect("脚本锁不应中毒")
                .pop_front()
                .expect("脚本已用尽：测试用例写错了步骤数");
            match step {
                Step::Accepted => Ok(codec::DaemonRegisterAck { accepted: true }),
                Step::Refused => Ok(codec::DaemonRegisterAck { accepted: false }),
                Step::Timeout => Err(RequestError::Timeout),
                Step::LinkDown => Err(RequestError::LinkDown),
            }
        }
    }

    #[test]
    fn acquire_on_an_accepting_kernel_marks_the_lease_held() {
        let fake = Fake::new([Step::Accepted]);
        let mut lease = Lease::new();
        assert_eq!(lease.state(), LeaseState::Idle);
        let state = lease
            .acquire(&fake, Duration::from_millis(50))
            .expect("接受时不应报错");
        assert_eq!(state, LeaseState::Held);
        assert!(lease.renewed_at().is_some(), "接受后必须有确认时刻");
        assert_eq!(lease.losses(), 0, "成功注册不是失联");
        assert_eq!(fake.calls(), 1);
    }

    #[test]
    fn a_refusal_is_not_a_loss_and_leaves_no_confirmation_time() {
        // 内核明确说「不」与「没听到回答」是两件事：前者是对方在正常拒绝，
        // 后者是链路不可判定。混为一谈会让运维看不到真正的链路故障。
        let fake = Fake::new([Step::Refused]);
        let mut lease = Lease::new();
        let state = lease
            .acquire(&fake, Duration::from_millis(50))
            .expect("拒绝是有效确认，不应报错");
        assert_eq!(state, LeaseState::Refused);
        assert!(lease.renewed_at().is_none(), "被拒不得留下确认时刻");
        assert_eq!(lease.losses(), 0, "被拒不是失联");
    }

    #[test]
    fn an_unconfirmed_acquire_becomes_lost_rather_than_pretending_to_hold() {
        for (step, expect) in [(Step::Timeout, "超时"), (Step::LinkDown, "链路断开")] {
            let fake = Fake::new([step]);
            let mut lease = Lease::new();
            let err = lease
                .acquire(&fake, Duration::from_millis(50))
                .expect_err(&format!("{expect} 时确认未到达，应报错"));
            // 错误类型保留细节，供上层区分「重试」与「告警」。
            assert!(
                matches!(err, RequestError::Timeout | RequestError::LinkDown),
                "{expect} 实得 {err:?}"
            );
            assert_eq!(
                lease.state(),
                LeaseState::Lost,
                "{expect} 后不得仍显示持有租约"
            );
            assert!(lease.renewed_at().is_none());
        }
    }

    #[test]
    fn a_failed_renewal_drops_the_lease_instead_of_keeping_it() {
        let fake = Fake::new([Step::Accepted, Step::Timeout]);
        let mut lease = Lease::new();
        lease
            .acquire(&fake, Duration::from_millis(50))
            .expect("首次注册应被接受");
        assert_eq!(lease.state(), LeaseState::Held);
        let err = lease
            .renew(&fake, Duration::from_millis(50))
            .expect_err("续约无确认应报错");
        assert!(matches!(err, RequestError::Timeout));
        assert_eq!(lease.state(), LeaseState::Lost, "续约失败即失去租约");
        assert!(lease.renewed_at().is_none());
        assert_eq!(lease.losses(), 1);
    }

    #[test]
    fn renewal_only_sends_while_the_lease_is_held() {
        // 未持有租约时重发注册报文只会去抢别人的租约，必须禁止。
        let fake = Fake::new([]);
        let mut lease = Lease::new();
        assert_eq!(
            lease
                .renew(&fake, Duration::from_millis(50))
                .expect("空转不报错"),
            LeaseState::Idle
        );
        lease.mark_lost();
        assert_eq!(
            lease
                .renew(&fake, Duration::from_millis(50))
                .expect("空转不报错"),
            LeaseState::Lost
        );
        assert_eq!(fake.calls(), 0, "非持有状态下不得发出任何注册报文");
    }

    #[test]
    fn a_successful_renewal_pushes_the_deadline_forward() {
        let fake = Fake::new([Step::Accepted, Step::Accepted]);
        let mut lease = Lease::new();
        lease
            .acquire(&fake, Duration::from_millis(50))
            .expect("首次注册应被接受");
        let first = lease.renewed_at().expect("应有确认时刻");
        lease
            .renew(&fake, Duration::from_millis(50))
            .expect("续约应被接受");
        let second = lease.renewed_at().expect("续约后仍有确认时刻");
        assert!(
            second >= first,
            "续约必须把确认时刻往后推（{first:?} -> {second:?}）"
        );
        assert_eq!(lease.state(), LeaseState::Held);
        assert_eq!(fake.calls(), 2, "续约必须真的重发报文");
    }

    #[test]
    fn needs_renewal_tracks_the_interval_against_the_confirmation_time() {
        let fake = Fake::new([Step::Accepted]);
        let mut lease = Lease::new();
        let interval = Duration::from_secs(10);
        assert!(
            !lease.needs_renewal(Instant::now(), interval),
            "无租约时不需要续约"
        );
        lease
            .acquire(&fake, Duration::from_millis(50))
            .expect("首次注册应被接受");
        let at = lease.renewed_at().expect("应有确认时刻");
        assert!(!lease.needs_renewal(at, interval), "刚确认过不需要续约");
        assert!(
            !lease.needs_renewal(at + interval - Duration::from_millis(1), interval),
            "未到间隔不得续约"
        );
        assert!(lease.needs_renewal(at + interval, interval), "到点必须续约");
    }

    #[test]
    fn remaining_counts_down_to_the_kernel_deadline() {
        let fake = Fake::new([Step::Accepted]);
        let mut lease = Lease::new();
        lease
            .acquire(&fake, Duration::from_millis(50))
            .expect("首次注册应被接受");
        let at = lease.renewed_at().expect("应有确认时刻");
        assert_eq!(
            lease.remaining(at, KERNEL_LEASE_TTL),
            Some(KERNEL_LEASE_TTL)
        );
        assert_eq!(
            lease.remaining(at + KERNEL_LEASE_TTL, KERNEL_LEASE_TTL),
            Some(Duration::ZERO),
            "到期后不得出现负数余额"
        );
        assert_eq!(
            lease.remaining(at + KERNEL_LEASE_TTL * 2, KERNEL_LEASE_TTL),
            Some(Duration::ZERO)
        );
        lease.mark_lost();
        assert_eq!(lease.remaining(at, KERNEL_LEASE_TTL), None, "无租约无余额");
    }

    #[test]
    fn losses_count_transitions_not_calls() {
        let fake = Fake::new([Step::Timeout, Step::Timeout]);
        let mut lease = Lease::new();
        lease
            .acquire(&fake, Duration::from_millis(50))
            .expect_err("首次确认超时");
        assert_eq!(lease.losses(), 1);
        // 已在 Lost 状态上再次上报：不重复计数（这是一次失联，不是两次）。
        lease
            .acquire(&fake, Duration::from_millis(50))
            .expect_err("再次确认超时");
        assert_eq!(lease.losses(), 1);
        // 恢复到 Held 之后再失联，才算新的一次。
        let fake = Fake::new([Step::Accepted, Step::Timeout]);
        lease
            .acquire(&fake, Duration::from_millis(50))
            .expect("接受");
        assert_eq!(lease.state(), LeaseState::Held);
        lease
            .renew(&fake, Duration::from_millis(50))
            .expect_err("续约超时");
        assert_eq!(lease.losses(), 2);
    }

    #[test]
    fn the_kernel_lease_ttl_matches_fw_nl_daemon_timeout() {
        // 内核是 `30 * HZ`；这里是秒级常量，改一处必须改另一处。
        assert_eq!(KERNEL_LEASE_TTL, Duration::from_secs(30));
    }
}
