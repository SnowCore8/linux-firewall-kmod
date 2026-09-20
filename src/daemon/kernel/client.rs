//! 类型化请求 API：`Arc<Transport>` 上的「发一条、等一条回复」。
//!
//! # 两种完成语义，用类型分开
//!
//! - **已确认**：内核有明确的回复报文（`StatsResponse` / `ConfigAck` /
//!   `DaemonRegisterAck` / 三个 `List*Response`），方法返回解好的结构体。
//! - **已投递**（[`Delivered`]）：`ban` / `unban` / 白名单增删在**成功**时没有
//!   任何回复，只有失败才有 `CmdResult`。故成功只能说明「内核收到了这条指令」。
//!   旧实现把 `sendto` 成功直接当成执行成功，本模块用返回类型把这件事写明，
//!   避免调用方再次把「已投递」当「已执行」。
//!
//! # 关联必须靠回显 `seq`
//!
//! 每次请求由 [`Client::alloc_seq`] 分配一个**非零**序号（0 在契约里表示
//! 「不参与配对」），先向 [`crate::kernel::reactor::Router`] 登记在途，
//! 再发出报文——顺序不能颠倒，否则回复可能先到而被计成「无人认领」。
//!
//! # 分页必须走完整张表
//!
//! 内核把 `total`（当前总条目数）与 `offset`（本页起点）都放在响应里，且
//! `limit == 0` 表示「内核默认页大小」而不是「不限量」。旧实现请求
//! `offset=0, limit=0` 后直接丢弃 `total`/`offset`，于是白名单与速率表**只会
//! 返回第一页**，其余条目静默消失。本模块的 `list_*_all` 一律请求契约给出的
//! 单页上限并续页到底。

use std::fmt;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::contract::{ListBansResponse, ListRatesResponse, ListWhitelistResponse, MsgType};
use crate::kernel::codec;
use crate::kernel::codec::Incoming;
use crate::kernel::reactor::Router;
use crate::kernel::transport::Transport;
use crate::runtime::RecvTimeoutError;

/// 一次请求成功投递到内核、但内核是否执行未获确认。
///
/// 见模块文档「两种完成语义」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivered;

// ============================================================================
// 错误
// ============================================================================

/// 一次请求失败的原因。
#[derive(Debug)]
pub enum RequestError {
    /// 在途请求表已满（`MAX_IN_FLIGHT`），请求**未发出**。
    Busy,
    /// 请求序号与某条在途请求重复，登记被拒、请求**未发出**。
    ///
    /// 单客户端的序号分配不会产生重复，出现即说明有调用方绕过了
    /// [`Client::alloc_seq`] 自行拼装序号。
    SeqReused,
    /// 报文未能投递到内核。
    Send(io::Error),
    /// 超时内未收到回复。既可能是内核没回，也可能是回复被丢弃。
    Timeout,
    /// 与内核的链路已断：接收侧已退出，回复不可能到达。
    LinkDown,
    /// 收到了回复，但不是本次请求该有的类型（协议违例）。
    Unexpected {
        /// 期望的回复类型名。
        expected: &'static str,
        /// 实际收到的类型名。
        got: &'static str,
    },
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => write!(f, "在途请求表已满，请求未发出"),
            Self::SeqReused => write!(f, "请求序号与在途请求重复，请求未发出"),
            Self::Send(e) => write!(f, "发送 netlink 请求失败：{e}"),
            Self::Timeout => write!(f, "等待内核回复超时"),
            Self::LinkDown => write!(f, "与内核的 netlink 链路已断开"),
            Self::Unexpected { expected, got } => {
                write!(f, "期望 {expected} 回复，实得 {got}")
            }
        }
    }
}

impl std::error::Error for RequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Send(e) => Some(e),
            Self::Busy
            | Self::SeqReused
            | Self::Timeout
            | Self::LinkDown
            | Self::Unexpected { .. } => None,
        }
    }
}

impl From<RecvTimeoutError> for RequestError {
    fn from(e: RecvTimeoutError) -> Self {
        match e {
            RecvTimeoutError::Timeout => Self::Timeout,
            RecvTimeoutError::Disconnected => Self::LinkDown,
        }
    }
}

// ============================================================================
// 客户端
// ============================================================================

/// 类型化请求客户端。可克隆共享（内部只有 `Arc` 与原子计数）。
#[derive(Debug, Clone)]
pub struct Client {
    transport: Arc<Transport>,
    router: Arc<Router>,
    next_seq: Arc<AtomicU32>,
}

impl Client {
    /// 在既有 socket 与路由器上建立客户端。
    #[must_use]
    pub fn new(transport: Arc<Transport>, router: Arc<Router>) -> Self {
        Self {
            transport,
            router,
            // 从 1 起：契约里 seq == 0 表示「不参与配对」。
            next_seq: Arc::new(AtomicU32::new(1)),
        }
    }

    /// socket 的所有者，供 [`super::lease`] 直接发送注册报文。
    #[must_use]
    pub fn transport(&self) -> &Arc<Transport> {
        &self.transport
    }

    /// 路由器，供 [`super::lease`] 登记注册配对。
    #[must_use]
    pub fn router(&self) -> &Arc<Router> {
        &self.router
    }

    /// 分配一个非零请求序号。
    ///
    /// 跳过 0：绕过 `u32` 回绕时 `fetch_add` 会产出 0，而 0 在契约里意味着
    /// 「本条不参与配对」，用它会和内核推送的「seq=0」混淆。
    fn alloc_seq(&self) -> u32 {
        loop {
            let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
            if seq != 0 {
                return seq;
            }
        }
    }

    /// 登记在途请求。
    ///
    /// 登记失败按原因分派（见 [`RequestError`]）：链路失联、表满、序号复用各自
    /// 可辨，上层才知道该告警、该退避重试、还是该查逻辑 bug。
    fn registered(
        &self,
        reply_type: MsgType,
        seq: u32,
    ) -> Result<crate::kernel::reactor::ReplyHandle, RequestError> {
        match self.router.register(reply_type, seq) {
            Ok(handle) => Ok(handle),
            Err(crate::kernel::reactor::RegisterError::LinkDown) => Err(RequestError::LinkDown),
            Err(crate::kernel::reactor::RegisterError::Full) => Err(RequestError::Busy),
            Err(crate::kernel::reactor::RegisterError::Duplicate) => Err(RequestError::SeqReused),
        }
    }

    /// 发出一条请求并等待配对回复。
    ///
    /// `seq` 由调用方给出，便于测试固定序号；生产路径一律用 [`Self::alloc_seq`]。
    fn exchange_with(
        &self,
        reply_type: MsgType,
        seq: u32,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Incoming, RequestError> {
        // 先登记再发送：回复可能在本函数返回前的任何时刻到达。
        let handle = self.registered(reply_type, seq)?;
        self.transport.send(payload).map_err(RequestError::Send)?;
        Ok(handle.recv_timeout(timeout)?)
    }

    /// 登记在途请求并等待配对回复，**不发送**任何报文。
    ///
    /// 仅供测试：生产路径一律走 [`Self::exchange_with`]（登记 → 发送 → 等待）。
    /// 与它分开是因为本机可能没加载内核模块，此时向内核 portid 0 发送会直接
    /// 拿到 `ECONNREFUSED`，无法验证配对逻辑；而「登记 + 等待」这一半不碰
    /// socket，可以在任何环境里确定性地驱动。
    #[cfg(test)]
    fn await_reply(
        &self,
        reply_type: MsgType,
        seq: u32,
        timeout: Duration,
    ) -> Result<Incoming, RequestError> {
        let handle = self.registered(reply_type, seq)?;
        Ok(handle.recv_timeout(timeout)?)
    }

    /// 发出一条请求；`seq` 由本客户端分配，编码由 `encode` 完成。
    fn request(
        &self,
        reply_type: MsgType,
        timeout: Duration,
        encode: impl FnOnce(u32) -> Vec<u8>,
    ) -> Result<Incoming, RequestError> {
        let seq = self.alloc_seq();
        let payload = encode(seq);
        self.exchange_with(reply_type, seq, &payload, timeout)
    }

    // ------------------------------------------------------------------
    // 已确认：有明确回复报文的请求
    // ------------------------------------------------------------------

    /// 查询内核统计。
    ///
    /// # Errors
    ///
    /// 见 [`RequestError`]。
    pub fn query_stats(&self, timeout: Duration) -> Result<codec::StatsResponse, RequestError> {
        let msg = self.request(MsgType::StatsResponse, timeout, |seq| {
            codec::StatsQuery.encode(seq)
        })?;
        as_stats(msg)
    }

    /// 查询分析数据（包大小/TTL 分布、端口与扫描者 Top-N）。
    ///
    /// # Errors
    ///
    /// 见 [`RequestError`]。
    pub fn query_analysis(
        &self,
        timeout: Duration,
    ) -> Result<codec::AnalysisResponse, RequestError> {
        let msg = self.request(MsgType::AnalysisResponse, timeout, |seq| {
            codec::AnalysisQuery.encode(seq)
        })?;
        as_analysis(msg)
    }

    /// 下发配置并返回内核的采纳/拒绝位图。
    ///
    /// 这是**唯一**的配置下发路径：基线更新也必须走这里，不得另开一条捷径
    /// （旧实现的 `send_baseline_update` 绕过了 `config_sync.rs`）。
    ///
    /// # Errors
    ///
    /// 见 [`RequestError`]。
    pub fn set_config(
        &self,
        change: &codec::SetConfig,
        timeout: Duration,
    ) -> Result<codec::ConfigAck, RequestError> {
        let msg = self.request(MsgType::ConfigAck, timeout, |seq| change.encode(seq))?;
        as_config_ack(msg)
    }

    /// 注册为唯一守护进程，返回内核的接受/拒绝结论。
    ///
    /// # Errors
    ///
    /// 见 [`RequestError`]。
    pub fn register(&self, timeout: Duration) -> Result<codec::DaemonRegisterAck, RequestError> {
        let msg = self.request(MsgType::DaemonRegisterAck, timeout, |seq| {
            codec::DaemonRegister.encode(seq)
        })?;
        as_register_ack(msg)
    }

    // ------------------------------------------------------------------
    // 已投递：成功时内核不回复
    // ------------------------------------------------------------------

    /// 下发封禁。返回值表示**已投递**，不表示已生效。
    ///
    /// 失败时内核会单播 `CmdResult`，它进入事件流（见
    /// [`crate::kernel::reactor::Router`]），不在本方法的返回路径上。
    ///
    /// # Errors
    ///
    /// 见 [`RequestError`]。
    pub fn ban(
        &self,
        addr: IpAddr,
        duration_secs: u32,
        reason: &str,
        _timeout: Duration,
    ) -> Result<Delivered, RequestError> {
        let cmd = codec::BanIp {
            addr,
            duration_secs,
            reason: reason.to_string(),
        };
        self.transport
            .send(&cmd.encode(self.alloc_seq()))
            .map_err(RequestError::Send)?;
        Ok(Delivered)
    }

    /// 下发解封。返回值表示**已投递**。
    ///
    /// # Errors
    ///
    /// 见 [`RequestError`]。
    pub fn unban(&self, addr: IpAddr, _timeout: Duration) -> Result<Delivered, RequestError> {
        let cmd = codec::UnbanIp { addr };
        self.transport
            .send(&cmd.encode(self.alloc_seq()))
            .map_err(RequestError::Send)?;
        Ok(Delivered)
    }

    /// 添加白名单。返回值表示**已投递**。
    ///
    /// # Errors
    ///
    /// 见 [`RequestError`]。
    pub fn add_whitelist(
        &self,
        addr: IpAddr,
        prefix_len: u8,
        device: &str,
        _timeout: Duration,
    ) -> Result<Delivered, RequestError> {
        let cmd = codec::AddWhitelist {
            addr,
            prefix_len,
            device: device.to_string(),
        };
        self.transport
            .send(&cmd.encode(self.alloc_seq()))
            .map_err(RequestError::Send)?;
        Ok(Delivered)
    }

    /// 移除白名单。返回值表示**已投递**。
    ///
    /// # Errors
    ///
    /// 见 [`RequestError`]。
    pub fn remove_whitelist(
        &self,
        addr: IpAddr,
        prefix_len: u8,
        device: &str,
        _timeout: Duration,
    ) -> Result<Delivered, RequestError> {
        let cmd = codec::RemoveWhitelist {
            addr,
            prefix_len,
            device: device.to_string(),
        };
        self.transport
            .send(&cmd.encode(self.alloc_seq()))
            .map_err(RequestError::Send)?;
        Ok(Delivered)
    }

    // ------------------------------------------------------------------
    // 分页查询
    // ------------------------------------------------------------------

    /// 取封禁表一页。
    ///
    /// # Errors
    ///
    /// 见 [`RequestError`]。
    pub fn list_bans_page(
        &self,
        offset: u32,
        limit: u32,
        timeout: Duration,
    ) -> Result<codec::PagedBans, RequestError> {
        let query = codec::ListBansQuery(codec::PageQuery { offset, limit });
        let msg = self.request(MsgType::ListBansResponse, timeout, |seq| query.encode(seq))?;
        as_paged_bans(msg)
    }

    /// 取白名单表一页。
    ///
    /// # Errors
    ///
    /// 见 [`RequestError`]。
    pub fn list_whitelist_page(
        &self,
        offset: u32,
        limit: u32,
        timeout: Duration,
    ) -> Result<codec::PagedWhitelist, RequestError> {
        let query = codec::ListWhitelistQuery(codec::PageQuery { offset, limit });
        let msg = self.request(MsgType::ListWhitelistResponse, timeout, |seq| {
            query.encode(seq)
        })?;
        as_paged_whitelist(msg)
    }

    /// 取速率表一页。
    ///
    /// # Errors
    ///
    /// 见 [`RequestError`]。
    pub fn list_rates_page(
        &self,
        offset: u32,
        limit: u32,
        timeout: Duration,
    ) -> Result<codec::PagedRates, RequestError> {
        let query = codec::ListRatesQuery(codec::PageQuery { offset, limit });
        let msg = self.request(MsgType::ListRatesResponse, timeout, |seq| query.encode(seq))?;
        as_paged_rates(msg)
    }

    /// 取回封禁表**全部**条目（自动续页）。
    ///
    /// # Errors
    ///
    /// 见 [`RequestError`]。
    pub fn list_bans_all(&self, timeout: Duration) -> Result<Vec<codec::BanEntry>, RequestError> {
        drain(
            page_cap(ListBansResponse::MAX_TAIL_ENTRIES),
            |offset, limit| {
                let page = self.list_bans_page(offset, limit, timeout)?;
                Ok((page.total, page.offset, page.entries))
            },
        )
    }

    /// 取回白名单表**全部**条目（自动续页）。
    ///
    /// # Errors
    ///
    /// 见 [`RequestError`]。
    pub fn list_whitelist_all(
        &self,
        timeout: Duration,
    ) -> Result<Vec<codec::WhitelistEntry>, RequestError> {
        drain(
            page_cap(ListWhitelistResponse::MAX_TAIL_ENTRIES),
            |offset, limit| {
                let page = self.list_whitelist_page(offset, limit, timeout)?;
                Ok((page.total, page.offset, page.entries))
            },
        )
    }

    /// 取回速率表**全部**条目（自动续页），附带最后一页的全局速率。
    ///
    /// 全局 `pps`/`bps` 是「自上次查询以来的平均速率」，只取最后一次响应即可，
    /// 故以最后一页的取值为准。
    ///
    /// # Errors
    ///
    /// 见 [`RequestError`]。
    pub fn list_rates_all(&self, timeout: Duration) -> Result<codec::RateSnapshot, RequestError> {
        let mut globals = (0u64, 0u64);
        let entries = drain(
            page_cap(ListRatesResponse::MAX_TAIL_ENTRIES),
            |offset, limit| {
                let page = self.list_rates_page(offset, limit, timeout)?;
                globals = (page.global_pps, page.global_bps);
                Ok((page.total, page.offset, page.entries))
            },
        )?;
        Ok(codec::RateSnapshot {
            global_pps: globals.0,
            global_bps: globals.1,
            entries,
        })
    }
}

/// 契约给出的单页上限，转成请求里用的 `u32` 页大小。
///
/// 显式请求上限（而不是传 `limit = 0` 让内核取默认的 256）可以让每页多装条目、
/// 少跑几个来回；上限本身由内核按同一份契约值截断，故这是安全的。
fn page_cap(max_entries: usize) -> u32 {
    u32::try_from(max_entries).unwrap_or(u32::MAX)
}

/// 逐页收集一张表的全部条目。
///
/// 结束条件有三个，缺一不可：
/// 1. 收到的条目数为 0。内核的发送器在 `offset >= total` 时直接回空页，
///    这是**唯一可靠**的收尾信号（`total` 是内核在读表时另行取的值，
///    与已收集到的条数不保证一致，所以不能拿它做「已收齐」的判据）；
/// 2. 本页起点没有推进（防御性：任何情况下都不允许死循环）；
/// 3. 已收条数达到已声明的总数（`total` 为 0 时的正常收尾）。
pub(crate) fn drain<T>(
    cap: u32,
    mut page: impl FnMut(u32, u32) -> Result<(u32, u32, Vec<T>), RequestError>,
) -> Result<Vec<T>, RequestError> {
    let mut all = Vec::new();
    let mut offset = 0u32;
    loop {
        let (total, page_offset, entries) = page(offset, cap)?;
        let got = u32::try_from(entries.len()).unwrap_or(u32::MAX);
        all.extend(entries);
        if got == 0 {
            break;
        }
        // 下一次要请求的起点：本页起点 + 本页条数。
        let next = page_offset.saturating_add(got);
        if next <= offset {
            // 起点没有推进：再请求只会拿到同一段内容。
            break;
        }
        offset = next;
        if all.len() >= total as usize {
            break;
        }
    }
    Ok(all)
}

// ============================================================================
// 回复类型校验
// ============================================================================

/// 把回复映射成期望的类型；类型不符是协议违例，必须报错而不是忽略。
fn mismatch(expected: &'static str, got: &Incoming) -> RequestError {
    RequestError::Unexpected {
        expected,
        got: got.msg_type_name(),
    }
}

fn as_stats(msg: Incoming) -> Result<codec::StatsResponse, RequestError> {
    match msg {
        Incoming::StatsResponse(b) => Ok(*b),
        other => Err(mismatch("StatsResponse", &other)),
    }
}

fn as_analysis(msg: Incoming) -> Result<codec::AnalysisResponse, RequestError> {
    match msg {
        Incoming::AnalysisResponse(b) => Ok(*b),
        other => Err(mismatch("AnalysisResponse", &other)),
    }
}

fn as_config_ack(msg: Incoming) -> Result<codec::ConfigAck, RequestError> {
    match msg {
        Incoming::ConfigAck(b) => Ok(*b),
        other => Err(mismatch("ConfigAck", &other)),
    }
}

fn as_register_ack(msg: Incoming) -> Result<codec::DaemonRegisterAck, RequestError> {
    match msg {
        Incoming::DaemonRegisterAck(b) => Ok(*b),
        other => Err(mismatch("DaemonRegisterAck", &other)),
    }
}

fn as_paged_bans(msg: Incoming) -> Result<codec::PagedBans, RequestError> {
    match msg {
        Incoming::ListBansResponse(b) => Ok(*b),
        other => Err(mismatch("ListBansResponse", &other)),
    }
}

fn as_paged_whitelist(msg: Incoming) -> Result<codec::PagedWhitelist, RequestError> {
    match msg {
        Incoming::ListWhitelistResponse(b) => Ok(*b),
        other => Err(mismatch("ListWhitelistResponse", &other)),
    }
}

fn as_paged_rates(msg: Incoming) -> Result<codec::PagedRates, RequestError> {
    match msg {
        Incoming::ListRatesResponse(b) => Ok(*b),
        other => Err(mismatch("ListRatesResponse", &other)),
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::codec::{frame_for_test, HDR_LEN};
    use crate::kernel::reactor::{LivenessGuard, RegisterError, Router, MAX_IN_FLIGHT};
    use crate::runtime::{Backpressure, Receiver};

    /// 建一个「不接 socket」的路由器，连同它的存活凭据。
    fn router_only() -> (Arc<Router>, Receiver<Incoming>, LivenessGuard) {
        let (tx, rx, _stats) = crate::runtime::channel::bounded(4, Backpressure::Reject);
        let (router, live) = Router::new(tx);
        (Arc::new(router), rx, live)
    }

    /// 建一个客户端。socket 只用于持有 fd——本机的内核模块未加载，
    /// 真正 `sendto` 目标 portid 0 会拿到 `ECONNREFUSED`，故所有测试都走
    /// [`Client::await_reply`]（登记 + 等待，不发送）。
    fn new_client() -> (Client, Receiver<Incoming>, LivenessGuard) {
        let transport = Arc::new(Transport::open().expect("创建 netlink socket 失败"));
        let (router, rx, live) = router_only();
        (Client::new(transport, router), rx, live)
    }

    #[test]
    fn seq_allocation_never_returns_zero_even_across_wraparound() {
        let (client, _events, _live) = new_client();
        // 逼近回绕：`u32::MAX` 之后 fetch_add 会产出 0，必须被跳过。
        client.next_seq.store(u32::MAX - 1, Ordering::Relaxed);
        assert_eq!(client.alloc_seq(), u32::MAX - 1);
        assert_eq!(client.alloc_seq(), u32::MAX);
        assert_eq!(client.alloc_seq(), 1, "回绕产出 0 必须被跳过");
    }

    #[test]
    fn request_is_busy_when_the_in_flight_table_is_full() {
        let (client, _events, _live) = new_client();
        let router = Arc::clone(client.router());

        // 占满在途表；每个 handle 都保持存活（drop 会释放名额）。
        let mut held = Vec::new();
        for i in 0..MAX_IN_FLIGHT {
            held.push(
                router
                    .register(MsgType::StatsResponse, i as u32 + 1000)
                    .expect("应能登记"),
            );
        }
        let err = client
            .await_reply(MsgType::StatsResponse, 999_999, Duration::from_millis(50))
            .expect_err("在途表已满时应拒绝");
        assert!(matches!(err, RequestError::Busy), "实得 {err:?}");
        assert_eq!(
            router.stats().pending_full(),
            1,
            "拒绝必须是可观测的，而不是静默失败"
        );
        drop(held);
    }

    #[test]
    fn a_duplicate_key_is_refused_rather_than_stealing_the_earlier_waiter() {
        let (router, _events, _live) = router_only();
        let first = router
            .register(MsgType::StatsResponse, 8)
            .expect("首次登记应成功");
        // 同一个 (类型, seq) 再登记一次必须被拒：否则后登记者会顶掉先登记者，
        // 先到的那条回复就投给了错误的等待方。
        assert_eq!(
            router.register(MsgType::StatsResponse, 8).unwrap_err(),
            RegisterError::Duplicate
        );
        assert_eq!(router.stats().seq_collisions(), 1);
        assert_eq!(router.in_flight(), 1, "被拒不得影响已有登记");
        assert_eq!(first.key(), (MsgType::StatsResponse.to_raw(), 8));
    }

    #[test]
    fn links_down_when_the_reactor_is_gone() {
        // 接收侧退出 = 存活凭据销毁：等待中的请求必须**立刻**看到失联，
        // 而不是空等到自己的超时（对上层是「重试」与「告警」的区别）。
        let (client, events, live) = new_client();
        drop(events);
        drop(live);
        let start = std::time::Instant::now();
        let err = client
            .await_reply(MsgType::StatsResponse, 5, Duration::from_secs(30))
            .expect_err("链路已断应报错");
        assert!(matches!(err, RequestError::LinkDown), "实得 {err:?}");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "失联必须立即可见，实耗 {:?}",
            start.elapsed()
        );
        assert_eq!(client.router().stats().link_down(), 1, "被拒的指令必须计数");
    }

    #[test]
    fn a_matched_reply_comes_back_through_the_client() {
        let (client, _events, _live) = new_client();
        let router = Arc::clone(client.router());
        // 固定 seq，使喂入线程能构造出配对回复。
        const SEQ: u32 = 7;

        let mut body = vec![0u8; crate::contract::StatsResponse::WIRE_SIZE - HDR_LEN];
        body[0..8].copy_from_slice(&123u64.to_be_bytes());
        let reply = frame_for_test(MsgType::StatsResponse, SEQ, &body);

        let feeder = std::thread::spawn(move || {
            // 轮询到客户端真的登记之后才回复，避免回复早于登记而被判「无人认领」。
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while router.in_flight() == 0 {
                assert!(std::time::Instant::now() < deadline, "客户端未登记在途请求");
                std::thread::yield_now();
            }
            router.route(0, &reply);
        });

        let msg = client
            .await_reply(MsgType::StatsResponse, SEQ, Duration::from_millis(500))
            .expect("应收到回复");
        feeder.join().expect("喂入线程不应 panic");
        assert_eq!(as_stats(msg).expect("类型应匹配").current_bans, 123);
    }

    #[test]
    fn timeout_is_reported_when_no_reply_arrives() {
        let (client, _events, _live) = new_client();
        let err = client
            .await_reply(MsgType::StatsResponse, 11, Duration::from_millis(30))
            .expect_err("无回复应超时");
        assert!(matches!(err, RequestError::Timeout), "实得 {err:?}");
    }

    #[test]
    fn a_reply_for_another_seq_is_not_delivered_to_this_waiter() {
        // 内核回了一个不同 seq 的回复：不能落到本等待者手里。
        let (client, _events, _live) = new_client();
        let router = Arc::clone(client.router());
        let feeder = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while router.in_flight() == 0 {
                assert!(std::time::Instant::now() < deadline, "客户端未登记在途请求");
                std::thread::yield_now();
            }
            let body = [0u8; crate::contract::StatsResponse::WIRE_SIZE - HDR_LEN];
            router.route(0, &frame_for_test(MsgType::StatsResponse, 4242, &body));
        });
        let err = client
            .await_reply(MsgType::StatsResponse, 4243, Duration::from_millis(200))
            .expect_err("seq 不符不应投递");
        feeder.join().expect("喂入线程不应 panic");
        assert!(matches!(err, RequestError::Timeout), "实得 {err:?}");
        // 「无人认领」必须是可观测的，而不是静默丢弃。
        assert_eq!(client.router().stats().unmatched_replies(), 1);
    }

    #[test]
    fn a_reply_of_the_wrong_type_never_reaches_the_waiter() {
        // 类型是配对键的一部分：内核发了 ConfigAck 却有人等 StatsResponse，
        // 这条回复就不该被当成「回复到了」。适配函数本身在任何情况下都不做
        // 强制转换——这里直接喂一个不符的枚举值来守住这一点。
        let (router, _events, _live) = router_only();
        let handle = router
            .register(MsgType::StatsResponse, 3)
            .expect("登记在途请求");
        router.route(0, &frame_for_test(MsgType::ConfigAck, 3, &[0u8; 8]));
        assert!(
            matches!(
                handle.recv_timeout(Duration::from_millis(50)),
                Err(RecvTimeoutError::Timeout)
            ),
            "类型不符的回复不得投给本等待者"
        );
        assert_eq!(
            router.stats().unmatched_replies(),
            1,
            "落空的回复必须计数，而不是静默丢弃"
        );

        let err = as_stats(Incoming::ConfigAck(Box::new(codec::ConfigAck {
            applied_flags: 0,
            rejected_flags: 0,
        })))
        .expect_err("适配函数不得把 ConfigAck 当成 StatsResponse");
        match err {
            RequestError::Unexpected { expected, got } => {
                assert_eq!(expected, "StatsResponse");
                assert_eq!(got, "ConfigAck");
            }
            other => panic!("实得 {other:?}"),
        }
    }

    #[test]
    fn drain_walks_every_page_until_total_is_reached() {
        // 5 条、每页 2 条 ⇒ 请求 3 次（2+2+1），最后靠「已收齐 total」收尾。
        let mut calls = 0;
        let got = drain(2, |offset, limit| {
            calls += 1;
            assert_eq!(limit, 2, "必须按调用方给的页上限请求");
            let total = 5u32;
            let end = (offset + 2).min(total);
            let entries: Vec<u32> = (offset..end).collect();
            Ok((total, offset, entries))
        })
        .expect("续页不应失败");
        assert_eq!(got, vec![0, 1, 2, 3, 4]);
        assert_eq!(calls, 3, "应为 3 次请求（2+2+1）");
    }

    #[test]
    fn drain_stops_when_the_kernel_reports_an_empty_page() {
        // 内核把 total 报成 100（实际只有 3 条）：必须靠空页收尾，而不是无限请求。
        let mut calls = 0;
        let got = drain(10, |offset, _limit| {
            calls += 1;
            let entries: Vec<u32> = if offset == 0 { vec![1, 2, 3] } else { vec![] };
            Ok((100u32, offset, entries))
        })
        .expect("续页不应失败");
        assert_eq!(got, vec![1, 2, 3]);
        assert_eq!(calls, 2, "第一页有数据 + 第二页空 ⇒ 两次请求");
    }

    #[test]
    fn drain_never_loops_forever_when_the_kernel_does_not_advance() {
        // 内核始终回同一段内容（offset 不推进）：必须在第二次就停下。
        let mut calls = 0;
        let got = drain(4, |_offset, _limit| {
            calls += 1;
            Ok((100u32, 0u32, vec![9, 9]))
        })
        .expect("续页不应失败");
        assert_eq!(calls, 2, "起点未推进时必须停止，不能死循环");
        assert_eq!(got, vec![9, 9, 9, 9]);
    }

    #[test]
    fn drain_of_an_empty_table_asks_once() {
        // 空表：内核在 offset >= total(=0) 时直接回空页；只应请求一次。
        let mut calls = 0;
        let got: Vec<u32> = drain(8, |_offset, _limit| {
            calls += 1;
            Ok((0u32, 0u32, Vec::new()))
        })
        .expect("续页不应失败");
        assert!(got.is_empty());
        assert_eq!(calls, 1);
    }

    #[test]
    fn page_caps_match_the_contract() {
        // 请求页上限必须来自契约，而不是写死的旧值（旧实现白名单是 64/256，
        // 与契约的 1926 冲突）。
        assert_eq!(page_cap(ListBansResponse::MAX_TAIL_ENTRIES), 696);
        assert_eq!(page_cap(ListWhitelistResponse::MAX_TAIL_ENTRIES), 1926);
        assert_eq!(page_cap(ListRatesResponse::MAX_TAIL_ENTRIES), 779);
    }
}
