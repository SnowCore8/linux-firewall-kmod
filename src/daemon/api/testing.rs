//! 测试替身：端口的可控实现。
//!
//! # 为什么需要
//!
//! 路由测试要能断言「读路径不改状态」「业务码映射正确」「分页切片正确」，就必须
//! 让历史/配置/控制面**可替换**：否则测试会被旧全局（SQLite、内核 netlink、
//! `OnceLock`）绑住，只能写成恒真断言——正是设计文档「测试债务」一节要消灭的
//! 那类东西。
//!
//! 替身也把「失败路径」变得可达：`ControlPort` 的实现可以在测试里指定返回错误，
//! 从而验证 40001 / 40002 / 40003 / 40004 真的会被产生。

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::ports::{
    BanCommand, BanHistoryView, BanOutcome, ConfigPort, ControlPort, HistoryPort, JailView,
    RuntimePort, RuntimeView, ThreatInputs, TrendsView, WebuiConfigPatch, WebuiConfigView,
};
use super::routes::ApiState;
use super::sse::SseStatus;
use crate::state::State;

/// 所有端口方法都成功、数据可控的配置端口。
#[derive(Debug)]
pub struct FakeConfigPort {
    /// 当前配置值。
    pub config: Mutex<WebuiConfigView>,
    /// 返回给 `jails()` 的列表。
    pub jails: Mutex<Vec<JailView>>,
    /// 设定为 `Some` 时，`apply` 返回该错误。
    pub apply_error: Mutex<Option<String>>,
    /// 设定为 `Some` 时，`set_jail_enabled` 返回该错误。
    pub jail_error: Mutex<Option<String>>,
}

impl Default for FakeConfigPort {
    fn default() -> Self {
        Self {
            config: Mutex::new(WebuiConfigView {
                rate_warning_pps: 100_000,
                ..WebuiConfigView::default()
            }),
            jails: Mutex::new(Vec::new()),
            apply_error: Mutex::new(None),
            jail_error: Mutex::new(None),
        }
    }
}

impl ConfigPort for FakeConfigPort {
    fn webui(&self) -> WebuiConfigView {
        self.config.lock().expect("锁未中毒").clone()
    }

    fn apply(&self, _patch: WebuiConfigPatch) -> Result<WebuiConfigView, String> {
        if let Some(err) = self.apply_error.lock().expect("锁未中毒").clone() {
            return Err(err);
        }
        Ok(self.webui())
    }

    fn jails(&self) -> Vec<JailView> {
        self.jails.lock().expect("锁未中毒").clone()
    }

    fn set_jail_enabled(&self, name: &str, enabled: bool) -> Result<JailView, String> {
        if let Some(err) = self.jail_error.lock().expect("锁未中毒").clone() {
            return Err(err);
        }
        let mut jails = self.jails.lock().expect("锁未中毒");
        let jail = jails
            .iter_mut()
            .find(|j| j.name == name)
            .ok_or_else(|| format!("Jail '{name}' 不存在"))?;
        jail.enabled = enabled;
        Ok(jail.clone())
    }
}

/// 运行时端口替身：就绪态与指标文本可控。
#[derive(Debug, Default)]
pub struct FakeRuntimePort {
    /// `snapshot()` 的返回值来源。
    pub ready: bool,
}

impl RuntimePort for FakeRuntimePort {
    fn snapshot(&self) -> RuntimeView {
        RuntimeView {
            status: if self.ready { "ok" } else { "degraded" },
            netlink_ready: self.ready,
            kmod_proc_present: self.ready,
            ban_cache_initialized: true,
            ban_history_initialized: true,
            active_bans: 0,
            lease_state: if self.ready { "held" } else { "idle" },
            lease_losses: 0,
        }
    }

    fn metrics_text(&self) -> String {
        "# metrics\n".to_string()
    }
}

/// 历史端口替身：趋势与信誉查询计数，便于断言「读路径只读」。
#[derive(Debug, Default)]
pub struct FakeHistoryPort {
    /// `trends()` 被调用次数。
    pub trend_calls: AtomicUsize,
    /// `ban_history()` 被调用次数。
    pub history_calls: AtomicUsize,
    /// 威胁输入。
    pub inputs: ThreatInputs,
    /// `today_bans()` 的返回值（默认 0，测试可覆盖以断言载荷确实取自端口）。
    pub today_bans: u64,
}

impl HistoryPort for FakeHistoryPort {
    fn trends(&self) -> TrendsView {
        self.trend_calls.fetch_add(1, Ordering::Relaxed);
        TrendsView::default()
    }

    fn ban_history(&self, _ip: IpAddr) -> Option<BanHistoryView> {
        self.history_calls.fetch_add(1, Ordering::Relaxed);
        Some(BanHistoryView::default())
    }

    fn threat_inputs(&self) -> ThreatInputs {
        self.inputs
    }

    fn today_bans(&self) -> u64 {
        self.today_bans
    }
}

/// 控制面替身：可指定失败，并记录收到的指令。
#[derive(Debug, Default)]
pub struct FakeControlPort {
    /// `ban` 的返回值（`None` = 成功）。
    pub ban_error: Mutex<Option<String>>,
    /// `unban` 的返回值（`None` = 成功）。
    pub unban_error: Mutex<Option<String>>,
    /// 收到的封禁指令。
    pub bans: Mutex<Vec<BanCommand>>,
    /// 收到的解封目标。
    pub unbans: Mutex<Vec<IpAddr>>,
    /// 收到的白名单添加。
    pub whitelist_adds: Mutex<Vec<String>>,
    /// 收到的白名单移除。
    pub whitelist_removes: Mutex<Vec<String>>,
}

impl ControlPort for FakeControlPort {
    fn ban(&self, cmd: BanCommand) -> Result<BanOutcome, String> {
        // 与真实实现（LegacyControlPort → create_ban）逐字对齐：`None` 与 `Some(0)`
        // 都是永久封禁。替身若只认 `Some(0)`，`duration: None` 的错误就会在测试里
        // 表现为「普通封禁」而蒙混过关——批量封禁曾被这样漏过。
        let permanent = cmd.duration.is_none() || cmd.duration == Some(0);
        self.bans.lock().expect("锁未中毒").push(cmd);
        if let Some(err) = self.ban_error.lock().expect("锁未中毒").clone() {
            return Err(err);
        }
        Ok(BanOutcome {
            permanent,
            duration_seconds: if permanent { None } else { Some(600) },
        })
    }

    fn unban(&self, ip: IpAddr) -> Result<(), String> {
        self.unbans.lock().expect("锁未中毒").push(ip);
        match self.unban_error.lock().expect("锁未中毒").clone() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn add_whitelist(&self, cidr: &str) -> Result<String, String> {
        self.whitelist_adds
            .lock()
            .expect("锁未中毒")
            .push(cidr.to_string());
        // 返回规范化后的文本，模拟内核的规范化行为。
        crate::state::cidr::CidrKey::parse(cidr)
            .map(|k| k.to_string())
            .map_err(|e| e.to_string())
    }

    fn remove_whitelist(&self, cidr: &str) -> Result<String, String> {
        self.whitelist_removes
            .lock()
            .expect("锁未中毒")
            .push(cidr.to_string());
        crate::state::cidr::CidrKey::parse(cidr)
            .map(|k| k.to_string())
            .map_err(|e| e.to_string())
    }
}

/// 组装一套全替身依赖。
///
/// 只保留真实际被测试读取的字段：其余替身在构造时就交给 `api` 持有，测试通过
/// `api` 间接使用它们（例如 `h.api.control.ban_error`），无需在此再暴露一份。
pub struct Harness {
    /// 状态所有者（真实现：它已经是无全局的）。
    pub state: Arc<State>,
    /// 配置替身。
    pub config: Arc<FakeConfigPort>,
    /// 控制替身。
    pub control: Arc<FakeControlPort>,
    /// 两条 SSE 流的计数。
    pub sse: Arc<SseStatus>,
    /// 供处理函数使用的依赖集合。
    pub api: Arc<ApiState>,
}

impl Harness {
    /// 构造全替身环境（运行时报就绪）。
    #[must_use]
    pub fn new() -> Self {
        Self::with_readiness(true)
    }

    /// 构造全替身环境，并指定就绪态。
    #[must_use]
    pub fn with_readiness(ready: bool) -> Self {
        let state = State::new();
        let config = Arc::new(FakeConfigPort::default());
        let runtime: Arc<dyn RuntimePort> = Arc::new(FakeRuntimePort { ready });
        let history: Arc<dyn HistoryPort> = Arc::new(FakeHistoryPort::default());
        let control = Arc::new(FakeControlPort::default());
        let sse = Arc::new(SseStatus::new());
        let api = Arc::new(ApiState::new(
            Arc::clone(&state),
            Arc::clone(&config) as Arc<dyn ConfigPort>,
            runtime,
            history,
            Arc::clone(&control) as Arc<dyn ControlPort>,
            Arc::clone(&sse),
            "2.2",
        ));
        Self {
            state,
            config,
            control,
            sse,
            api,
        }
    }

    /// 加一个 Jail 到配置替身。
    pub fn with_jail(self, name: &str) -> Self {
        self.config.jails.lock().expect("锁未中毒").push(JailView {
            name: name.to_string(),
            enabled: true,
            max_retries: 5,
            effective_max_retries: 5,
            findtime: 600,
            ban_time: 3600,
            is_peak_hours: false,
            peak_hours_multiplier: 1.0,
            internal_ip_multiplier: 2.0,
        });
        self
    }

    /// 指定历史端口给出的「今日封禁数」，用于断言载荷确实取自该端口。
    ///
    /// 端口以 `Arc<dyn HistoryPort>` 存入 [`ApiState`]，构造后无法回改；故这里
    /// 重建一份带值的替身并换掉 `ApiState` 里的那一份。
    #[must_use]
    pub fn with_today_bans(mut self, today_bans: u64) -> Self {
        let history: Arc<dyn HistoryPort> = Arc::new(FakeHistoryPort {
            today_bans,
            ..FakeHistoryPort::default()
        });
        self.api = Arc::new(ApiState::new(
            Arc::clone(&self.state),
            Arc::clone(&self.config) as Arc<dyn ConfigPort>,
            Arc::new(FakeRuntimePort { ready: true }) as Arc<dyn RuntimePort>,
            history,
            Arc::clone(&self.control) as Arc<dyn ControlPort>,
            Arc::clone(&self.sse),
            "2.2",
        ));
        self
    }
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}
