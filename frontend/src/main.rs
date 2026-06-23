//! Firewall 控制面板 — Leptos WASM 前端

mod api;
mod charts;
mod components;
mod format;
mod performance;
mod sse;
mod theme;
mod types;
mod validation;
mod views;

use leptos::*;
use leptos_router::*;

use components::layout::DefaultLayout;
use views::{bans, dashboard, ddos, jails, logs, settings, whitelist};

fn main() {
    performance::setup_error_handler();
    console_error_panic_hook::set_once();

    mount_to_body(move || {
        // 在顶层 Owner 中创建 SSE 状态——生命周期 = 整个应用，路由切换不丢失
        let sse_state = sse::SseState::create();
        provide_context(sse_state.clone());

        view! {
            <Router>
                <DefaultLayout sse_state=sse_state>
                    <Routes>
                        <Route path="/" view=|| view! { <Redirect path="/dashboard"/> }/>
                        <Route path="/dashboard" view=dashboard::Dashboard/>
                        <Route path="/bans" view=bans::Bans/>
                        <Route path="/whitelist" view=whitelist::Whitelist/>
                        <Route path="/jails" view=jails::Jails/>
                        <Route path="/ddos" view=ddos::DdosMonitor/>
                        <Route path="/logs" view=logs::Logs/>
                        <Route path="/settings" view=settings::Settings/>
                    </Routes>
                </DefaultLayout>
            </Router>
        }
    })
}
