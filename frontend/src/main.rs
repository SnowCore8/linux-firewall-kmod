//! Firewall 控制面板 — Leptos WASM 前端

mod api;
mod charts;
mod components;
mod format;
mod sse;
mod theme;
mod views;

use leptos::*;
use leptos_router::*;

use components::layout::DefaultLayout;
use views::{bans, dashboard, ddos, jails, logs, settings, whitelist};

fn main() {
    console_error_panic_hook::set_once();
    mount_to_body(|| {
        view! {
            <Router>
                <DefaultLayout>
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
    });
}
