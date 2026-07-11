//! 主题切换 — dark/light 双主题
#![allow(dead_code)]

use leptos::*;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Theme {
    Dark,
    Light,
}

thread_local! {
    static THEME: RwSignal<Theme> = create_rw_signal(Theme::Dark);
}

pub fn use_theme() -> RwSignal<Theme> {
    THEME.with(|t| *t)
}

/// 初始化主题（从 localStorage 读取，或默认 dark）
pub fn init_theme() {
    let stored = web_sys::window()
        .and_then(|w| w.local_storage().ok())
        .flatten()
        .and_then(|s| s.get_item("theme").ok())
        .flatten();

    let theme = match stored.as_deref() {
        Some("light") => Theme::Light,
        _ => Theme::Dark,
    };

    THEME.with(|t| t.set(theme));
    apply_theme(theme);

    // 监听主题变化
    create_effect(move |_| {
        let theme = THEME.with(|t| t.get());
        apply_theme(theme);
        if let Some(storage) = web_sys::window()
            .and_then(|w| w.local_storage().ok())
            .flatten()
        {
            let val = match theme {
                Theme::Dark => "dark",
                Theme::Light => "light",
            };
            let _ = storage.set_item("theme", val);
        }
    });
}

pub fn toggle_theme() {
    THEME.with(|t| {
        let current = t.get();
        let new = match current {
            Theme::Dark => Theme::Light,
            Theme::Light => Theme::Dark,
        };
        t.set(new);
    });
}

fn apply_theme(theme: Theme) {
    let val = match theme {
        Theme::Dark => "dark",
        Theme::Light => "light",
    };
    if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
        if let Some(el) = doc.document_element() {
            let _ = el.set_attribute("data-theme", val);
        }
        // 主题切换平滑过渡：添加 class → 350ms 后移除
        if let Some(body) = doc.body() {
            let _ = body.class_list().add_1("theme-transitioning");
            let body_clone = body.clone();
            set_timeout(
                move || {
                    let _ = body_clone.class_list().remove_1("theme-transitioning");
                },
                std::time::Duration::from_millis(350),
            );
        }
    }
}
