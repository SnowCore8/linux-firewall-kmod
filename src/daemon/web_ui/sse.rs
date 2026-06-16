//! SSE（Server-Sent Events）流式响应实现
//!
//! 基于 tiny_http 的自定义 Reader，实现长连接事件推送。
//! 每个连接一个后台线程，定期从数据源读取并推送事件。

use std::io::{self, Read};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use tiny_http::{Header, Request, Response, StatusCode};

use super::api;
use crate::http_exporter::get_global_jails;

/// SSE 流式 Reader
///
/// 实现 `std::io::Read`，tiny_http 会持续调用 `read()` 发送数据。
/// 通过 mpsc channel 接收事件，格式化为 SSE 协议后写入缓冲区。
struct SseReader {
    receiver: mpsc::Receiver<SseMessage>,
    buffer: Vec<u8>,
    buffer_pos: usize,
}

/// SSE 消息类型
enum SseMessage {
    /// 命名事件（带 event 字段）
    Event { name: String, data: String },
    /// 默认事件（无 event 字段）
    Data(String),
    /// 注释（以 : 开头）
    Comment(String),
    /// 关闭连接
    Close,
}

impl SseReader {
    fn new(receiver: mpsc::Receiver<SseMessage>) -> Self {
        Self {
            receiver,
            buffer: Vec::new(),
            buffer_pos: 0,
        }
    }

    /// 将消息格式化为 SSE 协议
    fn format_message(msg: &SseMessage) -> Vec<u8> {
        match msg {
            SseMessage::Event { name, data } => {
                format!("event: {}\ndata: {}\n\n", name, data).into_bytes()
            }
            SseMessage::Data(data) => {
                format!("data: {}\n\n", data).into_bytes()
            }
            SseMessage::Comment(comment) => {
                format!(": {}\n\n", comment).into_bytes()
            }
            SseMessage::Close => Vec::new(),
        }
    }
}

impl Read for SseReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // 如果缓冲区有剩余数据，继续发送
        if self.buffer_pos < self.buffer.len() {
            let remaining = &self.buffer[self.buffer_pos..];
            let len = remaining.len().min(buf.len());
            buf[..len].copy_from_slice(&remaining[..len]);
            self.buffer_pos += len;
            if self.buffer_pos >= self.buffer.len() {
                self.buffer.clear();
                self.buffer_pos = 0;
            }
            return Ok(len);
        }

        // 缓冲区空了，等待新消息（最长 30 秒超时发送 keep-alive）
        match self.receiver.recv_timeout(Duration::from_secs(30)) {
            Ok(SseMessage::Close) => Ok(0), // EOF，关闭连接
            Ok(msg) => {
                self.buffer = Self::format_message(&msg);
                self.buffer_pos = 0;
                // 递归调用读取刚填充的缓冲区
                self.read(buf)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // 超时，发送 SSE 注释作为 keep-alive
                self.buffer = b": keep-alive\n\n".to_vec();
                self.buffer_pos = 0;
                self.read(buf)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(0), // 发送端关闭
        }
    }
}

/// 处理 SSE 连接请求
///
/// 创建后台线程定期推送事件，返回流式响应。
pub fn handle_sse_connection(request: Request) {
    let (sender, receiver) = mpsc::channel::<SseMessage>();

    // 启动后台线程：定期收集并推送数据
    thread::spawn(move || {
        // 初始连接，发送欢迎注释
        let _ = sender.send(SseMessage::Comment("SSE 连接已建立".to_string()));

        loop {
            // 收集统计数据
            let stats = api::get_stats();
            let stats_json = match serde_json::to_string(&stats) {
                Ok(j) => j,
                Err(_) => {
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };
            if sender
                .send(SseMessage::Event {
                    name: "stats".to_string(),
                    data: stats_json,
                })
                .is_err()
            {
                break; // 客户端断开
            }

            // 收集封禁列表
            let bans = api::get_active_bans();
            let bans_json = match serde_json::to_string(&bans) {
                Ok(j) => j,
                Err(_) => {
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };
            if sender
                .send(SseMessage::Event {
                    name: "bans".to_string(),
                    data: bans_json,
                })
                .is_err()
            {
                break;
            }

            // 收集 Jail 列表
            if let Some(jail_infos) = get_global_jails() {
                let jails = api::get_jails(jail_infos);
                let jails_json = match serde_json::to_string(&jails) {
                    Ok(j) => j,
                    Err(_) => {
                        thread::sleep(Duration::from_secs(1));
                        continue;
                    }
                };
                if sender
                    .send(SseMessage::Event {
                        name: "jails".to_string(),
                        data: jails_json,
                    })
                    .is_err()
                {
                    break;
                }
            }

            // 收集 DDoS 速率数据
            let rates = api::get_ddos_rates();
            let rates_json = match serde_json::to_string(&rates) {
                Ok(j) => j,
                Err(_) => {
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };
            if sender
                .send(SseMessage::Event {
                    name: "rates".to_string(),
                    data: rates_json,
                })
                .is_err()
            {
                break;
            }

            // 等待 1 秒后推送下一轮
            thread::sleep(Duration::from_secs(1));
        }
    });

    // 构造 SSE 响应
    let reader = SseReader::new(receiver);
    let response = Response::new(
        StatusCode(200),
        vec![
            Header::from_bytes("Content-Type", "text/event-stream").expect("静态 ASCII 头"),
            Header::from_bytes("Cache-Control", "no-cache").expect("静态 ASCII 头"),
            Header::from_bytes("Connection", "keep-alive").expect("静态 ASCII 头"),
            Header::from_bytes("X-Accel-Buffering", "no").expect("静态 ASCII 头"), // Nginx 禁用缓冲
        ],
        reader,
        None,
        None,
    );

    if let Err(e) = request.respond(response) {
        crate::logger::warn!(
            crate::logger::get(),
            "SSE 响应发送失败";
            "error" => %e
        );
    }
}
