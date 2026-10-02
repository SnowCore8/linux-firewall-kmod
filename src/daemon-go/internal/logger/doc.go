// Package logger 是守护进程的日志系统：按配置的目的地与格式写出结构化日志。
//
// 移植自 Rust 版 `src/daemon/logger.rs`，保留其核心保证：
//
//   - JSON Lines：每行一条 JSON 对象，字段顺序 `ts` → `level` → `msg` → `version` → 其他；
//   - 整行单次写出：一条记录（含结尾换行）先在内存编码成一个 []byte，再单次 Write。
//     文件以 O_APPEND 打开时单次写对常规文件按行原子，拆成两次会让并发写者（另一进程、
//     另一 fd）的记录插进中间——进程内互斥锁对跨进程写者不生效；
//   - 按大小轮转：由 `log_max_size_mb` 与 `log_max_files` 控制，片名 `<base>.<n>`，n 越大越旧。
//
// Rust 版的 logger 只实现「JSON Lines → 文件」，本包在此之上补上配置里已声明但未被 Rust
// 使用的三个维度：日志目的地（`log_destination`）、日志格式（`log_format`）与级别门槛
// （`log_level`）。
//
// 初始化失败一律不致命：目的地不可用时降级到其余可用目的地，全部不可用时退化为 stderr
// ——日志系统自身的问题不应让守护进程崩掉。
package logger
