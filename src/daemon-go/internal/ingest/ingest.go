// Package ingest 承载日志采集：inotify 监视、源身份登记、按源增量读取。
//
// 本层由**单个采集协程**独占运行（见设计文档「运行时模型」），因此内部状态一律
// 不加锁：注册表、读取器表、上层的半行缓冲都只被该协程触碰。跨协程只传「已脱离
// 本层的不可变消息」。
//
// 三个子文件各担一件事，替换掉旧实现的三个结构问题：
//
//	watcher.go   inotify fd 的唯一所有权 + 事件读取   消除「fd 与 raw_fd 两处记账」
//	registry.go  SourceID ↔ (path, wd, inode) 映射    消除「用下标当身份」
//	reader.go    每源 fd、offset、复用缓冲            消除「每事件重开、重分配 256 KiB」
package ingest
