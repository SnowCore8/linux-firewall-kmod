package config

import "sync"

// configMu 是进程级配置实例的统一读写闸。
//
// # 为什么是包级变量而不是 Config 的字段
//
// Config 在所有地方都按值传递：applyConfig 做整份替换（`*cfg = newCfg`）、
// loadConfigContent / Default() 返回副本、重载从 Default() 起步再填字段。给
// Config 加一个 sync.RWMutex 字段有两个后果：go vet 的 copylocks 会在每一处值
// 复制上报错；复制出来的锁保护的是另一块内存，看着有锁、实际各锁各的。所以闸门
// 挂在包级，锁的是「那一个共享实例」，与实例的复制无关。
//
// # 保证的边界
//
// 锁保证的是「同一把读锁内读到的多个字段来自同一版本」。配置有两个写方：
//
//   - 重载 / 回滚：持有写锁做整份替换 `*cfg = newCfg`（runtime.applyConfig）。
//     没有写锁时，读方可能读到新 Jails 的 slice 头配旧 Ddos，或读到撕裂的 slice 头
//     （非法指针）。
//   - HTTP PUT /api/v2/config：持有写锁局部改写 cfg.Webui 与 cfg.Ddos 的三个开关
//     （http.persistWebui），文件 I/O 与内核下发都在锁外。
//
// 除此之外没有更强的保证：两次写之间读到的可以是旧版本，跨字段一致只在单次读锁
// 内成立；需要多个字段共同参与判断的读方必须在同一把读锁里一次取完、拷到局部变量，
// 不能读一半、解锁、再读另一半。返回指向 cfg 内部（cfg.Jails 元素之类）的指针是
// 不被允许的——解锁之后那个指针就没有保护了。
//
// # 纪律
//
// 持写锁期间不得调用对外组件（文件 I/O、netlink 下发、重载器），否则一次磁盘抖动
// 会钉住所有读方；也不要在持锁时再取读锁（sync.RWMutex 不可重入，会自锁）。重载器
// 的 Reload/Rollback 会在内部取写锁，所以调用它们前后都不能持有本锁。
var configMu sync.RWMutex

// LockConfig 取写锁，供改写共享配置的代码使用。
//
// 只包住对字段的赋值本身：读旧值、算新值、写文件、下发内核都在锁外完成。
func LockConfig() { configMu.Lock() }

// UnlockConfig 释放写锁。
func UnlockConfig() { configMu.Unlock() }

// RLockConfig 取读锁，供与写方并发执行的读方使用。
//
// 读锁内只做「拷到局部变量」这一件事，拷完立刻 RUnlockConfig。
func RLockConfig() { configMu.RLock() }

// RUnlockConfig 释放读锁。
func RUnlockConfig() { configMu.RUnlock() }
