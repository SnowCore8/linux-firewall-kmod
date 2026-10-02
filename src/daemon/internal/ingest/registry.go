package ingest

import (
	"strconv"
)

// SourceID 是稳定的日志源标识。分配后不再变化，与 inotify wd 解耦。
//
// 旧实现用文件状态切片的下标表示文件身份，而 jail 启用状态变化会重建整个切片，
// 重建后下标与实际 watch 的对应关系依赖重建顺序——那是隐式契约，编译期毫无保障。
// 这里把身份变成显式类型，各源的读取偏移、半行缓冲、失败计数窗口都能安全地以它为键。
type SourceID uint32

// NewSourceID 由数值构造身份编号，供不依赖 inotify 的纯逻辑测试使用。
func NewSourceID(v uint32) SourceID { return SourceID(v) }

// Get 返回数值形式（日志与诊断用）。
func (s SourceID) Get() uint32 { return uint32(s) }

// String 返回 `#n` 形式，便于日志阅读。
func (s SourceID) String() string { return "#" + strconv.FormatUint(uint64(s), 10) }

// SourceOwner 是登记项的用途：区分日志源与被监视的配置文件。
type SourceOwner struct {
	// Jail 非空表示某个 jail 的日志源；为空且 IsConfig 为真表示配置文件。
	Jail string
	// IsConfig 为真表示这是守护进程自身的配置文件。
	IsConfig bool
}

// LogOwner 构造一个日志源归属。
func LogOwner(jail string) SourceOwner { return SourceOwner{Jail: jail} }

// ConfigOwner 构造配置文件归属。
func ConfigOwner() SourceOwner { return SourceOwner{IsConfig: true} }

// SourceEntry 是一个登记项的当前状态。
type SourceEntry struct {
	// Owner 是用途（日志源 / 配置文件）。
	Owner SourceOwner
	// Path 是被监视的路径（已归一化）。
	Path string
	// WD 是当前生效的 inotify watch 描述符（轮转后会更新）。
	WD int32
	// Inode 是登记（或最近一次重挂）时记录的 inode，仅用于诊断日志。
	Inode uint64
}

// SourceRegistry 是 SourceID ↔ wd ↔ path 三向映射，由采集协程独占（无需锁）。
type SourceRegistry struct {
	byID   map[SourceID]*SourceEntry
	byWD   map[int32]SourceID
	byPath map[string]SourceID
	next   uint32
}

// NewSourceRegistry 新建空注册表。
func NewSourceRegistry() *SourceRegistry {
	return &SourceRegistry{
		byID:   make(map[SourceID]*SourceEntry),
		byWD:   make(map[int32]SourceID),
		byPath: make(map[string]SourceID),
	}
}

// Register 登记一个被监视的路径，返回其稳定身份。
//
// 同一路径重复登记（轮转重挂、重载后重扫）返回**同一个** SourceID，只更新 wd 与
// inode；这样各源以身份为键的偏移与缓冲不会被重挂动作清空。
func (r *SourceRegistry) Register(owner SourceOwner, path string, wd int32, inode uint64) SourceID {
	path = CleanPath(path)
	if id, ok := r.byPath[path]; ok {
		r.Rebind(id, wd, inode)
		// 重载可能改变归属（同一路径改挂到别的 jail），故归属一并更新。
		r.byID[id].Owner = owner
		return id
	}

	id := SourceID(r.next)
	r.next++
	// 该路径之前可能登记过别的 wd（理论上不会：byPath 已去重），但防御性摘除可
	// 避免 byWD 里留下指向旧身份的悬挂映射。
	for otherWD, mapped := range r.byWD {
		if mapped == id {
			delete(r.byWD, otherWD)
		}
	}
	r.byWD[wd] = id
	r.byPath[path] = id
	r.byID[id] = &SourceEntry{Owner: owner, Path: path, WD: wd, Inode: inode}
	return id
}

// Rebind 更新某个身份当前的 wd 与 inode（轮转后重挂 watch 时调用）。
func (r *SourceRegistry) Rebind(id SourceID, wd int32, inode uint64) {
	entry, ok := r.byID[id]
	if !ok {
		return
	}
	oldWD := entry.WD
	entry.WD = wd
	entry.Inode = inode
	// 旧 wd 可能因轮转已失效；内核的 wd 可复用，同值重挂不得把当前映射删掉。
	if oldWD != wd {
		delete(r.byWD, oldWD)
		r.byWD[wd] = id
	}
}

// Resolve 由 wd 找到稳定身份。未知 wd（已被摘除的旧 watch）返回 false。
func (r *SourceRegistry) Resolve(wd int32) (SourceID, bool) {
	id, ok := r.byWD[wd]
	return id, ok
}

// Get 按身份取状态。
func (r *SourceRegistry) Get(id SourceID) (SourceEntry, bool) {
	entry, ok := r.byID[id]
	if !ok {
		return SourceEntry{}, false
	}
	return *entry, true
}

// Remove 摘除一个身份，返回其状态（调用方据此摘 watch）。
func (r *SourceRegistry) Remove(id SourceID) (SourceEntry, bool) {
	entry, ok := r.byID[id]
	if !ok {
		return SourceEntry{}, false
	}
	delete(r.byID, id)
	delete(r.byPath, entry.Path)
	// 只有当 byWD 里的映射确实指向本身份时才删除：轮转后可能已由 Rebind 指向
	// 新 wd，按旧 wd 删除会误删当前映射。
	if mapped, ok := r.byWD[entry.WD]; ok && mapped == id {
		delete(r.byWD, entry.WD)
	}
	return *entry, true
}

// Entries 返回全部登记项的副本（顺序不保证）。
func (r *SourceRegistry) Entries() []SourceEntry {
	out := make([]SourceEntry, 0, len(r.byID))
	for _, entry := range r.byID {
		out = append(out, *entry)
	}
	return out
}

// Iterate 以身份为键遍历全部登记项，将 (身份, 状态副本) 交给 fn。
//
// 收敛路径（reconcile）必须能按身份挑出过期项并逐项摘除，而 Entries 只返回不带身份
// 的状态副本，无从定位要摘的对象，故单独提供按身份迭代的入口。fn 拿到的是状态副本，
// 在回调内改动它不会影响注册表。
func (r *SourceRegistry) Iterate(fn func(id SourceID, entry SourceEntry)) {
	for id, entry := range r.byID {
		fn(id, *entry)
	}
}

// ContainsPath 报告是否已登记该路径。
func (r *SourceRegistry) ContainsPath(path string) bool {
	_, ok := r.byPath[CleanPath(path)]
	return ok
}

// Len 返回当前登记项数量。
func (r *SourceRegistry) Len() int { return len(r.byID) }

// IsEmpty 报告是否没有任何登记项。
func (r *SourceRegistry) IsEmpty() bool { return len(r.byID) == 0 }
