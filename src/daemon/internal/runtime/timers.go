package runtime

import "time"

// TimerID 是定时器句柄。Cancel 之后该 id 失效，槽位会被后续登记复用。
type TimerID int

// Fired 是一次到期事件。
type Fired struct {
	// ID 是到期的定时器。
	ID TimerID
	// Repeating 为真表示这是周期定时器（已重排到下一个周期）；为假表示一次性
	// （已从表中移除）。
	Repeating bool
}

// timerSlot 是一个定时器槽位。
type timerSlot struct {
	// deadline 是下次到期时刻（单调时钟）。
	deadline time.Time
	// period 为 0 表示一次性；大于 0 表示周期。
	period time.Duration
}

// TimerTable 是固定容量的单调时钟定时器表。
//
// 旧实现用挂钟时间记录「上次执行时刻」，在主循环里靠 poll 超时逐个比较经过秒数：
// 时钟回拨会让定时器停摆，事件洪泛时维护任务被不断推后。本表以单调时钟为唯一时间
// 源，且 FireDue(now) 是纯函数——输入「当前时刻」返回到期集合，不读时钟、不睡眠，
// 因此可在测试里用合成时刻精确验证不漂移。周期定时器到期后按原定时刻 + 周期重排，
// 而不是「实际触发时刻 + 周期」，所以长期运行不累积漂移。
type TimerTable struct {
	slots []*timerSlot
}

// NewTimerTable 新建容量为 maxTimers 的表。
//
// 容量在构造期确定，登记满载时 Every/At 返回 ok=false（调用方决定如何处理，
// 不静默丢弃）。定时器数量在编译期可数，故用固定表而非可变长结构。
func NewTimerTable(maxTimers int) *TimerTable {
	if maxTimers < 0 {
		maxTimers = 0
	}
	return &TimerTable{slots: make([]*timerSlot, maxTimers)}
}

// Every 登记一个从 firstFire 起、每 period 触发一次的周期定时器。
//
// firstFire 显式传入（而非内部读时钟），使调用方与测试都能精确控制相位。表满时
// 返回 ok=false。
func (t *TimerTable) Every(period time.Duration, firstFire time.Time) (TimerID, bool) {
	return t.insert(&timerSlot{deadline: firstFire, period: period})
}

// At 登记一个在 deadline 触发的一次性定时器。表满时返回 ok=false。
func (t *TimerTable) At(deadline time.Time) (TimerID, bool) {
	return t.insert(&timerSlot{deadline: deadline})
}

// Cancel 取消定时器。对已取消 / 不存在的 id 调用是幂等的空操作。
func (t *TimerTable) Cancel(id TimerID) {
	if id >= 0 && int(id) < len(t.slots) {
		t.slots[id] = nil
	}
}

// NextDeadline 返回最近的下次到期时刻；无活动定时器时 ok=false。
func (t *TimerTable) NextDeadline() (time.Time, bool) {
	var best time.Time
	found := false
	for _, slot := range t.slots {
		if slot == nil {
			continue
		}
		if !found || slot.deadline.Before(best) {
			best = slot.deadline
			found = true
		}
	}
	return best, found
}

// FireDue 取出所有 deadline <= now 的定时器并推进其状态。纯函数，不读时钟。
//
//   - 一次性：从表中移除。
//   - 周期：重排到「原定时刻 + period」；若已落后超过一个周期（线程被长时间阻塞），
//     则跳到 now + period——不补发历史欠账，避免唤醒后突发一串回调。
func (t *TimerTable) FireDue(now time.Time) []Fired {
	var fired []Fired
	for i, slot := range t.slots {
		if slot == nil || slot.deadline.After(now) {
			continue
		}
		id := TimerID(i)
		if slot.period <= 0 {
			t.slots[i] = nil
			fired = append(fired, Fired{ID: id})
			continue
		}
		next := slot.deadline.Add(slot.period)
		if !next.After(now) {
			next = now.Add(slot.period)
		}
		slot.deadline = next
		fired = append(fired, Fired{ID: id, Repeating: true})
	}
	return fired
}

// insert 找到空闲槽位并写入，返回其 id；满载返回 ok=false。
func (t *TimerTable) insert(slot *timerSlot) (TimerID, bool) {
	for i, existing := range t.slots {
		if existing == nil {
			t.slots[i] = slot
			return TimerID(i), true
		}
	}
	return 0, false
}
