package runtime

import (
	"testing"
	"time"
)

func TestOneShotFiresOnceThenIsRemoved(t *testing.T) {
	table := NewTimerTable(4)
	t0 := time.Now()
	if _, ok := table.At(t0.Add(100 * time.Millisecond)); !ok {
		t.Fatal("登记失败")
	}

	if got := table.FireDue(t0); len(got) != 0 {
		t.Fatalf("未到期不应触发，实得 %d", len(got))
	}
	fired := table.FireDue(t0.Add(100 * time.Millisecond))
	if len(fired) != 1 {
		t.Fatalf("到期应触发一次，实得 %d", len(fired))
	}
	if fired[0].Repeating {
		t.Fatal("一次性定时器不应标记为周期")
	}
	if _, ok := table.NextDeadline(); ok {
		t.Fatal("一次性定时器触发后应被移除")
	}
	if got := table.FireDue(t0.Add(10 * time.Second)); len(got) != 0 {
		t.Fatalf("不应二次触发，实得 %d", len(got))
	}
}

func TestRepeatingTimerIsDriftFreeOverManySteps(t *testing.T) {
	table := NewTimerTable(4)
	t0 := time.Now()
	period := 100 * time.Millisecond
	if _, ok := table.Every(period, t0.Add(period)); !ok {
		t.Fatal("登记失败")
	}

	count := 0
	for k := 1; k <= 20; k++ {
		count += len(table.FireDue(t0.Add(period * time.Duration(k))))
	}
	if count != 20 {
		t.Fatalf("每步应各触发一次，实得 %d", count)
	}
	// 关键：第 21 次到期是 20*period + period，与原定序列严格对齐，无累积漂移。
	next, ok := table.NextDeadline()
	if !ok {
		t.Fatal("应有下次到期")
	}
	if want := t0.Add(period * 21); !next.Equal(want) {
		t.Fatalf("重排必须基于原定时刻 + 周期：want %v got %v", want, next)
	}
}

func TestLateWakeupDoesNotBurst(t *testing.T) {
	table := NewTimerTable(4)
	t0 := time.Now()
	period := 1 * time.Second
	if _, ok := table.Every(period, t0.Add(period)); !ok {
		t.Fatal("登记失败")
	}

	// 线程被阻塞了 5 个周期以上才醒来：只触发一次，不补发欠账。
	now := t0.Add(5*time.Second + 100*time.Millisecond)
	fired := table.FireDue(now)
	if len(fired) != 1 {
		t.Fatalf("落后时不应突发补发，实得 %d", len(fired))
	}
	next, ok := table.NextDeadline()
	if !ok {
		t.Fatal("周期定时器应仍存在")
	}
	if !next.After(now) {
		t.Fatalf("下次到期应在当前时刻之后：%v", next)
	}
	if next.After(now.Add(period)) {
		t.Fatalf("下次到期应在一个周期内：%v", next)
	}
}

func TestCancelIsIdempotentAndFreesTheSlot(t *testing.T) {
	table := NewTimerTable(1)
	t0 := time.Now()
	id, ok := table.At(t0.Add(time.Second))
	if !ok {
		t.Fatal("登记失败")
	}
	if _, ok := table.At(t0); ok {
		t.Fatal("容量为 1 时第二次登记应失败")
	}

	table.Cancel(id)
	table.Cancel(id) // 幂等
	if _, ok := table.NextDeadline(); ok {
		t.Fatal("取消后应无活动定时器")
	}
	if _, ok := table.At(t0.Add(2 * time.Second)); !ok {
		t.Fatal("取消后应释放槽位")
	}
}

func TestMultipleTimersFireByDeadlineOrder(t *testing.T) {
	table := NewTimerTable(4)
	t0 := time.Now()
	late, ok := table.At(t0.Add(10 * time.Second))
	if !ok {
		t.Fatal("登记 late 失败")
	}
	early, ok := table.At(t0.Add(time.Second))
	if !ok {
		t.Fatal("登记 early 失败")
	}

	fired := table.FireDue(t0.Add(time.Second))
	if len(fired) != 1 || fired[0].ID != early || fired[0].Repeating {
		t.Fatalf("应只触发 early，实得 %+v", fired)
	}
	next, ok := table.NextDeadline()
	if !ok || !next.Equal(t0.Add(10*time.Second)) {
		t.Fatalf("下次到期应为 late，实得 %v", next)
	}
	_ = late
}

func TestTableFullReportsFailure(t *testing.T) {
	table := NewTimerTable(1)
	t0 := time.Now()
	if _, ok := table.At(t0); !ok {
		t.Fatal("首个登记应成功")
	}
	if _, ok := table.At(t0); ok {
		t.Fatal("满载时应如实返回失败而非静默丢弃")
	}
}
