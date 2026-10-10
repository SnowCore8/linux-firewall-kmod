// 偏离计算的两条形状约束：名字表与列下标的对应，以及样本护栏的「没有基线」形状。
//
// 这里不测分位数本身的数值（那是 percentile 的内部事），测的是**读侧会画错的东西**：
// 维度名与列下标一旦错位，面板就把 bps 当成 pps 比分位——数值全对，结论全错。
package analysis

import "testing"

// TestDeviateNamesColumnsByNameTable 要求逐维结果按 Names 的顺序给名字。
//
// 每列取一个互不相同的值，最后一行只在其中一列上突出：这样「哪一维得了满分」是可判定的，
// 而名字错位会让它落在别的维度上。
func TestDeviateNamesColumnsByNameTable(t *testing.T) {
	names := []string{"a", "b", "c", "d"}
	rows := [][]float64{
		{1, 2, 3, 4},
		{1, 2, 3, 4},
		{1, 2, 3, 4},
		{1, 2, 900, 4},
	}
	report := Deviate(FeatureMatrix{Names: names, Rows: rows}, 3)
	if !report.Ok {
		t.Fatal("行数已达护栏却报 Ok=false")
	}

	for i, want := range names {
		if got := report.Dimensions[i].Name; got != want {
			t.Errorf("第 %d 维的名字 = %q，期望 %q（名字表与列下标错位）", i, got, want)
		}
	}
	if got := report.Dimensions[2].Score; got != 1 {
		t.Errorf("突出那一列（下标 2）的偏差分 = %v，期望满分 1", got)
	}
	for i, want := range []float64{0, 0, 1, 0} {
		if got := report.Dimensions[i].Score; got != want {
			t.Errorf("第 %d 维偏差分 = %v，期望 %v", i, got, want)
		}
	}

	// 三条基线共用同一张名字表，读侧才能把它们并排画。
	for _, tc := range []struct {
		name string
		got  []Feature
	}{
		{"Current", report.Current},
		{"BaselineP50", report.BaselineP50},
		{"BaselineP95", report.BaselineP95},
	} {
		if len(tc.got) != len(names) {
			t.Fatalf("%s 长度 = %d，期望 %d", tc.name, len(tc.got), len(names))
		}
		for i, f := range tc.got {
			if f.Name != names[i] {
				t.Errorf("%s 第 %d 项名字 = %q，期望 %q", tc.name, i, f.Name, names[i])
			}
		}
	}
	// Current 必须是**最后一行**：把第一行当当前值会让面板在整段历史平稳、刚刚才突发时
	// 报「一切正常」。
	if report.Current[len(names)-1].Value != 4 || report.Current[2].Value != 900 {
		t.Errorf("Current 不是最后一行：%v", report.Current)
	}
}

// TestDeviateBelowGuardCarriesNoBaseline 核对护栏未达时的形状：Ok=false、Samples 如实，
// 基线与维度表都不给——读侧据此把「没有基线」原样传出去，而不是把零当成读数。
func TestDeviateBelowGuardCarriesNoBaseline(t *testing.T) {
	report := Deviate(FeatureMatrix{
		Names: []string{"a", "b"},
		Rows:  [][]float64{{1, 1}, {2, 2}},
	}, MinGlobalSamples)

	if report.Ok {
		t.Fatal("2 行未达护栏却报 Ok=true")
	}
	if report.Samples != 2 {
		t.Errorf("Samples = %d，期望如实报 2（读侧要能区分「没数据」与「数据为 0」）", report.Samples)
	}
	if len(report.BaselineP50)+len(report.BaselineP95)+len(report.Dimensions)+len(report.Rows) != 0 {
		t.Errorf("护栏未达却给出了基线或维度分：%+v", report)
	}
	if report.Current != nil {
		t.Errorf("护栏未达却给出了当前值：%v", report.Current)
	}
}

// TestDeviateZeroSpreadFlagsAnyMove 核对全等列的不除零分支：一列绝大多数样本全等
// （p95 与 p50 重合、spread 为 0）时，任何超过 p95 的值记满分，等于或低于记 0 分。
//
// 样本数要够大才走得进这条分支：四五个点时 p95 就是最大值本身，spread 从来不为 0。
func TestDeviateZeroSpreadFlagsAnyMove(t *testing.T) {
	same := make([][]float64, 0, 20)
	for i := 0; i < 19; i++ {
		same = append(same, []float64{5})
	}
	moving := append(append([][]float64(nil), same...), []float64{6})

	report := Deviate(FeatureMatrix{Names: []string{"x"}, Rows: moving}, 3)
	if got := report.BaselineP95[0].Value; got != 5 {
		t.Fatalf("构造没造出零 spread：%v", report.BaselineP95)
	}
	if got := report.Dimensions[0].Score; got != 1 {
		t.Errorf("全等列上出现更大值的偏差分 = %v，期望 1（spread 为 0 不能退化成 0）", got)
	}

	below := Deviate(FeatureMatrix{Names: []string{"x"}, Rows: same}, 3)
	if got := below.Dimensions[0].Score; got != 0 {
		t.Errorf("全等列没有任何移动的偏差分 = %v，期望 0", got)
	}
}

// TestDeviateShortRowScoresMissingColumnAsZero 核对缺列不拖垮整份报告。
func TestDeviateShortRowScoresMissingColumnAsZero(t *testing.T) {
	report := Deviate(FeatureMatrix{
		Names: []string{"a", "b", "c"},
		Rows: [][]float64{
			{1, 1, 1},
			{2, 2, 2},
			{3, 3}, // 产出方漏了最后一维
		},
	}, 3)
	if !report.Ok {
		t.Fatal("行数达标却没出报告")
	}
	if got := report.Current[2].Value; got != 0 {
		t.Errorf("缺列的当前值 = %v，期望按 0 记", got)
	}
	if len(report.Dimensions) != 3 {
		t.Errorf("维度数 = %d，期望仍是 3（缺列只影响那一维的分）", len(report.Dimensions))
	}
}
