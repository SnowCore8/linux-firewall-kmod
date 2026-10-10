// 分析直方图的桶标签：与内核侧的标签表逐字一致，由测试核对。
//
// netlink 的 AnalysisResponse 只带**计数**（pkt_sizes[5] / ttl_dist[6]），桶的含义由内核
// 的采集代码决定；procfs 的 pkt_sizes / ttl_dist 两个文本文件打印同一批桶时用的就是
// fw_procfs.c 里那两张标签表。这里再抄一份是为了让 HTTP 载荷能带上人类可读的标签
// （契约的 PacketSizeDistributionResponse.labels 与 counts 按下标对齐），而
// analysis_labels_test.go 会把这张表与内核源里的字符串字面量逐格比对——分桶边界一改，
// 忘记同步标签不会静默画出一张错名的图。
package contract

// AnalysisPktSizeLabels 是包大小分桶标签，下标与 AnalysisResponse.PktSizes 一致。
var AnalysisPktSizeLabels = [AnalysisPktSizeBins]string{
	"<64B", "64-256B", "256B-1KB", "1-1.5KB", ">1.5KB",
}

// AnalysisTTLLabels 是 TTL 分桶标签，下标与 AnalysisResponse.TTLDist 一致。
var AnalysisTTLLabels = [AnalysisTTLBins]string{
	"=1", "2-32", "33-64", "65-128", "129-192", "193-255",
}
