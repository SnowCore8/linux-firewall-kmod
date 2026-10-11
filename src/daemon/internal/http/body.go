// 请求体读取：契约信封面上 415 与 422 两个状态码的唯一产点。
//
// 这两个码契约里记 shape=envelope，产点就是本文件：net/http 没有 JSON 提取器，
// 请求体能不能解析只有 daemon 自己知道，所以由本文件显式产出 415/422。
package http

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// maxRequestBodyBytes 是单个请求体的上限：1 MiB。
//
// 批量封禁最多 100 条 IP，正常载荷远小于这个数；上限存在的意义是把「有人 POST 一个
// 1 GB 的体」从内存耗尽降级成一次 422，而不是指望调用方自觉。
const maxRequestBodyBytes = 1 << 20

// decodeJSON 读取并反序列化请求体；返回 false 时响应已经写出，调用方直接 return。
//
// 两条失败分支的形状不同：
//
//   - Content-Type 声明了别的媒体类型 → 415 + 业务码 40008；
//   - 体超限、不是合法 JSON、或字段类型不符 → 422 + 业务码 40007。
//
// Content-Type **缺席**不算不符：本 API 只说 application/json 一种类型，命令行客户端不带
// 该头而发的就是 JSON，拒之门外只会把可用工具挡在外面；说了别的类型的请求照样被拒。
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if ct := r.Header.Get("Content-Type"); ct != "" && !isJSONContentType(ct) {
		WriteCode(w, httpcontract.Code40008,
			"Content-Type 必须是 application/json，实际是 "+ct)
		return false
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodyBytes+1))
	if err != nil {
		WriteCode(w, httpcontract.Code40007, "读取请求体失败: "+err.Error())
		return false
	}
	if len(raw) > maxRequestBodyBytes {
		WriteCode(w, httpcontract.Code40007, "请求体超过 1 MiB 上限")
		return false
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		WriteCode(w, httpcontract.Code40007, "请求体解析失败: "+err.Error())
		return false
	}
	return true
}

// isJSONContentType 判断 Content-Type 的媒体类型是不是 JSON（忽略参数与大小写）。
//
// 用 mime.ParseMediaType 而不是 strings.HasPrefix：`application/json; charset=utf-8` 与
// `application/json` 都得认，而 `application/jsonml` 这种前缀相同的类型不能算数。
// `+json` 后缀（如 `application/api+json`）同样是 JSON。
func isJSONContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	mediaType = strings.ToLower(mediaType)
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}
