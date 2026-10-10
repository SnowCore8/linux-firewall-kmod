// 统一信封：契约 envelope 段与 codes 段在 Go 侧的唯一写出点。
//
// 三条规矩都来自契约，不是风格选择：key 顺序 code, data, message；成功时 message 是
// 空串；失败时 data 必须**存在**且为 null。三条都靠 struct tag 与字段顺序保证，所以
// 本文件里的字面量少一处，门禁就红一处——不要在别处再拼一份 map 当信封。
package http

import (
	"encoding/json"
	"net/http"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// Envelope 是线上 JSON 的形状（前端 ApiResponse<T>）。
//
// 三个字段都不带 omitempty：契约禁止「为空则省略」这类序列化开关。data 的 Go 类型是
// json.RawMessage 而不是 any——成功路径要原样转发已经算好的载荷，失败路径要写出台面
// 上的 null，两者都不该经过第二次编码；而 nil RawMessage 由 encoding/json 序列化成
// `null`，正好是契约要的「存在且为 null」，不需要额外造一个指针。
type Envelope struct {
	Code    int             `json:"code"`
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message"`
}

// SuccessEnvelope 装配成功响应：code 0、message 空串、data 是载荷本体。
//
// 载荷序列化失败不在这里升级成错误：能进信封的载荷全是 struct/map，序列化失败意味着
// 有人往载荷里塞了 channel 或 func——那是编译期之后、上线之前就该被用例抓住的装配错误，
// 在写响应的最后一刻把它压成一条 500 反而藏住了现场。
func SuccessEnvelope(data any) Envelope {
	raw, _ := json.Marshal(data)
	return Envelope{
		Code:    httpcontract.CodeOK,
		Data:    raw,
		Message: "",
	}
}

// ErrorEnvelope 装配失败响应：code 是契约声明的业务码，data 恒为 null。
//
// code 不再是 -1：契约的 codes 段给每个失败都编了号，前端按号区分「同一 HTTP 状态码的
// 不同原因」（400 可能是 40001 封禁失败，也可能是 40005 批量参数非法），-1 把所有信息
// 压成一句 message，等于宣布业务码不存在。
func ErrorEnvelope(code int, message string) Envelope {
	return Envelope{
		Code:    code,
		Data:    nil,
		Message: message,
	}
}

// WriteSuccess 写出 200 与成功信封。
func WriteSuccess(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, SuccessEnvelope(data))
}

// WriteCreated 写出 201 与成功信封。
//
// 契约给 POST /api/v1/bans 与 POST /api/v1/bans/batch 写的都是 `status = 201`
// （`alt_status = 200` 留给「幂等重试时资源早已存在」这类分支，不是实现可以随手挑的
// 第二个偏好）：新建资源用 201，前端与 curl 都按这个区分「创建成功」与「查到一个列表」。
func WriteCreated(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusCreated, SuccessEnvelope(data))
}

// WriteCode 按业务码写出失败信封，HTTP 状态码由码查生成物表得到。
//
// 调用处不再手写状态码：契约里 `code 40001 { status = 400 }` 已经把两者的对应关系钉死，
// 每一处再填一个数字迟早与它分叉（旧形态正是这样——Code 恒置 -1、状态码各处手写，于是
// 契约声明的业务码在 Go 侧从未产出）。
//
// 码不在表里时回 500 而不是 200：传进一个契约没声明的数字是缺陷，应当显眼地失败。
func WriteCode(w http.ResponseWriter, code int, message string) {
	status, ok := httpcontract.CodeHTTPStatus[code]
	if !ok {
		status = http.StatusInternalServerError
	}
	writeJSON(w, status, ErrorEnvelope(code, message))
}

// WriteInternalError 写出 500 + 业务码 50002。
func WriteInternalError(w http.ResponseWriter, message string) {
	WriteCode(w, httpcontract.Code50002, message)
}

// WriteServiceUnavailable 写出 503 + 业务码 50003（依赖未就绪）。
//
// 「未就绪」与「出错」是两件事：历史库没开起来、日志文件没配置、jail 控制器缺席、SSE
// 名额已满，客户端换个时间再来可能就成了，而 500 会让它直接放弃或报警。
func WriteServiceUnavailable(w http.ResponseWriter, message string) {
	WriteCode(w, httpcontract.Code50003, message)
}
