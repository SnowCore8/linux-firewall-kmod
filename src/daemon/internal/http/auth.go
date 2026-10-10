// HTTP 认证面：契约的 auth=required / auth=none 两组在 Go 侧的唯一落点。
package http

import (
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net/http"
	"strings"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/httpcontract"
)

// authUnauthorizedBody 是契约 errmodel AUTH_UNAUTHORIZED 声明的 401 响应体原文
// （纯文本、不经信封）。逐字带尾换行，与 net/http 的纯文本写法一致。
const authUnauthorizedBody = "401 Unauthorized\n"

// RequireAuth 包装 handler，实现契约的 auth=required 组。
//
// 凭据有两种来源，值都是 Basic 凭据本体 `user:pass` 的 base64：
//
//   - `Authorization: Basic <b64>`：fetch 走这条；
//   - `?access_token=<b64>`：浏览器不允许给 EventSource 设请求头，SSE 只能走 query
//     （契约 auth.token_query）。
//
// 缺凭据或凭据不符都回 401 纯文本，且**有意不发 WWW-Authenticate**：那个头会让浏览器
// 弹原生凭据对话框，对话框挂起 fetch，用户看到的是「输错密码后按钮永久转圈」。本项目
// 用应用内登录表单、凭据由前端显式携带，严格 HTTP 语义在这里让位于可用性。
//
// 两项凭据都为空 = 未配置认证，一律放行；半配置（只填一项）按失败处理——否则一个配置
// 笔误就把整个 API 敞开了。
func RequireAuth(username, password string, next http.HandlerFunc) http.HandlerFunc {
	// 两项都空：未配置认证，原样交回 next——不套一层「永远放行」的闭包，免得装饰链
	// 上多一个看不出语义的中转。
	if username == "" && password == "" {
		return next
	}
	// 半配置（只填一项）：契约判它失败，而且是**结构性**失败——另一半是空串，任何
	// 请求都不可能同时匹配两项，所以不必等比较结果，直接拒。留在比较里靠
	// sameCredential("", "") 恰好为真来放行，等于把「密码留空」当成「密码是空串」，
	// 一个笔误就把整个 API 敞开。
	if username == "" || password == "" {
		return alwaysUnauthorized
	}
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := requestCredentials(r)
		if !ok || !sameCredential(u, username) || !sameCredential(p, password) {
			unauthorized(w)
			return
		}
		next(w, r)
	}
}

// alwaysUnauthorized 是半配置凭据下的 auth=required 面：整组端点一律 401。
func alwaysUnauthorized(w http.ResponseWriter, _ *http.Request) {
	unauthorized(w)
}

// requestCredentials 按「请求头优先、query 兜底」取出 Basic 凭据。
//
// 只做解码，不比较：比较留在 RequireAuth 里，好让常量时间比较的位置一目了然。
func requestCredentials(r *http.Request) (user, pass string, ok bool) {
	if u, p, present := r.BasicAuth(); present {
		return u, p, true
	}
	token := r.URL.Query().Get(httpcontract.AuthTokenQuery)
	if token == "" {
		return "", "", false
	}
	// 前端用 window.btoa 生成，即标准 base64（带填充）；URL 里可能出现的是被
	// 转义过的 '+' '/'，r.URL.Query() 已解过百分号，这里不再做字符替换。
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", "", false
	}
	user, pass, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	return user, pass, true
}

// sameCredential 常量时间比较单个凭据字段。
//
// 长度不同时 subtle.ConstantTimeCompare 返回 0，这里不必特判：长度本身不算秘密，
// 而把「长度相同吗」做成早退分支反而多留一条计时侧信道。
func sameCredential(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// unauthorized 写契约声明的 401 纯文本响应。
func unauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	// 体是固定字符串，写失败的只有客户端已断开这一类；无的可行动作，故忽略返回值。
	_, _ = io.WriteString(w, authUnauthorizedBody)
}
