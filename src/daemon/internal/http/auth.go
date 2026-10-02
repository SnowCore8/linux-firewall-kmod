package http

import (
	"crypto/subtle"
	"net/http"
)

// RequireAuth 包装 handler，要求 HTTP Basic Auth 认证。
//
// username 与 password 均为空时跳过认证（未配置凭据 = 不启用认证）。
func RequireAuth(username, password string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if username == "" && password == "" {
			next(w, r)
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(u), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="firewall-daemon"`)
			WriteError(w, http.StatusUnauthorized, "unauthorized", "认证失败")
			return
		}
		next(w, r)
	}
}

// OptionalAuth 包装 handler，提取 Basic Auth 凭据但不强制要求。
//
// 凭据正确或无凭据均放行；凭据错误返回 401。用于只读端点的可选认证。
func OptionalAuth(username, password string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if username == "" && password == "" {
			next(w, r)
			return
		}
		u, p, ok := r.BasicAuth()
		if !ok {
			// 无凭据：只读端点允许匿名访问
			next(w, r)
			return
		}
		if subtle.ConstantTimeCompare([]byte(u), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="firewall-daemon"`)
			WriteError(w, http.StatusUnauthorized, "unauthorized", "认证失败")
			return
		}
		next(w, r)
	}
}
