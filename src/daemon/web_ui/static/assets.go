// Package webuiassets 是前端静态面板的嵌入清单：把整个 static 目录（HTML + CSS +
// JS + icons）作为 embed.FS 提供，供守护进程随二进制携带并对外提供 /static/*path。
//
// 本包不是 main，不参与 go build ./... 的二进制产出；go:embed "." 只读取同目录
// 的文件（index.html / app.js / style.css / sw.js / manifest.webmanifest /
// earth-night.webp / icons/）。该文件本身位于构建产物目录内（gitignored），
// 由 make frontend / vite build 的输出路径自然生成，不手工维护。
package webuiassets

import (
	"embed"
	"io/fs"
)

// PanelDir 是本目录自身的路径；启动期用它校验面板资源是否随构建存在。
var PanelDir string

//go:embed *
var staticFS embed.FS

func StaticFS() fs.FS {
	sub, _ := fs.Sub(staticFS, ".")
	return sub
}

// List 按固定顺序给出对外提供的静态资源，便于守护进程与前端契约核对；
// index.html 是页面外壳，其余按 /static/<name> 路由提供。
func Files() []string {
	return []string{"index.html", "app.js", "style.css", "sw.js", "manifest.webmanifest", "earth-night.webp"}
}

var _ = Files
