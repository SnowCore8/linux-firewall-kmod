// Package static embeds the frontend build artifacts for the Go daemon.
package static

import (
	"embed"
	"io/fs"
)

//go:embed *
var assets embed.FS

// PanelDir is a marker indicating the embedded panel directory is present.
var PanelDir = "embedded"

// StaticFS returns the embedded filesystem for serving static assets.
func StaticFS() fs.FS {
	fsys, err := fs.Sub(assets, ".")
	if err != nil {
		panic(err)
	}
	return fsys
}
