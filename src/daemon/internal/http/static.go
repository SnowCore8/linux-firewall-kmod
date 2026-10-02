package http

import (
	"io/fs"
	"net/http"
)

func (s *Server) RegisterStaticFiles(fsys fs.FS) {
	fileServer := http.FileServer(http.FS(fsys))
	s.Handle("/static/", http.StripPrefix("/static/", fileServer))
	s.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		indexFile, err := fs.ReadFile(fsys, "index.html")
		if err != nil {
			http.Error(w, "index.html not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexFile)
	})
	s.HandleFunc("/sw.js", func(w http.ResponseWriter, r *http.Request) {
		swFile, err := fs.ReadFile(fsys, "sw.js")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Service-Worker-Allowed", "/")
		w.Write(swFile)
	})
	s.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		manifestFile, err := fs.ReadFile(fsys, "manifest.json")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(manifestFile)
	})
}
