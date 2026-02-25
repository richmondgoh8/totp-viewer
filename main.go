//go:build !wasm
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
)

const (
	DefaultPort = "8080"
)

func main() {
	port := flag.String("port", DefaultPort, "Port to run the local server on")
	flag.Parse()

	// Simple static file server
	fs := http.FileServer(http.Dir("public"))
	
	// Middleware to set correct MIME type for .wasm files
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "public/index.html")
			return
		}
		fs.ServeHTTP(w, r)
	})

	fmt.Printf("🚀 TOTP Server (Wasm-powered) running at http://localhost:%s\n", *port)
	fmt.Printf("👉 Generator UI: http://localhost:%s/?secret=JBSWY3DPEHPK3PXP\n", *port)

	log.Fatal(http.ListenAndServe(":"+*port, nil))
}
