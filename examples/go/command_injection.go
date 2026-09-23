package main

import (
	"net/http"
	"os/exec"
)

// handler runs a command from the query string (CWE-78).
func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("cmd")
	cmd := exec.Command(q)
	_ = cmd.Run()
}

// runEnv executes an environment-provided command (CWE-78).
func runEnv(name string) {
	cmd := exec.Command(name)
	_ = cmd.Run()
}
