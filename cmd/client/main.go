package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	server := flag.String("server", envOr("SERVER_URL", "http://server:8080"), "fingerprint server base URL")
	input := flag.String("input", envOr("INPUT_FILE", "/data/sample.json"), "local JSON file of scan records")
	timeout := flag.Duration("timeout", 15*time.Second, "HTTP timeout")
	flag.Parse()

	raw, err := os.ReadFile(*input)
	if err != nil {
		fatal("read input: %v", err)
	}
	if !json.Valid(raw) {
		fatal("input is not valid json: %s", *input)
	}

	url := *server + "/fingerprint"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		fatal("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: *timeout}
	resp, err := client.Do(req)
	if err != nil {
		fatal("call server %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fatal("read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		fatal("server returned %d: %s", resp.StatusCode, string(body))
	}

	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", "  "); err != nil {
		fmt.Println(string(body))
		return
	}
	fmt.Println(pretty.String())
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
