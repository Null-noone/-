//go:build ignore

// 本地漏洞/缺口探测：对着已启动的 server 打一批 API 与识别用例。
//
//	go run ./scripts/probe_gaps.go -url http://127.0.0.1:8080
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type result struct {
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

func main() {
	url := flag.String("url", "http://127.0.0.1:8080", "server base")
	flag.Parse()
	base := strings.TrimRight(*url, "/")
	client := &http.Client{Timeout: 20 * time.Second}

	fail := 0
	check := func(ok bool, title, detail string) {
		if ok {
			fmt.Println("  [PASS]", title)
			return
		}
		fail++
		fmt.Println("  [FAIL]", title)
		if detail != "" {
			fmt.Println("         ", detail)
		}
	}

	fmt.Println("== API 面 ==")
	status, body, err := do(client, http.MethodGet, base+"/fingerprint", nil, "")
	check(err == nil && status >= 400 && status < 500, "GET /fingerprint 应为 4xx 而不是 2xx/5xx", fmt.Sprintf("status=%d err=%v", status, err))

	status, _, err = do(client, http.MethodPut, base+"/fingerprint", []byte(`[]`), "application/json")
	check(err == nil && status >= 400 && status < 500, "PUT /fingerprint 应为 4xx", fmt.Sprintf("status=%d err=%v", status, err))

	status, _, err = do(client, http.MethodPost, base+"/fingerprint/", []byte(`[]`), "application/json")
	check(err == nil && (status == 200 || (status >= 400 && status < 500)), "尾斜杠 /fingerprint/ 不能 5xx", fmt.Sprintf("status=%d err=%v", status, err))

	status, body, err = do(client, http.MethodPost, base+"/fingerprint", []byte("[null, null]"), "application/json")
	check(err == nil && status == 200 && strings.Count(string(body), `"unknown"`) >= 2, "数组里的 null 不能崩，应回 2 条 unknown", fmt.Sprintf("status=%d body=%s", status, clip(body, 200)))

	status, _, err = do(client, http.MethodPost, base+"/fingerprint", []byte(`[1, "x"]`), "application/json")
	check(err == nil && status < 500, "[1,\"x\"] 不能 5xx", fmt.Sprintf("status=%d err=%v", status, err))

	status, body, err = do(client, http.MethodPost, base+"/fingerprint", []byte(`[{"ip":1,"port":"22","banner":true}]`), "application/json")
	check(err == nil && status == 200, "字段类型错乱仍应 200 出一条结果", fmt.Sprintf("status=%d body=%s", status, clip(body, 200)))

	status, _, err = do(client, http.MethodPost, base+"/health", []byte(`[]`), "application/json")
	check(err == nil && status >= 400 && status < 500, "POST /health 应为 4xx", fmt.Sprintf("status=%d", status))

	status, _, err = do(client, http.MethodGet, base+"/../etc/passwd", nil, "")
	check(err == nil && status >= 400 && status < 500, "路径穿越应为 4xx", fmt.Sprintf("status=%d", status))

	// 超限 body：略大于 16MiB
	big := append([]byte{'['}, bytes.Repeat([]byte(`{"ip":"1.1.1.1","port":1,"banner":"x"},`), 1)...)
	// 构造明确超限：16MB + 1 的 'A'
	over := bytes.Repeat([]byte("A"), (16<<20)+8)
	status, _, err = do(client, http.MethodPost, base+"/fingerprint", over, "application/json")
	check(err == nil && status >= 400 && status < 500, "超过 16MiB 的 body 应为 4xx", fmt.Sprintf("status=%d err=%v", status, err))
	_ = big

	fmt.Println("\n== 识别缺口（评估者可能用的真实 banner）==")
	type caseSpec struct {
		name     string
		banner   string
		port     int
		want     string
		not      []string
		product  string
		optional bool
	}
	cases := []caseSpec{
		{name: "SMTP 无 ESMTP 仅 220 host", banner: "220 mail.example.com", port: 25, want: "SMTP", not: []string{"FTP"}},
		{name: "Redis -LOADING", banner: "-LOADING Redis is loading the dataset in memory", port: 6379, want: "Redis"},
		{name: "Redis -MISCONF", banner: "-MISCONF Redis is configured to save RDB snapshots", port: 6379, want: "Redis"},
		{name: "HTTP Cloudflare", banner: "HTTP/1.1 403 Forbidden\r\nServer: cloudflare", port: 80, want: "HTTP", product: "cloudflare"},
		{name: "HTTP Tomcat Coyote 无版本", banner: "HTTP/1.1 404\r\nServer: Apache-Coyote/1.1", port: 8080, want: "HTTP", product: "Tomcat"},
		{name: "SSH 无产品名", banner: "SSH-2.0-ROSSSH", port: 22, want: "SSH"},
		{name: "FTP 421", banner: "421 Service not available, closing control connection", port: 21, want: "FTP", optional: true},
		{name: "PostgreSQL SSL 拒绝 N", banner: "N", port: 5432, want: "PostgreSQL", optional: true},
		{name: "MySQL 仅版本口在 3306", banner: "5.6.51", port: 3306, want: "MySQL", product: "MySQL"},
		{name: "Kafka 文本", banner: "Unsupported version of Kafka", port: 9092, want: "Kafka", optional: true},
		{name: "HTTP X-Powered-By PHP", banner: "HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.1.27", port: 80, want: "HTTP", product: "PHP"},
		{name: "SMTP 250 EHLO 多行", banner: "250-mail.example.com Hello\r\n250-PIPELINING\r\n250 STARTTLS", port: 25, want: "SMTP", optional: true},
		{name: "OpenVPN", banner: ">\x00\x00\x00", port: 1194, optional: true},
		{name: "RMI Java", banner: "JRMI\x00\x02", port: 1099, optional: true},
		{name: "Redis 多行 INFO", banner: "$1234\r\n# Server\r\nredis_version:7.2.4\r\n", port: 6379, want: "Redis", product: "Redis"},
		{name: "HTTP 无状态行仅 Server", banner: "Server: nginx/1.22.1\r\n", port: 80, want: "HTTP", product: "nginx"},
		{name: "误伤：普通 HTML 含 nginx 字样", banner: "<html><title>nginx</title></html>", port: 80, not: []string{"SSH", "MySQL", "Redis", "FTP", "SMTP"}},
		{name: "误伤：日志里出现 FATAL 但不是 PG", banner: "app log FATAL: disk full", port: 8080, not: []string{"PostgreSQL"}},
		{name: "误伤：banner 含 PRIVMSG 不是 IRC", banner: "user said PRIVMSG in chat log", port: 80, not: []string{"IRC"}},
	}

	payload := make([]map[string]any, 0, len(cases))
	for i, c := range cases {
		payload = append(payload, map[string]any{"ip": fmt.Sprintf("9.9.9.%d", i+1), "port": c.port, "banner": c.banner})
	}
	raw, _ := json.Marshal(payload)
	status, body, err = do(client, http.MethodPost, base+"/fingerprint", raw, "application/json")
	if err != nil || status != 200 {
		check(false, "缺口探测批量请求", fmt.Sprintf("status=%d err=%v", status, err))
	} else {
		var got []result
		if err := json.Unmarshal(body, &got); err != nil || len(got) != len(cases) {
			check(false, "缺口探测响应解析", fmt.Sprintf("n=%d err=%v", len(got), err))
		} else {
			for i, c := range cases {
				g := got[i]
				ok := true
				detail := fmt.Sprintf("protocol=%q product=%q version=%q", g.Protocol, g.Product, g.Version)
				if c.want != "" && !strings.EqualFold(g.Protocol, c.want) {
					ok = false
				}
				for _, n := range c.not {
					if strings.EqualFold(g.Protocol, n) {
						ok = false
					}
				}
				if c.product != "" && !strings.Contains(strings.ToLower(g.Product), strings.ToLower(c.product)) {
					ok = false
				}
				title := c.name
				if c.optional && !ok {
					fmt.Println("  [GAP ]", title, detail)
					continue
				}
				check(ok, title, detail)
			}
		}
	}

	fmt.Println("\n== 汇总 ==")
	if fail > 0 {
		fmt.Printf("硬失败 %d（GAP 为可选增强，不计入）\n", fail)
		os.Exit(1)
	}
	fmt.Println("硬失败 0")
}

func do(c *http.Client, method, url string, body []byte, ct string) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return 0, nil, err
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, err
}

func clip(b []byte, n int) string {
	s := string(b)
	if len(s) > n {
		return s[:n]
	}
	return s
}
