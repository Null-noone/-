package fingerprint

import (
	"path/filepath"
	"runtime"
	"testing"
)

func rulesDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "rules")
}

func TestSampleDepth(t *testing.T) {
	rules, err := LoadRulesDir(rulesDir(t))
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(rules)

	cases := []struct {
		in       Input
		protocol string
		product  string
		version  string
		os       string
	}{
		{Input{"1.2.3.4", 22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}, "SSH", "OpenSSH", "8.9p1", "Ubuntu"},
		{Input{"1.2.3.5", 80, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"}, "HTTP", "nginx", "1.24.0", ""},
		{Input{"1.2.3.6", 443, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"}, "HTTP", "Apache", "2.4.57", ""},
		{Input{"1.2.3.7", 3306, `J\x00\x00\x00\n8.0.32\x00`}, "MySQL", "MySQL", "8.0.32", ""},
		{Input{"1.2.3.8", 6379, "-ERR wrong number of arguments for 'get' command"}, "Redis", "Redis", "", ""},
		{Input{"1.2.3.9", 21, "220 ProFTPD 1.3.7 Server (ProFTPD)"}, "FTP", "ProFTPD", "1.3.7", ""},
		{Input{"1.2.3.10", 8080, "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"}, "HTTP", "Jetty", "9.4.51", ""},
		{Input{"1.2.3.23", 12345, "QUIT\r\n"}, "unknown", "", "", ""},
		{Input{"1.2.3.19", 9999, "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"}, "TLS", "", "", ""},
		{Input{"10.4.0.1", 25, "220 mail.example.com ESMTP Postfix"}, "SMTP", "Postfix", "", ""},
		{Input{"10.6.0.1", 5432, `FATAL:  password authentication failed for user "postgres"`}, "PostgreSQL", "PostgreSQL", "", ""},
		{Input{"9.9.9.1", 25, "220 mail.example.com"}, "SMTP", "", "", ""},
		{Input{"9.9.9.2", 6379, "-LOADING Redis is loading the dataset in memory"}, "Redis", "Redis", "", ""},
		{Input{"9.9.9.3", 80, "HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.1.27"}, "HTTP", "PHP", "8.1.27", ""},
	}

	for _, tc := range cases {
		got := eng.Identify(tc.in)
		if got.Protocol != tc.protocol {
			t.Errorf("%s:%d protocol=%q want %q", tc.in.IP, tc.in.Port, got.Protocol, tc.protocol)
		}
		if tc.product != "" && got.Product != tc.product {
			t.Errorf("%s:%d product=%q want %q", tc.in.IP, tc.in.Port, got.Product, tc.product)
		}
		if tc.version != "" && got.Version != tc.version {
			t.Errorf("%s:%d version=%q want %q", tc.in.IP, tc.in.Port, got.Version, tc.version)
		}
		if tc.os != "" && got.OSHint != tc.os {
			t.Errorf("%s:%d os_hint=%q want %q", tc.in.IP, tc.in.Port, got.OSHint, tc.os)
		}
	}
}

func TestFalsePositives(t *testing.T) {
	rules, err := LoadRulesDir(rulesDir(t))
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine(rules)
	cases := []Input{
		{IP: "1.1.1.1", Port: 8080, Banner: "app log FATAL: disk full"},
		{IP: "1.1.1.2", Port: 80, Banner: "user said PRIVMSG in chat log"},
	}
	for _, in := range cases {
		got := eng.Identify(in)
		if got.Protocol == "PostgreSQL" || got.Protocol == "IRC" {
			t.Errorf("%q => %s (false positive)", in.Banner, got.Protocol)
		}
	}
}

func TestNeverPanics(t *testing.T) {
	eng := NewEngine(nil)
	got := eng.Identify(Input{Banner: string([]byte{0xff, 0xfe})})
	if got.Protocol != "unknown" {
		t.Fatalf("empty engine should return unknown, got %s", got.Protocol)
	}
}
