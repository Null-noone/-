// Banner 指纹识别系统 — 边界值 / 特殊情况测试脚本
//
// 覆盖：
//
//	A. 基础协议变体（SSH/HTTP/MySQL/Redis/FTP 的大小写、空白、非标准端口、版本格式）
//	B. 空值 / 缺字段 / 非法 IP·端口（认不出返回 unknown，禁止崩溃）
//	C. 二进制、转义、超长、注入类 banner
//	D. 易混淆协议（SMTP 220 vs FTP、TLS、QUIT）
//	E. API 契约（空数组、非法 JSON、超大批次、响应 schema）
//	F. 扩展应用层协议（SMTP/POP3/IMAP、PostgreSQL、MongoDB、Memcached、
//	   MSSQL/Oracle、ES/CouchDB、Telnet/RDP/VNC、MQTT/AMQP、LDAP/SIP/RTSP、
//	   SMB/Rsync/ZooKeeper、Docker/K8s/etcd、NNTP/IRC/XMPP 等）
//	G. 扩展协议变体与交叉误判（+OK、SIP vs HTTP、NNTP 200 vs HTTP 200 等）
//
// 用法：
//
//	go run ./scripts/test_edge_cases.go
//	go run ./scripts/test_edge_cases.go -url http://127.0.0.1:8080
//	go run ./scripts/test_edge_cases.go -dump testdata/edge_cases.json
//	go run ./scripts/test_edge_cases.go -offline
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type inputItem map[string]any

type expectSpec struct {
	Protocol      string
	ProtocolIn    []string
	ProtocolNotIn []string
	Product       string
	ProductIn     []string
	Version       string
	OSHint        string
}

type identifyCase struct {
	ID     string
	Group  string
	Name   string
	Input  inputItem
	Expect expectSpec
}

var identifyCases = []identifyCase{
	// ---------- A. 必识别协议变体 ----------
	{
		ID: "ssh-ubuntu-standard", Group: "A-必识别变体", Name: "SSH OpenSSH + Ubuntu 发行版后缀",
		Input:  inputItem{"ip": "10.1.0.1", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
		Expect: expectSpec{Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu"},
	},
	{
		ID: "ssh-debian", Group: "A-必识别变体", Name: "SSH OpenSSH + Debian",
		Input:  inputItem{"ip": "10.1.0.2", "port": 22, "banner": "SSH-2.0-OpenSSH_9.3 Debian-1"},
		Expect: expectSpec{Protocol: "SSH", Product: "OpenSSH", Version: "9.3", OSHint: "Debian"},
	},
	{
		ID: "ssh-legacy-1.99", Group: "A-必识别变体", Name: "SSH-1.99 老协议标识",
		Input:  inputItem{"ip": "10.1.0.3", "port": 22, "banner": "SSH-1.99-OpenSSH_4.3"},
		Expect: expectSpec{Protocol: "SSH", Product: "OpenSSH", Version: "4.3"},
	},
	{
		ID: "ssh-lowercase", Group: "A-必识别变体", Name: "SSH banner 全小写",
		Input:  inputItem{"ip": "10.1.0.4", "port": 22, "banner": "ssh-2.0-openssh_8.2p1"},
		Expect: expectSpec{Protocol: "SSH", Product: "OpenSSH", Version: "8.2p1"},
	},
	{
		ID: "ssh-extra-spaces", Group: "A-必识别变体", Name: "SSH banner 多余空白 / 回车",
		Input:  inputItem{"ip": "10.1.0.5", "port": 22, "banner": "  SSH-2.0-OpenSSH_8.9p1 Ubuntu-3  \r\n"},
		Expect: expectSpec{Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu"},
	},
	{
		ID: "ssh-nonstandard-port", Group: "A-必识别变体", Name: "SSH 开在 2222，端口不能压过 banner",
		Input:  inputItem{"ip": "10.1.0.6", "port": 2222, "banner": "SSH-2.0-OpenSSH_8.0"},
		Expect: expectSpec{Protocol: "SSH", Product: "OpenSSH", Version: "8.0"},
	},
	{
		ID: "http-nginx-crlf", Group: "A-必识别变体", Name: "HTTP nginx 标准 Server 头",
		Input:  inputItem{"ip": "10.1.0.7", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"},
		Expect: expectSpec{Protocol: "HTTP", Product: "nginx", Version: "1.24.0"},
	},
	{
		ID: "http-nginx-ubuntu-paren", Group: "A-必识别变体", Name: "HTTP nginx 版本后带 (Ubuntu)",
		Input:  inputItem{"ip": "10.1.0.8", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)"},
		Expect: expectSpec{Protocol: "HTTP", Product: "nginx", Version: "1.18.0", OSHint: "Ubuntu"},
	},
	{
		ID: "http-nginx-no-space", Group: "A-必识别变体", Name: "Server 头无空格 / 小写",
		Input:  inputItem{"ip": "10.1.0.9", "port": 8443, "banner": "HTTP/1.1 200 OK\r\nserver:nginx/1.25.3"},
		Expect: expectSpec{Protocol: "HTTP", Product: "nginx", Version: "1.25.3"},
	},
	{
		ID: "http-apache-modules", Group: "A-必识别变体", Name: "Apache 版本后跟模块串",
		Input:  inputItem{"ip": "10.1.0.10", "port": 443, "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Unix) OpenSSL/1.1.1 PHP/8.1.0"},
		Expect: expectSpec{Protocol: "HTTP", Product: "Apache", Version: "2.4.57"},
	},
	{
		ID: "http-apache-ubuntu", Group: "A-必识别变体", Name: "Apache + Ubuntu",
		Input:  inputItem{"ip": "10.1.0.11", "port": 443, "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)"},
		Expect: expectSpec{Protocol: "HTTP", Product: "Apache", Version: "2.4.41", OSHint: "Ubuntu"},
	},
	{
		ID: "http-jetty-slash", Group: "A-必识别变体", Name: "Jetty 斜杠版本",
		Input:  inputItem{"ip": "10.1.0.12", "port": 8080, "banner": "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"},
		Expect: expectSpec{Protocol: "HTTP", Product: "Jetty", Version: "9.4.51"},
	},
	{
		ID: "http-jetty-paren-build", Group: "A-必识别变体", Name: "Jetty 官方括号+构建号格式",
		Input:  inputItem{"ip": "10.1.0.13", "port": 8080, "banner": "HTTP/1.1 200 OK\r\nServer: Jetty(9.4.51.v20230217)"},
		Expect: expectSpec{Protocol: "HTTP", Product: "Jetty", Version: "9.4.51"},
	},
	{
		ID: "http-iis", Group: "A-必识别变体", Name: "Microsoft-IIS（HTTP 家族）",
		Input:  inputItem{"ip": "10.1.0.14", "port": 8888, "banner": "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0"},
		Expect: expectSpec{Protocol: "HTTP", Product: "IIS", Version: "10.0"},
	},
	{
		ID: "http-no-server-header", Group: "A-必识别变体", Name: "HTTP 状态行在，但没有 Server 头",
		Input:  inputItem{"ip": "10.1.0.15", "port": 80, "banner": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"},
		Expect: expectSpec{Protocol: "HTTP"},
	},
	{
		ID: "http-http10", Group: "A-必识别变体", Name: "HTTP/1.0",
		Input:  inputItem{"ip": "10.1.0.16", "port": 80, "banner": "HTTP/1.0 200 OK\r\nServer: nginx/1.14.0"},
		Expect: expectSpec{Protocol: "HTTP", Product: "nginx", Version: "1.14.0"},
	},
	{
		ID: "mysql-escaped-8032", Group: "A-必识别变体", Name: "MySQL handshake 字面 \\x00 转义（扫描器常见）",
		Input:  inputItem{"ip": "10.1.0.17", "port": 3306, "banner": `J\x00\x00\x00\n8.0.32\x00`},
		Expect: expectSpec{Protocol: "MySQL", Product: "MySQL", Version: "8.0.32"},
	},
	{
		ID: "mysql-escaped-5742", Group: "A-必识别变体", Name: "MySQL 5.7 字面转义",
		Input:  inputItem{"ip": "10.1.0.18", "port": 3306, "banner": `J\x00\x00\x00\n5.7.42\x00`},
		Expect: expectSpec{Protocol: "MySQL", Product: "MySQL", Version: "5.7.42"},
	},
	{
		ID: "mysql-real-nulls", Group: "A-必识别变体", Name: "MySQL handshake 真实 NUL 字节",
		Input:  inputItem{"ip": "10.1.0.19", "port": 3306, "banner": "J\x00\x00\x00\n8.0.36\x00"},
		Expect: expectSpec{Protocol: "MySQL", Product: "MySQL", Version: "8.0.36"},
	},
	{
		ID: "mysql-mariadb", Group: "A-必识别变体", Name: "MariaDB 伪装 MySQL 版本前缀 5.5.5-",
		Input:  inputItem{"ip": "10.1.0.20", "port": 3306, "banner": `J\x00\x00\x00\n5.5.5-10.6.12-MariaDB\x00`},
		Expect: expectSpec{Protocol: "MySQL", Version: "10.6.12"},
	},
	{
		ID: "redis-err-arity", Group: "A-必识别变体", Name: "Redis -ERR 参数个数错误",
		Input:  inputItem{"ip": "10.1.0.21", "port": 6379, "banner": "-ERR wrong number of arguments for 'get' command"},
		Expect: expectSpec{Protocol: "Redis", Product: "Redis"},
	},
	{
		ID: "redis-pong", Group: "A-必识别变体", Name: "Redis +PONG",
		Input:  inputItem{"ip": "10.1.0.22", "port": 6379, "banner": "+PONG"},
		Expect: expectSpec{Protocol: "Redis", Product: "Redis"},
	},
	{
		ID: "redis-noauth", Group: "A-必识别变体", Name: "Redis -NOAUTH",
		Input:  inputItem{"ip": "10.1.0.23", "port": 6379, "banner": "-NOAUTH Authentication required."},
		Expect: expectSpec{Protocol: "Redis", Product: "Redis"},
	},
	{
		ID: "redis-denied-protected", Group: "A-必识别变体", Name: "Redis 保护模式 DENIED",
		Input:  inputItem{"ip": "10.1.0.24", "port": 6379, "banner": "-DENIED Redis is running in protected mode"},
		Expect: expectSpec{Protocol: "Redis", Product: "Redis"},
	},
	{
		ID: "redis-ok", Group: "A-必识别变体", Name: "Redis +OK（非标准端口）",
		Input:  inputItem{"ip": "10.1.0.25", "port": 6380, "banner": "+OK"},
		Expect: expectSpec{Protocol: "Redis", Product: "Redis"},
	},
	{
		ID: "ftp-proftpd", Group: "A-必识别变体", Name: "FTP ProFTPD",
		Input:  inputItem{"ip": "10.1.0.26", "port": 21, "banner": "220 ProFTPD 1.3.7 Server (ProFTPD)"},
		Expect: expectSpec{Protocol: "FTP", Product: "ProFTPD", Version: "1.3.7"},
	},
	{
		ID: "ftp-vsftpd", Group: "A-必识别变体", Name: "FTP vsFTPd 括号版本",
		Input:  inputItem{"ip": "10.1.0.27", "port": 21, "banner": "220 (vsFTPd 3.0.5)"},
		Expect: expectSpec{Protocol: "FTP", Product: "vsFTPd", Version: "3.0.5"},
	},
	{
		ID: "ftp-pureftpd-no-ver", Group: "A-必识别变体", Name: "FTP Pure-FTPd 无版本",
		Input:  inputItem{"ip": "10.1.0.28", "port": 21, "banner": "220 Welcome to Pure-FTPd"},
		Expect: expectSpec{Protocol: "FTP", Product: "Pure-FTPd"},
	},
	{
		ID: "ftp-filezilla", Group: "A-必识别变体", Name: "FTP FileZilla Server 多行 220",
		Input:  inputItem{"ip": "10.1.0.29", "port": 21, "banner": "220-FileZilla Server 1.6.7\r\n220 Please visit https://filezilla-project.org/"},
		Expect: expectSpec{Protocol: "FTP", Product: "FileZilla", Version: "1.6.7"},
	},

	// ---------- B. 空值 / 缺字段 / 非法地址 ----------
	{
		ID: "empty-banner", Group: "B-空值缺字段", Name: "空 banner → unknown，不能崩",
		Input:  inputItem{"ip": "10.2.0.1", "port": 80, "banner": ""},
		Expect: expectSpec{Protocol: "unknown"},
	},
	{
		ID: "whitespace-banner", Group: "B-空值缺字段", Name: "仅空白 banner",
		Input:  inputItem{"ip": "10.2.0.2", "port": 80, "banner": "   \t\r\n  "},
		Expect: expectSpec{Protocol: "unknown"},
	},
	{
		ID: "missing-banner-field", Group: "B-空值缺字段", Name: "缺 banner 字段",
		Input:  inputItem{"ip": "10.2.0.3", "port": 22},
		Expect: expectSpec{Protocol: "unknown"},
	},
	{
		ID: "missing-ip", Group: "B-空值缺字段", Name: "缺 ip 字段仍应识别 banner",
		Input:  inputItem{"port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1"},
		Expect: expectSpec{Protocol: "SSH", Product: "OpenSSH"},
	},
	{
		ID: "empty-ip", Group: "B-空值缺字段", Name: "ip 为空字符串",
		Input:  inputItem{"ip": "", "port": 22, "banner": "SSH-2.0-OpenSSH_9.0"},
		Expect: expectSpec{Protocol: "SSH", Product: "OpenSSH"},
	},
	{
		ID: "invalid-ip-text", Group: "B-空值缺字段", Name: "ip 不是地址",
		Input:  inputItem{"ip": "not-an-ip", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"},
		Expect: expectSpec{Protocol: "HTTP", Product: "nginx"},
	},
	{
		ID: "port-zero", Group: "B-空值缺字段", Name: "port=0 但 banner 是 SSH",
		Input:  inputItem{"ip": "10.2.0.4", "port": 0, "banner": "SSH-2.0-OpenSSH_8.9p1"},
		Expect: expectSpec{Protocol: "SSH", Product: "OpenSSH"},
	},
	{
		ID: "port-65535", Group: "B-空值缺字段", Name: "port=65535 边界合法值",
		Input:  inputItem{"ip": "10.2.0.5", "port": 65535, "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"},
		Expect: expectSpec{Protocol: "HTTP", Product: "nginx"},
	},
	{
		ID: "port-out-of-range", Group: "B-空值缺字段", Name: "port=65536 非法，不能崩",
		Input:  inputItem{"ip": "10.2.0.6", "port": 65536, "banner": "SSH-2.0-OpenSSH_8.9p1"},
		Expect: expectSpec{Protocol: "SSH"},
	},
	{
		ID: "port-negative", Group: "B-空值缺字段", Name: "port=-1，不能崩",
		Input:  inputItem{"ip": "10.2.0.7", "port": -1, "banner": "+PONG"},
		Expect: expectSpec{Protocol: "Redis"},
	},
	{
		ID: "ipv6", Group: "B-空值缺字段", Name: "IPv6 地址",
		Input:  inputItem{"ip": "2001:db8::1", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
		Expect: expectSpec{Protocol: "SSH", Product: "OpenSSH", OSHint: "Ubuntu"},
	},
	{
		ID: "extra-unknown-fields", Group: "B-空值缺字段", Name: "输入多未知字段应被忽略",
		Input: inputItem{
			"ip": "10.2.0.8", "port": 80,
			"banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0",
			"ttl":    64, "raw": "xxxx", "note": "ignore-me",
		},
		Expect: expectSpec{Protocol: "HTTP", Product: "nginx", Version: "1.24.0"},
	},

	// ---------- C. 二进制 / 超长 / 注入 ----------
	{
		ID: "tls-clienthello-16-03-01", Group: "C-二进制超长注入", Name: "TLS ClientHello 记录头（可 TLS 或 unknown，但不能当 HTTP/SSH）",
		Input:  inputItem{"ip": "10.3.0.1", "port": 9999, "banner": "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"},
		Expect: expectSpec{ProtocolNotIn: []string{"SSH", "HTTP", "FTP", "MySQL", "Redis"}},
	},
	{
		ID: "tls-literal-escape", Group: "C-二进制超长注入", Name: "TLS 被扫描器写成字面 \\x16\\x03\\x01",
		Input:  inputItem{"ip": "10.3.0.2", "port": 443, "banner": `\x16\x03\x01\x00\xa5\x01\x00\x00\xa1`},
		Expect: expectSpec{ProtocolNotIn: []string{"SSH", "HTTP", "FTP", "MySQL", "Redis"}},
	},
	{
		ID: "banner-with-quotes-and-backslash", Group: "C-二进制超长注入", Name: "banner 含引号、反斜杠",
		Input:  inputItem{"ip": "10.3.0.3", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nX-Req: \"a\\b\""},
		Expect: expectSpec{Protocol: "HTTP", Product: "nginx"},
	},
	{
		ID: "banner-html-xss", Group: "C-二进制超长注入", Name: "banner 含 HTML/脚本片段，不能当解析错误",
		Input:  inputItem{"ip": "10.3.0.4", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57\r\n\r\n<script>alert(1)</script>"},
		Expect: expectSpec{Protocol: "HTTP", Product: "Apache", Version: "2.4.57"},
	},
	{
		ID: "banner-format-string", Group: "C-二进制超长注入", Name: "格式化串 %s%s%n",
		Input:  inputItem{"ip": "10.3.0.5", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 %s%s%n"},
		Expect: expectSpec{Protocol: "SSH", Product: "OpenSSH"},
	},
	{
		ID: "banner-unicode", Group: "C-二进制超长注入", Name: "Server 头附近有中文/emoji",
		Input:  inputItem{"ip": "10.3.0.6", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nX-Msg: 测试🚀"},
		Expect: expectSpec{Protocol: "HTTP", Product: "nginx", Version: "1.24.0"},
	},
	{
		ID: "banner-very-long", Group: "C-二进制超长注入", Name: "超长 banner（约 64KB 垃圾 + 有效 Server 头）",
		Input:  inputItem{"ip": "10.3.0.7", "port": 80, "banner": "HTTP/1.1 200 OK\r\nX-Pad: " + strings.Repeat("A", 65536) + "\r\nServer: nginx/1.24.0\r\n"},
		Expect: expectSpec{Protocol: "HTTP", Product: "nginx", Version: "1.24.0"},
	},
	{
		ID: "banner-null-in-middle", Group: "C-二进制超长注入", Name: "HTTP banner 中间插入 NUL",
		Input:  inputItem{"ip": "10.3.0.8", "port": 80, "banner": "HTTP/1.1 200 OK\r\nSer\x00ver: nginx/1.24.0"},
		Expect: expectSpec{Protocol: "HTTP"},
	},

	// ---------- D. 易混淆 / 应 unknown ----------
	{
		ID: "smtp-not-ftp", Group: "D-易混淆", Name: "SMTP 220 ESMTP 必须识别为 SMTP，不能当 FTP",
		Input:  inputItem{"ip": "10.4.0.1", "port": 25, "banner": "220 mail.example.com ESMTP Postfix"},
		Expect: expectSpec{Protocol: "SMTP", Product: "Postfix", ProtocolNotIn: []string{"FTP", "SSH", "HTTP", "MySQL", "Redis"}},
	},
	{
		ID: "bare-220", Group: "D-易混淆", Name: "裸 220 无产品名：允许 FTP 或 unknown",
		Input:  inputItem{"ip": "10.4.0.2", "port": 21, "banner": "220"},
		Expect: expectSpec{ProtocolIn: []string{"FTP", "unknown"}},
	},
	{
		ID: "quit-crlf", Group: "D-易混淆", Name: "裸 QUIT（题目自测）必须 unknown",
		Input:  inputItem{"ip": "10.4.0.3", "port": 12345, "banner": "QUIT\r\n"},
		Expect: expectSpec{Protocol: "unknown"},
	},
	{
		ID: "html-without-http", Group: "D-易混淆", Name: "只有 HTML 没有 HTTP 状态行",
		Input:  inputItem{"ip": "10.4.0.4", "port": 80, "banner": "<!DOCTYPE html><html><head><title>nginx</title></head></html>"},
		Expect: expectSpec{ProtocolIn: []string{"HTTP", "unknown"}},
	},
	{
		ID: "multi-product-server", Group: "D-易混淆", Name: "Server 头同时出现 nginx 和 Apache",
		Input:  inputItem{"ip": "10.4.0.5", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 Apache/2.4.57"},
		Expect: expectSpec{Protocol: "HTTP", ProductIn: []string{"nginx", "Apache"}},
	},
	{
		ID: "postgres", Group: "D-易混淆", Name: "PostgreSQL 二进制 FATAL 必须识别，且不能当 MySQL",
		Input:  inputItem{"ip": "10.4.0.6", "port": 5432, "banner": "E\x00\x00\x00NSFATAL\x00C28P01\x00Mpassword authentication failed"},
		Expect: expectSpec{ProtocolIn: []string{"PostgreSQL", "PGSQL", "Postgres"}, ProtocolNotIn: []string{"MySQL", "Redis", "SSH", "FTP"}},
	},
	{
		ID: "dropbear-ssh", Group: "D-易混淆", Name: "Dropbear SSH（非 OpenSSH）",
		Input:  inputItem{"ip": "10.4.0.7", "port": 22, "banner": "SSH-2.0-dropbear_2020.81"},
		Expect: expectSpec{Protocol: "SSH", Product: "dropbear", Version: "2020.81"},
	},
	{
		ID: "http2-preface", Group: "D-易混淆", Name: "HTTP/2 连接前言",
		Input:  inputItem{"ip": "10.4.0.8", "port": 443, "banner": "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"},
		Expect: expectSpec{ProtocolIn: []string{"HTTP", "HTTP2", "unknown"}},
	},
	{
		ID: "banner-looks-like-json", Group: "D-易混淆", Name: "banner 本身是 JSON",
		Input:  inputItem{"ip": "10.4.0.9", "port": 8080, "banner": `{"error":"not found","server":"nginx/1.24.0"}`},
		Expect: expectSpec{ProtocolIn: []string{"HTTP", "unknown"}},
	},
	{
		ID: "ssh-looks-http-later", Group: "D-易混淆", Name: "先 SSH 行再跟一段 HTTP，主体应是 SSH",
		Input:  inputItem{"ip": "10.4.0.10", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1\r\nHTTP/1.1 400 Bad Request"},
		Expect: expectSpec{Protocol: "SSH", Product: "OpenSSH"},
	},

	// ---------- F. 扩展应用层协议 ----------
	{
		ID: "smtp-exim", Group: "F-扩展协议-邮件", Name: "SMTP Exim",
		Input:  inputItem{"ip": "10.5.0.1", "port": 25, "banner": "220 mx.example.com ESMTP Exim 4.96"},
		Expect: expectSpec{Protocol: "SMTP", Product: "Exim", Version: "4.96"},
	},
	{
		ID: "smtp-sendmail", Group: "F-扩展协议-邮件", Name: "SMTP Sendmail",
		Input:  inputItem{"ip": "10.5.0.2", "port": 25, "banner": "220 mail.example.com ESMTP Sendmail 8.17.1/8.17.1"},
		Expect: expectSpec{Protocol: "SMTP", Product: "Sendmail", Version: "8.17.1"},
	},
	{
		ID: "smtp-microsoft", Group: "F-扩展协议-邮件", Name: "SMTP Microsoft ESMTP",
		Input:  inputItem{"ip": "10.5.0.3", "port": 25, "banner": "220 EXCH01.contoso.com Microsoft ESMTP MAIL Service ready at Tue, 22 Sep 2026 10:00:00 +0800"},
		Expect: expectSpec{Protocol: "SMTP", ProductIn: []string{"Microsoft", "Exchange", "ESMTP"}},
	},
	{
		ID: "smtp-submission-587", Group: "F-扩展协议-邮件", Name: "SMTP 开在 587（submission），端口不能压过 banner",
		Input:  inputItem{"ip": "10.5.0.4", "port": 587, "banner": "220 mail.example.com ESMTP Postfix (Ubuntu)"},
		Expect: expectSpec{Protocol: "SMTP", Product: "Postfix", OSHint: "Ubuntu"},
	},
	{
		ID: "smtp-multiline-220", Group: "F-扩展协议-邮件", Name: "SMTP 多行 220-",
		Input:  inputItem{"ip": "10.5.0.5", "port": 25, "banner": "220-mail.example.com ESMTP Exim 4.94.2\r\n220-TLS is available\r\n220 End"},
		Expect: expectSpec{Protocol: "SMTP", Product: "Exim", Version: "4.94.2"},
	},
	{
		ID: "smtp-lowercase", Group: "F-扩展协议-邮件", Name: "SMTP banner 小写 esmtp",
		Input:  inputItem{"ip": "10.5.0.6", "port": 25, "banner": "220 mx.example.net esmtp postfix"},
		Expect: expectSpec{Protocol: "SMTP", Product: "Postfix"},
	},
	{
		ID: "smtp-hostname-has-ftp", Group: "F-扩展协议-邮件", Name: "主机名含 ftp 但 ESMTP 仍是 SMTP",
		Input:  inputItem{"ip": "10.5.0.7", "port": 25, "banner": "220 ftp.example.com ESMTP Postfix"},
		Expect: expectSpec{Protocol: "SMTP", Product: "Postfix", ProtocolNotIn: []string{"FTP"}},
	},
	{
		ID: "pop3-dovecot", Group: "F-扩展协议-邮件", Name: "POP3 Dovecot",
		Input:  inputItem{"ip": "10.5.0.8", "port": 110, "banner": "+OK Dovecot ready."},
		Expect: expectSpec{Protocol: "POP3", Product: "Dovecot", ProtocolNotIn: []string{"Redis"}},
	},
	{
		ID: "pop3-exchange", Group: "F-扩展协议-邮件", Name: "POP3 Microsoft Exchange",
		Input:  inputItem{"ip": "10.5.0.9", "port": 110, "banner": "+OK Microsoft Exchange POP3 server ready"},
		Expect: expectSpec{Protocol: "POP3", ProductIn: []string{"Exchange", "Microsoft"}},
	},
	{
		ID: "imap-dovecot-debian", Group: "F-扩展协议-邮件", Name: "IMAP Dovecot + Debian",
		Input:  inputItem{"ip": "10.5.0.10", "port": 143, "banner": "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS] Dovecot (Debian) ready."},
		Expect: expectSpec{Protocol: "IMAP", Product: "Dovecot", OSHint: "Debian"},
	},
	{
		ID: "imap-cyrus", Group: "F-扩展协议-邮件", Name: "IMAP Cyrus",
		Input:  inputItem{"ip": "10.5.0.11", "port": 143, "banner": "* OK [CAPABILITY IMAP4rev1] Cyrus IMAP v3.6.1 server ready"},
		Expect: expectSpec{Protocol: "IMAP", Product: "Cyrus", Version: "3.6.1"},
	},

	{
		ID: "pgsql-fatal-text", Group: "F-扩展协议-数据库", Name: "PostgreSQL 文本 FATAL 认证失败",
		Input:  inputItem{"ip": "10.6.0.1", "port": 5432, "banner": `FATAL:  password authentication failed for user "postgres"`},
		Expect: expectSpec{ProtocolIn: []string{"PostgreSQL", "PGSQL", "Postgres"}, ProtocolNotIn: []string{"MySQL"}},
	},
	{
		ID: "pgsql-no-hba", Group: "F-扩展协议-数据库", Name: "PostgreSQL 无 pg_hba.conf 条目",
		Input:  inputItem{"ip": "10.6.0.2", "port": 5432, "banner": `FATAL:  no pg_hba.conf entry for host "10.6.0.2", user "app", database "app"`},
		Expect: expectSpec{ProtocolIn: []string{"PostgreSQL", "PGSQL", "Postgres"}},
	},
	{
		ID: "pgsql-unsupported-frontend", Group: "F-扩展协议-数据库", Name: "PostgreSQL 不支持的前端协议",
		Input:  inputItem{"ip": "10.6.0.3", "port": 5432, "banner": "FATAL:  unsupported frontend protocol 0.0: server supports 3.0 to 3.0"},
		Expect: expectSpec{ProtocolIn: []string{"PostgreSQL", "PGSQL", "Postgres"}},
	},
	{
		ID: "pgsql-nonstandard-port", Group: "F-扩展协议-数据库", Name: "PostgreSQL 开在 15432",
		Input:  inputItem{"ip": "10.6.0.4", "port": 15432, "banner": `FATAL:  password authentication failed for user "app"`},
		Expect: expectSpec{ProtocolIn: []string{"PostgreSQL", "PGSQL", "Postgres"}},
	},
	{
		ID: "mongodb-http-native-port", Group: "F-扩展协议-数据库", Name: "MongoDB 原生端口误用 HTTP",
		Input:  inputItem{"ip": "10.6.0.5", "port": 27017, "banner": "It looks like you are trying to access MongoDB over HTTP on the native driver port."},
		Expect: expectSpec{ProtocolIn: []string{"MongoDB", "Mongo"}, ProtocolNotIn: []string{"HTTP"}},
	},
	{
		ID: "mongodb-json-errmsg", Group: "F-扩展协议-数据库", Name: "MongoDB JSON 错误",
		Input:  inputItem{"ip": "10.6.0.6", "port": 27017, "banner": `{"ok":0,"errmsg":"no such cmd: foo","code":59,"codeName":"CommandNotFound"}`},
		Expect: expectSpec{ProtocolIn: []string{"MongoDB", "Mongo"}},
	},
	{
		ID: "memcached-version", Group: "F-扩展协议-数据库", Name: "Memcached VERSION",
		Input:  inputItem{"ip": "10.6.0.7", "port": 11211, "banner": "VERSION 1.6.18\r\n"},
		Expect: expectSpec{Protocol: "Memcached", Product: "Memcached", Version: "1.6.18"},
	},
	{
		ID: "memcached-stat", Group: "F-扩展协议-数据库", Name: "Memcached STAT",
		Input:  inputItem{"ip": "10.6.0.8", "port": 11211, "banner": "STAT pid 1\r\nSTAT version 1.6.15\r\nEND\r\n"},
		Expect: expectSpec{Protocol: "Memcached", Version: "1.6.15"},
	},
	{
		ID: "mssql-banner", Group: "F-扩展协议-数据库", Name: "Microsoft SQL Server",
		Input:  inputItem{"ip": "10.6.0.9", "port": 1433, "banner": "Microsoft SQL Server 2019 (RTM-CU18) - 15.0.4261.1"},
		Expect: expectSpec{ProtocolIn: []string{"MSSQL", "SQLServer", "TDS"}, ProductIn: []string{"SQL Server", "MSSQL"}, Version: "2019"},
	},
	{
		ID: "oracle-tns", Group: "F-扩展协议-数据库", Name: "Oracle TNS 错误描述",
		Input:  inputItem{"ip": "10.6.0.10", "port": 1521, "banner": "(DESCRIPTION=(ERR=12514)(VSNNUM=318767104)(ERROR_STACK=(ERROR=(CODE=12514)(EMFI=4))))"},
		Expect: expectSpec{ProtocolIn: []string{"Oracle", "TNS"}, ProductIn: []string{"Oracle", "TNS"}},
	},
	{
		ID: "elasticsearch-tagline", Group: "F-扩展协议-数据库", Name: "Elasticsearch Welcome JSON",
		Input:  inputItem{"ip": "10.6.0.11", "port": 9200, "banner": "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"name\":\"es01\",\"cluster_name\":\"docker-cluster\",\"version\":{\"number\":\"8.11.1\"},\"tagline\":\"You Know, for Search\"}"},
		Expect: expectSpec{ProtocolIn: []string{"Elasticsearch", "ES", "HTTP"}, ProductIn: []string{"Elasticsearch", "ES"}, Version: "8.11.1"},
	},
	{
		ID: "couchdb-welcome", Group: "F-扩展协议-数据库", Name: "CouchDB Welcome JSON",
		Input:  inputItem{"ip": "10.6.0.12", "port": 5984, "banner": "HTTP/1.1 200 OK\r\nServer: CouchDB/3.3.2\r\n\r\n{\"couchdb\":\"Welcome\",\"version\":\"3.3.2\"}"},
		Expect: expectSpec{ProtocolIn: []string{"CouchDB", "HTTP"}, Product: "CouchDB", Version: "3.3.2"},
	},
	{
		ID: "cassandra-protocol", Group: "F-扩展协议-数据库", Name: "Cassandra 协议版本错误",
		Input:  inputItem{"ip": "10.6.0.13", "port": 9042, "banner": "Invalid or unsupported protocol version (4); supported versions are (3/v3, 5/v5-beta)"},
		Expect: expectSpec{Protocol: "Cassandra", Product: "Cassandra"},
	},
	{
		ID: "clickhouse-exception", Group: "F-扩展协议-数据库", Name: "ClickHouse 认证异常",
		Input:  inputItem{"ip": "10.6.0.14", "port": 8123, "banner": "Code: 516. DB::Exception: default: Authentication failed: password is incorrect, or there is no user with such name. (AUTHENTICATION_FAILED)"},
		Expect: expectSpec{Protocol: "ClickHouse", Product: "ClickHouse"},
	},
	{
		ID: "influxdb-header", Group: "F-扩展协议-数据库", Name: "InfluxDB HTTP 版本头",
		Input:  inputItem{"ip": "10.6.0.15", "port": 8086, "banner": "HTTP/1.1 204 No Content\r\nX-Influxdb-Version: 1.8.10\r\nX-Influxdb-Build: OSS"},
		Expect: expectSpec{ProtocolIn: []string{"InfluxDB", "HTTP"}, Product: "InfluxDB", Version: "1.8.10"},
	},

	{
		ID: "telnet-ubuntu-login", Group: "F-扩展协议-远程", Name: "Telnet Ubuntu 登录提示",
		Input:  inputItem{"ip": "10.7.0.1", "port": 23, "banner": "Ubuntu 22.04.3 LTS\r\nlogin: "},
		Expect: expectSpec{Protocol: "Telnet", OSHint: "Ubuntu"},
	},
	{
		ID: "telnet-iac", Group: "F-扩展协议-远程", Name: "Telnet IAC 协商",
		Input:  inputItem{"ip": "10.7.0.2", "port": 23, "banner": "\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27"},
		Expect: expectSpec{Protocol: "Telnet"},
	},
	{
		ID: "rdp-tpkt", Group: "F-扩展协议-远程", Name: "RDP TPKT 头",
		Input:  inputItem{"ip": "10.7.0.3", "port": 3389, "banner": "\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x00\x08\x00\x02\x00\x00\x00"},
		Expect: expectSpec{Protocol: "RDP"},
	},
	{
		ID: "vnc-rfb-008", Group: "F-扩展协议-远程", Name: "VNC RFB 003.008",
		Input:  inputItem{"ip": "10.7.0.4", "port": 5900, "banner": "RFB 003.008\n"},
		Expect: expectSpec{Protocol: "VNC", Version: "003.008"},
	},
	{
		ID: "vnc-rfb-003", Group: "F-扩展协议-远程", Name: "VNC RFB 003.003",
		Input:  inputItem{"ip": "10.7.0.5", "port": 5901, "banner": "RFB 003.003\n"},
		Expect: expectSpec{Protocol: "VNC", Version: "003.003"},
	},
	{
		ID: "mqtt-connack", Group: "F-扩展协议-远程", Name: "MQTT CONNACK",
		Input:  inputItem{"ip": "10.7.0.6", "port": 1883, "banner": "\x20\x02\x00\x00"},
		Expect: expectSpec{Protocol: "MQTT"},
	},
	{
		ID: "amqp-header", Group: "F-扩展协议-远程", Name: "AMQP / RabbitMQ 协议头",
		Input:  inputItem{"ip": "10.7.0.7", "port": 5672, "banner": "AMQP\x00\x00\x09\x01"},
		Expect: expectSpec{ProtocolIn: []string{"AMQP", "RabbitMQ"}, ProductIn: []string{"AMQP", "RabbitMQ"}},
	},
	{
		ID: "modbus-mbap", Group: "F-扩展协议-远程", Name: "Modbus TCP MBAP",
		Input:  inputItem{"ip": "10.7.0.8", "port": 502, "banner": "\x00\x01\x00\x00\x00\x03\x01\x83\x01"},
		Expect: expectSpec{Protocol: "Modbus"},
	},

	{
		ID: "ldap-bind-fail", Group: "F-扩展协议-基础设施", Name: "LDAP bind 失败文本",
		Input:  inputItem{"ip": "10.8.0.1", "port": 389, "banner": "ldap_bind: Invalid credentials (49)\nadditional info: 80090308: LdapErr: DSID-0C090447"},
		Expect: expectSpec{Protocol: "LDAP"},
	},
	{
		ID: "sip-asterisk", Group: "F-扩展协议-基础设施", Name: "SIP Asterisk",
		Input:  inputItem{"ip": "10.8.0.2", "port": 5060, "banner": "SIP/2.0 200 OK\r\nServer: Asterisk PBX 18.12.0\r\nVia: SIP/2.0/UDP 10.8.0.9:5060"},
		Expect: expectSpec{Protocol: "SIP", Product: "Asterisk", Version: "18.12.0", ProtocolNotIn: []string{"HTTP"}},
	},
	{
		ID: "rtsp-vlc", Group: "F-扩展协议-基础设施", Name: "RTSP VLC",
		Input:  inputItem{"ip": "10.8.0.3", "port": 554, "banner": "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: VLC/3.0.18"},
		Expect: expectSpec{Protocol: "RTSP", Product: "VLC", Version: "3.0.18", ProtocolNotIn: []string{"HTTP"}},
	},
	{
		ID: "socks5-noauth", Group: "F-扩展协议-基础设施", Name: "SOCKS5 无认证应答",
		Input:  inputItem{"ip": "10.8.0.4", "port": 1080, "banner": "\x05\x00"},
		Expect: expectSpec{ProtocolIn: []string{"SOCKS", "SOCKS5"}},
	},
	{
		ID: "tls-serverhello", Group: "F-扩展协议-基础设施", Name: "TLS ServerHello 记录",
		Input:  inputItem{"ip": "10.8.0.5", "port": 443, "banner": "\x16\x03\x03\x00\x3a\x02\x00\x00\x36\x03\x03"},
		Expect: expectSpec{ProtocolIn: []string{"TLS", "SSL"}, ProtocolNotIn: []string{"HTTP", "SSH", "FTP"}},
	},
	{
		ID: "smb-ntlm", Group: "F-扩展协议-基础设施", Name: "SMB 方言头 \\xffSMB",
		Input:  inputItem{"ip": "10.8.0.6", "port": 445, "banner": "\xffSMB\x72\x00\x00\x00\x00"},
		Expect: expectSpec{Protocol: "SMB"},
	},
	{
		ID: "rsyncd", Group: "F-扩展协议-基础设施", Name: "Rsync 守护进程问候",
		Input:  inputItem{"ip": "10.8.0.7", "port": 873, "banner": "@RSYNCD: 31.0\n"},
		Expect: expectSpec{Protocol: "Rsync", Version: "31.0"},
	},
	{
		ID: "zookeeper-stat", Group: "F-扩展协议-基础设施", Name: "ZooKeeper stat 版本行",
		Input:  inputItem{"ip": "10.8.0.8", "port": 2181, "banner": "Zookeeper version: 3.8.0-e4d3d3, built on 2022-02-23 16:21 UTC\nLatency min/avg/max: 0/0/0"},
		Expect: expectSpec{ProtocolIn: []string{"ZooKeeper", "Zookeeper"}, ProductIn: []string{"ZooKeeper", "Zookeeper"}, Version: "3.8.0"},
	},
	{
		ID: "irc-notice", Group: "F-扩展协议-基础设施", Name: "IRC NOTICE AUTH",
		Input:  inputItem{"ip": "10.8.0.9", "port": 6667, "banner": ":irc.example.com NOTICE AUTH :*** Looking up your hostname"},
		Expect: expectSpec{Protocol: "IRC"},
	},
	{
		ID: "nntp-ready", Group: "F-扩展协议-基础设施", Name: "NNTP 200 Ready",
		Input:  inputItem{"ip": "10.8.0.10", "port": 119, "banner": "200 NNTP Service Ready, posting allowed"},
		Expect: expectSpec{Protocol: "NNTP", ProtocolNotIn: []string{"HTTP", "SMTP", "FTP"}},
	},
	{
		ID: "xmpp-stream", Group: "F-扩展协议-基础设施", Name: "XMPP stream 开场",
		Input:  inputItem{"ip": "10.8.0.11", "port": 5222, "banner": "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' from='example.com' version='1.0'>"},
		Expect: expectSpec{Protocol: "XMPP"},
	},
	{
		ID: "docker-api", Group: "F-扩展协议-基础设施", Name: "Docker API HTTP 头",
		Input:  inputItem{"ip": "10.8.0.12", "port": 2375, "banner": "HTTP/1.1 200 OK\r\nApi-Version: 1.43\r\nDocker-Experimental: false\r\nServer: Docker/24.0.7 (linux)"},
		Expect: expectSpec{ProtocolIn: []string{"Docker", "HTTP"}, Product: "Docker", Version: "24.0.7"},
	},
	{
		ID: "k8s-unauthorized", Group: "F-扩展协议-基础设施", Name: "Kubernetes API 401 JSON",
		Input:  inputItem{"ip": "10.8.0.13", "port": 6443, "banner": "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\",\"status\":\"Failure\",\"message\":\"Unauthorized\",\"reason\":\"Unauthorized\",\"code\":401}"},
		Expect: expectSpec{ProtocolIn: []string{"Kubernetes", "K8s", "HTTP"}, ProductIn: []string{"Kubernetes", "K8s"}},
	},
	{
		ID: "etcd-version", Group: "F-扩展协议-基础设施", Name: "etcd version JSON",
		Input:  inputItem{"ip": "10.8.0.14", "port": 2379, "banner": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"etcdserver\":\"3.5.9\",\"etcdcluster\":\"3.5.0\"}"},
		Expect: expectSpec{ProtocolIn: []string{"etcd", "HTTP"}, Product: "etcd", Version: "3.5.9"},
	},
	{
		ID: "consul-agent", Group: "F-扩展协议-基础设施", Name: "Consul agent JSON",
		Input:  inputItem{"ip": "10.8.0.15", "port": 8500, "banner": "HTTP/1.1 200 OK\r\nX-Consul-Index: 12\r\n\r\n{\"Config\":{\"Datacenter\":\"dc1\",\"NodeName\":\"consul-1\",\"Version\":\"1.16.2\"}}"},
		Expect: expectSpec{ProtocolIn: []string{"Consul", "HTTP"}, Product: "Consul", Version: "1.16.2"},
	},
	{
		ID: "jenkins-header", Group: "F-扩展协议-基础设施", Name: "Jenkins X-Jenkins 头",
		Input:  inputItem{"ip": "10.8.0.16", "port": 8080, "banner": "HTTP/1.1 200 OK\r\nX-Jenkins: 2.426.1\r\nX-Hudson: 1.395\r\nServer: Jetty(10.0.17)"},
		Expect: expectSpec{Protocol: "HTTP", ProductIn: []string{"Jenkins", "Jetty"}},
	},
	{
		ID: "ipp-cups", Group: "F-扩展协议-基础设施", Name: "IPP / CUPS",
		Input:  inputItem{"ip": "10.8.0.17", "port": 631, "banner": "HTTP/1.1 200 OK\r\nServer: CUPS/2.4.2\r\nContent-Type: application/ipp"},
		Expect: expectSpec{ProtocolIn: []string{"IPP", "HTTP"}, Product: "CUPS", Version: "2.4.2"},
	},
	{
		ID: "winrm-httpapi", Group: "F-扩展协议-基础设施", Name: "WinRM / Microsoft-HTTPAPI",
		Input:  inputItem{"ip": "10.8.0.18", "port": 5985, "banner": "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\nWWW-Authenticate: Kerberos\r\nServer: Microsoft-HTTPAPI/2.0"},
		Expect: expectSpec{ProtocolIn: []string{"WinRM", "HTTP"}, ProductIn: []string{"WinRM", "HTTPAPI", "Microsoft"}},
	},
	{
		ID: "snmp-public-text", Group: "F-扩展协议-基础设施", Name: "SNMP 社区/错误可见文本",
		Input:  inputItem{"ip": "10.8.0.19", "port": 161, "banner": "public\nSNMPv2-MIB::sysDescr.0 = STRING: Linux host 5.15.0-91-generic"},
		Expect: expectSpec{Protocol: "SNMP", OSHint: "Linux"},
	},
	{
		ID: "dns-bind-chaos", Group: "F-扩展协议-基础设施", Name: "BIND version CHAOS 文本",
		Input:  inputItem{"ip": "10.8.0.20", "port": 53, "banner": "version.bind.        CH      TXT     \"9.18.18-0ubuntu0.22.04.1-Ubuntu\""},
		Expect: expectSpec{Protocol: "DNS", ProductIn: []string{"BIND", "named"}, Version: "9.18.18", OSHint: "Ubuntu"},
	},

	{
		ID: "http-tomcat", Group: "F-扩展协议-HTTP家族", Name: "Apache Tomcat",
		Input:  inputItem{"ip": "10.9.0.1", "port": 8080, "banner": "HTTP/1.1 404 \r\nServer: Apache-Coyote/1.1\r\n"},
		Expect: expectSpec{Protocol: "HTTP", ProductIn: []string{"Tomcat", "Coyote"}},
	},
	{
		ID: "http-tomcat-full", Group: "F-扩展协议-HTTP家族", Name: "Apache Tomcat 完整产品名",
		Input:  inputItem{"ip": "10.9.0.2", "port": 8080, "banner": "HTTP/1.1 200 OK\r\nServer: Apache Tomcat/9.0.75"},
		Expect: expectSpec{Protocol: "HTTP", Product: "Tomcat", Version: "9.0.75"},
	},
	{
		ID: "http-caddy", Group: "F-扩展协议-HTTP家族", Name: "Caddy",
		Input:  inputItem{"ip": "10.9.0.3", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: Caddy"},
		Expect: expectSpec{Protocol: "HTTP", Product: "Caddy"},
	},
	{
		ID: "http-lighttpd", Group: "F-扩展协议-HTTP家族", Name: "lighttpd",
		Input:  inputItem{"ip": "10.9.0.4", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.69"},
		Expect: expectSpec{Protocol: "HTTP", Product: "lighttpd", Version: "1.4.69"},
	},
	{
		ID: "http-openresty", Group: "F-扩展协议-HTTP家族", Name: "OpenResty",
		Input:  inputItem{"ip": "10.9.0.5", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: openresty/1.21.4.1"},
		Expect: expectSpec{Protocol: "HTTP", Product: "openresty", Version: "1.21.4.1"},
	},
	{
		ID: "http-gunicorn", Group: "F-扩展协议-HTTP家族", Name: "gunicorn",
		Input:  inputItem{"ip": "10.9.0.6", "port": 8000, "banner": "HTTP/1.1 200 OK\r\nServer: gunicorn/20.1.0"},
		Expect: expectSpec{Protocol: "HTTP", Product: "gunicorn", Version: "20.1.0"},
	},
	{
		ID: "http-weblogic", Group: "F-扩展协议-HTTP家族", Name: "WebLogic",
		Input:  inputItem{"ip": "10.9.0.7", "port": 7001, "banner": "HTTP/1.1 200 OK\r\nServer: WebLogic Server 12.2.1.4.0 Tue Jan 14 12:00:00 PST 2020"},
		Expect: expectSpec{Protocol: "HTTP", Product: "WebLogic", Version: "12.2.1.4.0"},
	},
	{
		ID: "http-wildfly", Group: "F-扩展协议-HTTP家族", Name: "WildFly / JBoss",
		Input:  inputItem{"ip": "10.9.0.8", "port": 8080, "banner": "HTTP/1.1 200 OK\r\nServer: WildFly/26.1.3"},
		Expect: expectSpec{Protocol: "HTTP", ProductIn: []string{"WildFly", "JBoss"}, Version: "26.1.3"},
	},
	{
		ID: "http-squid", Group: "F-扩展协议-HTTP家族", Name: "Squid 代理",
		Input:  inputItem{"ip": "10.9.0.9", "port": 3128, "banner": "HTTP/1.1 400 Bad Request\r\nServer: squid/5.7\r\nX-Squid-Error: ERR_INVALID_URL 0"},
		Expect: expectSpec{Protocol: "HTTP", Product: "squid", Version: "5.7"},
	},
	{
		ID: "ssh-cisco", Group: "F-扩展协议-SSH/FTP", Name: "SSH Cisco",
		Input:  inputItem{"ip": "10.9.0.10", "port": 22, "banner": "SSH-2.0-Cisco-1.25"},
		Expect: expectSpec{Protocol: "SSH", Product: "Cisco", Version: "1.25"},
	},
	{
		ID: "ssh-libssh", Group: "F-扩展协议-SSH/FTP", Name: "SSH libssh",
		Input:  inputItem{"ip": "10.9.0.11", "port": 22, "banner": "SSH-2.0-libssh_0.9.6"},
		Expect: expectSpec{Protocol: "SSH", Product: "libssh", Version: "0.9.6"},
	},
	{
		ID: "ftp-microsoft", Group: "F-扩展协议-SSH/FTP", Name: "Microsoft FTP Service 不能当 SMTP",
		Input:  inputItem{"ip": "10.9.0.12", "port": 21, "banner": "220 Microsoft FTP Service"},
		Expect: expectSpec{Protocol: "FTP", ProductIn: []string{"Microsoft", "IIS", "FTP"}, ProtocolNotIn: []string{"SMTP"}},
	},

	// ---------- G. 扩展协议交叉误判 ----------
	{
		ID: "pop3-not-redis", Group: "G-扩展协议混淆", Name: "POP3 +OK 不能当 Redis",
		Input:  inputItem{"ip": "10.10.0.1", "port": 110, "banner": "+OK Dovecot ready."},
		Expect: expectSpec{Protocol: "POP3", ProtocolNotIn: []string{"Redis"}},
	},
	{
		ID: "redis-plus-ok-still-redis", Group: "G-扩展协议混淆", Name: "6379 上裸 +OK 仍是 Redis，不能当 POP3",
		Input:  inputItem{"ip": "10.10.0.2", "port": 6379, "banner": "+OK"},
		Expect: expectSpec{Protocol: "Redis", ProtocolNotIn: []string{"POP3"}},
	},
	{
		ID: "memcached-error-not-redis", Group: "G-扩展协议混淆", Name: "Memcached ERROR 不能当 Redis -ERR",
		Input:  inputItem{"ip": "10.10.0.3", "port": 11211, "banner": "ERROR\r\n"},
		Expect: expectSpec{Protocol: "Memcached", ProtocolNotIn: []string{"Redis"}},
	},
	{
		ID: "sip-not-http", Group: "G-扩展协议混淆", Name: "SIP/2.0 不能当 HTTP",
		Input:  inputItem{"ip": "10.10.0.4", "port": 5060, "banner": "SIP/2.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"asterisk\""},
		Expect: expectSpec{Protocol: "SIP", ProtocolNotIn: []string{"HTTP"}},
	},
	{
		ID: "rtsp-not-http", Group: "G-扩展协议混淆", Name: "RTSP/1.0 不能当 HTTP",
		Input:  inputItem{"ip": "10.10.0.5", "port": 554, "banner": "RTSP/1.0 401 Unauthorized\r\nCSeq: 2"},
		Expect: expectSpec{Protocol: "RTSP", ProtocolNotIn: []string{"HTTP"}},
	},
	{
		ID: "nntp-200-not-http", Group: "G-扩展协议混淆", Name: "NNTP 200 不能当 HTTP 200",
		Input:  inputItem{"ip": "10.10.0.6", "port": 119, "banner": "200 news.example.com InterNetNews NNRP server INN 2.6.4 ready"},
		Expect: expectSpec{Protocol: "NNTP", ProductIn: []string{"INN", "NNTP"}, Version: "2.6.4", ProtocolNotIn: []string{"HTTP", "SMTP", "FTP"}},
	},
	{
		ID: "imap-star-ok-not-http", Group: "G-扩展协议混淆", Name: "IMAP * OK 不能当 HTTP",
		Input:  inputItem{"ip": "10.10.0.7", "port": 143, "banner": "* OK IMAP4rev1 Server ready"},
		Expect: expectSpec{Protocol: "IMAP", ProtocolNotIn: []string{"HTTP", "Redis"}},
	},
	{
		ID: "es-not-couchdb", Group: "G-扩展协议混淆", Name: "Elasticsearch tagline 不能当 CouchDB",
		Input:  inputItem{"ip": "10.10.0.8", "port": 9200, "banner": "{\"tagline\":\"You Know, for Search\",\"version\":{\"number\":\"7.17.14\"}}"},
		Expect: expectSpec{ProtocolIn: []string{"Elasticsearch", "ES", "HTTP"}, ProductIn: []string{"Elasticsearch", "ES"}, ProtocolNotIn: []string{"CouchDB", "MongoDB"}},
	},
	{
		ID: "ftp-not-smtp-microsoft", Group: "G-扩展协议混淆", Name: "220 Microsoft FTP 不能当 SMTP",
		Input:  inputItem{"ip": "10.10.0.9", "port": 21, "banner": "220 Microsoft FTP Service"},
		Expect: expectSpec{Protocol: "FTP", ProtocolNotIn: []string{"SMTP"}},
	},
	{
		ID: "http-connect-proxy", Group: "G-扩展协议混淆", Name: "HTTP CONNECT 代理仍是 HTTP",
		Input:  inputItem{"ip": "10.10.0.10", "port": 8080, "banner": "HTTP/1.1 403 Forbidden\r\nProxy-Agent: tinyproxy/1.11.1"},
		Expect: expectSpec{Protocol: "HTTP", Product: "tinyproxy", Version: "1.11.1"},
	},
}

var requiredFields = []string{"ip", "port", "protocol", "product", "version", "os_hint", "confidence"}

type reporter struct {
	passed int
	failed int
	errors []string
}

func (r *reporter) check(ok bool, title, detail string) {
	mark := "PASS"
	if !ok {
		mark = "FAIL"
		r.failed++
		if detail != "" {
			r.errors = append(r.errors, title+": "+detail)
		} else {
			r.errors = append(r.errors, title)
		}
	} else {
		r.passed++
	}
	line := fmt.Sprintf("  [%s] %s", mark, title)
	if !ok && detail != "" {
		line += "\n         " + detail
	}
	fmt.Println(line)
}

func dumpInputs() []inputItem {
	out := make([]inputItem, 0, len(identifyCases))
	for _, c := range identifyCases {
		out = append(out, c.Input)
	}
	return out
}

func norm(v any) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func normLower(v any) string {
	return strings.ToLower(norm(v))
}

func containsFold(haystack any, needle string) bool {
	return strings.Contains(normLower(haystack), strings.ToLower(needle))
}

func inFold(value any, list []string) bool {
	got := normLower(value)
	for _, item := range list {
		if got == strings.ToLower(item) {
			return true
		}
	}
	return false
}

func validateSchema(item map[string]any, idx int) []string {
	var errs []string
	for _, field := range requiredFields {
		if _, ok := item[field]; !ok {
			errs = append(errs, fmt.Sprintf("[%d] 缺少字段 %s", idx, field))
		}
	}
	if norm(item["protocol"]) == "" {
		errs = append(errs, fmt.Sprintf("[%d] protocol 不能为空，认不出应返回 unknown", idx))
	}
	raw, ok := item["confidence"]
	if !ok {
		errs = append(errs, fmt.Sprintf("[%d] confidence 缺失", idx))
		return errs
	}
	var conf float64
	switch n := raw.(type) {
	case float64:
		conf = n
	case json.Number:
		v, err := n.Float64()
		if err != nil {
			errs = append(errs, fmt.Sprintf("[%d] confidence 不是数字: %v", idx, raw))
			return errs
		}
		conf = v
	default:
		errs = append(errs, fmt.Sprintf("[%d] confidence 不是数字: %v", idx, raw))
		return errs
	}
	if conf < 0 || conf > 1 {
		errs = append(errs, fmt.Sprintf("[%d] confidence=%v 超出 [0,1]", idx, raw))
	}
	return errs
}

func matchExpect(item map[string]any, exp expectSpec, idx int, id string) []string {
	var errs []string
	prefix := fmt.Sprintf("[%d %s]", idx, id)
	if exp.Protocol != "" && normLower(item["protocol"]) != strings.ToLower(exp.Protocol) {
		errs = append(errs, fmt.Sprintf("%s protocol 期望 %q 实际 %v", prefix, exp.Protocol, item["protocol"]))
	}
	if len(exp.ProtocolIn) > 0 && !inFold(item["protocol"], exp.ProtocolIn) {
		errs = append(errs, fmt.Sprintf("%s protocol=%v 不在 %v", prefix, item["protocol"], exp.ProtocolIn))
	}
	if len(exp.ProtocolNotIn) > 0 && inFold(item["protocol"], exp.ProtocolNotIn) {
		errs = append(errs, fmt.Sprintf("%s protocol=%v 不应是 %v", prefix, item["protocol"], exp.ProtocolNotIn))
	}
	if exp.Product != "" && !containsFold(item["product"], exp.Product) {
		errs = append(errs, fmt.Sprintf("%s product 期望包含 %q 实际 %v", prefix, exp.Product, item["product"]))
	}
	if len(exp.ProductIn) > 0 {
		ok := false
		for _, p := range exp.ProductIn {
			if containsFold(item["product"], p) {
				ok = true
				break
			}
		}
		if !ok {
			errs = append(errs, fmt.Sprintf("%s product=%v 不在 %v", prefix, item["product"], exp.ProductIn))
		}
	}
	if exp.Version != "" && !strings.Contains(norm(item["version"]), exp.Version) {
		errs = append(errs, fmt.Sprintf("%s version 期望包含 %q 实际 %v", prefix, exp.Version, item["version"]))
	}
	if exp.OSHint != "" && !containsFold(item["os_hint"], exp.OSHint) {
		errs = append(errs, fmt.Sprintf("%s os_hint 期望包含 %q 实际 %v", prefix, exp.OSHint, item["os_hint"]))
	}
	return errs
}

func doJSON(client *http.Client, method, url string, body any) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return resp.StatusCode, data, err
}

func doRaw(client *http.Client, url string, raw []byte, contentType string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return resp.StatusCode, data, err
}

func runHealth(client *http.Client, base string, r *reporter) {
	fmt.Println("\n== E. GET /health ==")
	status, _, err := doJSON(client, http.MethodGet, base+"/health", nil)
	if err != nil {
		r.check(false, "健康检查可访问", err.Error())
		return
	}
	r.check(status >= 200 && status < 300, fmt.Sprintf("健康检查返回 2xx（实际 %d）", status), "")
}

func runIdentify(client *http.Client, base string, r *reporter) {
	fmt.Println("\n== A/B/C/D. POST /fingerprint 批量识别 ==")
	payload := dumpInputs()
	status, raw, err := doJSON(client, http.MethodPost, base+"/fingerprint", payload)
	if err != nil {
		r.check(false, "批量识别接口可访问", err.Error())
		return
	}
	r.check(status == 200, fmt.Sprintf("批量识别 HTTP 200（实际 %d）", status), "")

	var parsed []map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		preview := string(raw)
		if len(preview) > 200 {
			preview = preview[:200]
		}
		r.check(false, "响应必须是 JSON 数组", preview)
		return
	}
	r.check(len(parsed) == len(payload), fmt.Sprintf("结果条数等于输入条数（输入 %d 输出 %d）", len(payload), len(parsed)), "")

	n := len(parsed)
	if n > len(identifyCases) {
		n = len(identifyCases)
	}
	for i := 0; i < n; i++ {
		c := identifyCases[i]
		item := parsed[i]
		errs := append(validateSchema(item, i), matchExpect(item, c.Expect, i, c.ID)...)
		r.check(len(errs) == 0, c.Group+" | "+c.Name, strings.Join(errs, "; "))
	}
}

func runAPIContract(client *http.Client, base string, timeout time.Duration, r *reporter) {
	fmt.Println("\n== E. API 契约 / 抗造情况 ==")
	url := base + "/fingerprint"

	status, raw, err := doJSON(client, http.MethodPost, url, []any{})
	if err != nil {
		r.check(false, "空数组 []", err.Error())
	} else {
		ok := status == 200 && strings.TrimSpace(string(raw)) == "[]"
		if !ok && status == 200 {
			var parsed []any
			if json.Unmarshal(raw, &parsed) == nil && len(parsed) == 0 {
				ok = true
			}
		}
		r.check(ok, "空数组 [] → 200 且返回 []", fmt.Sprintf("status=%d body=%s", status, clip(raw, 200)))
	}

	status, raw, err = doJSON(client, http.MethodPost, url, []inputItem{
		{"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
	})
	if err != nil {
		r.check(false, "单条数组", err.Error())
	} else {
		var parsed []map[string]any
		ok := status == 200 && json.Unmarshal(raw, &parsed) == nil && len(parsed) == 1
		if ok {
			ok = normLower(parsed[0]["protocol"]) == "ssh"
		}
		r.check(ok, "单条数组也能识别 SSH", fmt.Sprintf("status=%d body=%s", status, clip(raw, 200)))
	}

	status, raw, err = doRaw(client, url, []byte{}, "application/json")
	if err != nil {
		r.check(true, "空 body 被拒绝但进程仍在", err.Error())
	} else {
		r.check(status > 0 && status < 500, fmt.Sprintf("空 body 不能 5xx（实际 %d）", status), clip(raw, 200))
	}

	status, raw, err = doRaw(client, url, []byte("{not-json"), "application/json")
	if err != nil {
		r.check(true, "非法 JSON 被拒绝但进程仍在", err.Error())
	} else {
		r.check(status > 0 && status < 500, fmt.Sprintf("非法 JSON 不能 5xx（实际 %d）", status), clip(raw, 200))
	}

	status, raw, err = doJSON(client, http.MethodPost, url, inputItem{
		"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1",
	})
	if err != nil {
		r.check(true, "对象 body 被拒绝但进程仍在", err.Error())
	} else {
		r.check(status < 500, fmt.Sprintf("误传对象而不是数组，不能 5xx（实际 %d）", status), clip(raw, 200))
	}

	big := make([]inputItem, 200)
	for i := range big {
		big[i] = inputItem{
			"ip":     fmt.Sprintf("11.0.%d.%d", i/256, i%256),
			"port":   80,
			"banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0",
		}
	}
	bigClient := &http.Client{Timeout: maxDuration(timeout, 30*time.Second)}
	start := time.Now()
	status, raw, err = doJSON(bigClient, http.MethodPost, url, big)
	elapsed := time.Since(start)
	if err != nil {
		r.check(false, "200 条批量识别", err.Error())
	} else {
		var parsed []map[string]any
		ok := status == 200 && json.Unmarshal(raw, &parsed) == nil && len(parsed) == 200
		if ok {
			for _, item := range parsed {
				if normLower(item["protocol"]) != "http" {
					ok = false
					break
				}
			}
		}
		r.check(ok, fmt.Sprintf("200 条批量识别（%.2fs）", elapsed.Seconds()), fmt.Sprintf("status=%d", status))
	}

	status, raw, err = doJSON(client, http.MethodPost, url, []inputItem{
		{"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
		{"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
	})
	if err != nil {
		r.check(false, "重复输入", err.Error())
	} else {
		var parsed []map[string]any
		ok := status == 200 && json.Unmarshal(raw, &parsed) == nil && len(parsed) == 2
		r.check(ok, "完全重复的两条输入仍返回两条", fmt.Sprintf("status=%d", status))
	}

	mix := []inputItem{
		{"ip": "8.8.8.1", "port": 25, "banner": "220 mail.example.com ESMTP Postfix"},
		{"ip": "8.8.8.2", "port": 5432, "banner": `FATAL:  password authentication failed for user "postgres"`},
		{"ip": "8.8.8.3", "port": 5900, "banner": "RFB 003.008\n"},
		{"ip": "8.8.8.4", "port": 6379, "banner": "+PONG"},
		{"ip": "8.8.8.5", "port": 5060, "banner": "SIP/2.0 200 OK\r\nServer: Asterisk PBX 18.12.0"},
		{"ip": "8.8.8.6", "port": 110, "banner": "+OK Dovecot ready."},
	}
	status, raw, err = doJSON(client, http.MethodPost, url, mix)
	if err != nil {
		r.check(false, "混合协议小批量", err.Error())
	} else {
		var parsed []map[string]any
		ok := status == 200 && json.Unmarshal(raw, &parsed) == nil && len(parsed) == len(mix)
		if ok {
			want := [][]string{
				{"smtp"},
				{"postgresql", "pgsql", "postgres"},
				{"vnc"},
				{"redis"},
				{"sip"},
				{"pop3"},
			}
			for i, item := range parsed {
				if !inFold(item["protocol"], want[i]) {
					ok = false
					r.check(false, "混合协议小批量", fmt.Sprintf("[%d] protocol=%v 期望 %v", i, item["protocol"], want[i]))
					break
				}
			}
		}
		if ok {
			r.check(true, "混合协议小批量（SMTP/PostgreSQL/VNC/Redis/SIP/POP3）", "")
		} else if status != 200 || len(parsed) != len(mix) {
			r.check(false, "混合协议小批量", fmt.Sprintf("status=%d n=%d", status, len(parsed)))
		}
	}
}

func clip(b []byte, n int) string {
	s := string(b)
	if len(s) > n {
		return s[:n]
	}
	return s
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func printOfflineCatalog() {
	fmt.Printf("共 %d 条识别用例：\n\n", len(identifyCases))
	current := ""
	for _, c := range identifyCases {
		if c.Group != current {
			current = c.Group
			fmt.Printf("[%s]\n", current)
		}
		fmt.Printf("  - %s: %s\n", c.ID, c.Name)
	}
}

func writeDump(path string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(dumpInputs(), "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o644)
}

func main() {
	url := flag.String("url", envOr("FINGERPRINT_URL", "http://127.0.0.1:8080"), "服务根地址")
	timeout := flag.Duration("timeout", 10*time.Second, "单次请求超时")
	dump := flag.String("dump", "", "把识别用例 input 导出为 client 可用 JSON")
	offline := flag.Bool("offline", false, "不访问服务，只打印用例清单")
	flag.Parse()

	if *dump != "" {
		if err := writeDump(*dump); err != nil {
			fmt.Fprintln(os.Stderr, "导出失败:", err)
			os.Exit(1)
		}
		fmt.Printf("已导出 %d 条 input → %s\n", len(identifyCases), *dump)
		if *offline {
			return
		}
	}
	if *offline {
		printOfflineCatalog()
		return
	}

	base := strings.TrimRight(*url, "/")
	fmt.Printf("目标服务: %s\n识别用例: %d 条\n", base, len(identifyCases))

	client := &http.Client{Timeout: *timeout}
	rep := &reporter{}
	runHealth(client, base, rep)
	runIdentify(client, base, rep)
	runAPIContract(client, base, *timeout, rep)

	fmt.Println("\n== 汇总 ==")
	total := rep.passed + rep.failed
	fmt.Printf("通过 %d/%d，失败 %d\n", rep.passed, total, rep.failed)
	if rep.failed > 0 {
		fmt.Println("\n失败明细：")
		for _, e := range rep.errors {
			fmt.Println("  -", e)
		}
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
