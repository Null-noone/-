#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Banner 指纹识别系统 — 边界值 / 特殊情况测试脚本

覆盖维度
  A. 基础协议变体（SSH/HTTP/MySQL/Redis/FTP）
  B. 空值、缺字段、非法 IP / 端口（服务不能崩，认不出则 protocol=unknown）
  C. 二进制、转义串、超长、注入类 banner（服务不能崩）
  D. 易混淆协议（SMTP 的 220 vs FTP、TLS ClientHello、裸 QUIT）
  E. API 契约（空数组、非法 JSON、超大批次、响应 schema）
  F. 扩展应用层协议（SMTP/POP3/IMAP、PostgreSQL、Mongo/Memcached/MSSQL/Oracle、
     ES/CouchDB、Telnet/RDP/VNC、MQTT/AMQP、LDAP/SIP/RTSP/SMB/Rsync、
     Docker/K8s/etcd、NNTP/IRC/XMPP 等）
  G. 扩展协议变体与交叉误判

用法
  python scripts/test_edge_cases.py
  python scripts/test_edge_cases.py --url http://127.0.0.1:8080
  python scripts/test_edge_cases.py --dump testdata/edge_cases.json
  python scripts/test_edge_cases.py --offline
  python scripts/test_edge_cases.py --timeout 15

依赖：仅 Python 3 标准库。服务需已启动（默认 http://127.0.0.1:8080）。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any

# ---------------------------------------------------------------------------
# 识别用例：会作为一批 POST /fingerprint 发出
# expect 只校验给出的字段；未写的字段不强制（给实现留空间）
# protocol / product 大小写不敏感；version / os_hint 做子串匹配
# ---------------------------------------------------------------------------

IDENTIFY_CASES: list[dict[str, Any]] = [
    # ---------- A. 必识别协议：正常变体 ----------
    {
        "id": "ssh-ubuntu-standard",
        "group": "A-必识别变体",
        "name": "SSH OpenSSH + Ubuntu 发行版后缀",
        "input": {"ip": "10.1.0.1", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
        "expect": {
            "protocol": "SSH",
            "product": "OpenSSH",
            "version": "8.9p1",
            "os_hint": "Ubuntu",
        },
    },
    {
        "id": "ssh-debian",
        "group": "A-必识别变体",
        "name": "SSH OpenSSH + Debian",
        "input": {"ip": "10.1.0.2", "port": 22, "banner": "SSH-2.0-OpenSSH_9.3 Debian-1"},
        "expect": {
            "protocol": "SSH",
            "product": "OpenSSH",
            "version": "9.3",
            "os_hint": "Debian",
        },
    },
    {
        "id": "ssh-legacy-1.99",
        "group": "A-必识别变体",
        "name": "SSH-1.99 老协议标识",
        "input": {"ip": "10.1.0.3", "port": 22, "banner": "SSH-1.99-OpenSSH_4.3"},
        "expect": {"protocol": "SSH", "product": "OpenSSH", "version": "4.3"},
    },
    {
        "id": "ssh-lowercase",
        "group": "A-必识别变体",
        "name": "SSH banner 全小写",
        "input": {"ip": "10.1.0.4", "port": 22, "banner": "ssh-2.0-openssh_8.2p1"},
        "expect": {"protocol": "SSH", "product": "OpenSSH", "version": "8.2p1"},
    },
    {
        "id": "ssh-extra-spaces",
        "group": "A-必识别变体",
        "name": "SSH banner 多余空白 / 回车",
        "input": {"ip": "10.1.0.5", "port": 22, "banner": "  SSH-2.0-OpenSSH_8.9p1 Ubuntu-3  \r\n"},
        "expect": {"protocol": "SSH", "product": "OpenSSH", "version": "8.9p1", "os_hint": "Ubuntu"},
    },
    {
        "id": "ssh-nonstandard-port",
        "group": "A-必识别变体",
        "name": "SSH 开在 2222，端口不能压过 banner",
        "input": {"ip": "10.1.0.6", "port": 2222, "banner": "SSH-2.0-OpenSSH_8.0"},
        "expect": {"protocol": "SSH", "product": "OpenSSH", "version": "8.0"},
    },
    {
        "id": "http-nginx-crlf",
        "group": "A-必识别变体",
        "name": "HTTP nginx 标准 Server 头",
        "input": {
            "ip": "10.1.0.7",
            "port": 80,
            "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html",
        },
        "expect": {"protocol": "HTTP", "product": "nginx", "version": "1.24.0"},
    },
    {
        "id": "http-nginx-ubuntu-paren",
        "group": "A-必识别变体",
        "name": "HTTP nginx 版本后带 (Ubuntu)",
        "input": {
            "ip": "10.1.0.8",
            "port": 80,
            "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)",
        },
        "expect": {
            "protocol": "HTTP",
            "product": "nginx",
            "version": "1.18.0",
            "os_hint": "Ubuntu",
        },
    },
    {
        "id": "http-nginx-no-space",
        "group": "A-必识别变体",
        "name": "Server 头无空格 / 小写",
        "input": {
            "ip": "10.1.0.9",
            "port": 8443,
            "banner": "HTTP/1.1 200 OK\r\nserver:nginx/1.25.3",
        },
        "expect": {"protocol": "HTTP", "product": "nginx", "version": "1.25.3"},
    },
    {
        "id": "http-apache-modules",
        "group": "A-必识别变体",
        "name": "Apache 版本后跟模块串",
        "input": {
            "ip": "10.1.0.10",
            "port": 443,
            "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Unix) OpenSSL/1.1.1 PHP/8.1.0",
        },
        "expect": {"protocol": "HTTP", "product": "Apache", "version": "2.4.57"},
    },
    {
        "id": "http-apache-ubuntu",
        "group": "A-必识别变体",
        "name": "Apache + Ubuntu",
        "input": {
            "ip": "10.1.0.11",
            "port": 443,
            "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)",
        },
        "expect": {
            "protocol": "HTTP",
            "product": "Apache",
            "version": "2.4.41",
            "os_hint": "Ubuntu",
        },
    },
    {
        "id": "http-jetty-slash",
        "group": "A-必识别变体",
        "name": "Jetty 斜杠版本",
        "input": {
            "ip": "10.1.0.12",
            "port": 8080,
            "banner": "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51",
        },
        "expect": {"protocol": "HTTP", "product": "Jetty", "version": "9.4.51"},
    },
    {
        "id": "http-jetty-paren-build",
        "group": "A-必识别变体",
        "name": "Jetty 官方括号+构建号格式",
        "input": {
            "ip": "10.1.0.13",
            "port": 8080,
            "banner": "HTTP/1.1 200 OK\r\nServer: Jetty(9.4.51.v20230217)",
        },
        "expect": {"protocol": "HTTP", "product": "Jetty", "version": "9.4.51"},
    },
    {
        "id": "http-iis",
        "group": "A-必识别变体",
        "name": "Microsoft-IIS（HTTP 家族，product 应能拆出）",
        "input": {
            "ip": "10.1.0.14",
            "port": 8888,
            "banner": "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0",
        },
        "expect": {"protocol": "HTTP", "product": "IIS", "version": "10.0"},
    },
    {
        "id": "http-no-server-header",
        "group": "A-必识别变体",
        "name": "HTTP 状态行在，但没有 Server 头",
        "input": {
            "ip": "10.1.0.15",
            "port": 80,
            "banner": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>",
        },
        "expect": {"protocol": "HTTP"},
    },
    {
        "id": "http-http10",
        "group": "A-必识别变体",
        "name": "HTTP/1.0",
        "input": {
            "ip": "10.1.0.16",
            "port": 80,
            "banner": "HTTP/1.0 200 OK\r\nServer: nginx/1.14.0",
        },
        "expect": {"protocol": "HTTP", "product": "nginx", "version": "1.14.0"},
    },
    {
        "id": "mysql-escaped-8032",
        "group": "A-必识别变体",
        "name": "MySQL handshake 字面 \\x00 转义（扫描器常见）",
        "input": {"ip": "10.1.0.17", "port": 3306, "banner": "J\\x00\\x00\\x00\\n8.0.32\\x00"},
        "expect": {"protocol": "MySQL", "product": "MySQL", "version": "8.0.32"},
    },
    {
        "id": "mysql-escaped-5742",
        "group": "A-必识别变体",
        "name": "MySQL 5.7 字面转义",
        "input": {"ip": "10.1.0.18", "port": 3306, "banner": "J\\x00\\x00\\x00\\n5.7.42\\x00"},
        "expect": {"protocol": "MySQL", "product": "MySQL", "version": "5.7.42"},
    },
    {
        "id": "mysql-real-nulls",
        "group": "A-必识别变体",
        "name": "MySQL handshake 真实 NUL 字节",
        "input": {"ip": "10.1.0.19", "port": 3306, "banner": "J\x00\x00\x00\n8.0.36\x00"},
        "expect": {"protocol": "MySQL", "product": "MySQL", "version": "8.0.36"},
    },
    {
        "id": "mysql-mariadb",
        "group": "A-必识别变体",
        "name": "MariaDB 伪装 MySQL 版本前缀 5.5.5-",
        "input": {
            "ip": "10.1.0.20",
            "port": 3306,
            "banner": "J\\x00\\x00\\x00\\n5.5.5-10.6.12-MariaDB\\x00",
        },
        "expect": {"protocol": "MySQL", "version": "10.6.12"},
    },
    {
        "id": "redis-err-arity",
        "group": "A-必识别变体",
        "name": "Redis -ERR 参数个数错误",
        "input": {
            "ip": "10.1.0.21",
            "port": 6379,
            "banner": "-ERR wrong number of arguments for 'get' command",
        },
        "expect": {"protocol": "Redis", "product": "Redis"},
    },
    {
        "id": "redis-pong",
        "group": "A-必识别变体",
        "name": "Redis +PONG",
        "input": {"ip": "10.1.0.22", "port": 6379, "banner": "+PONG"},
        "expect": {"protocol": "Redis", "product": "Redis"},
    },
    {
        "id": "redis-noauth",
        "group": "A-必识别变体",
        "name": "Redis -NOAUTH",
        "input": {"ip": "10.1.0.23", "port": 6379, "banner": "-NOAUTH Authentication required."},
        "expect": {"protocol": "Redis", "product": "Redis"},
    },
    {
        "id": "redis-denied-protected",
        "group": "A-必识别变体",
        "name": "Redis 保护模式 DENIED",
        "input": {
            "ip": "10.1.0.24",
            "port": 6379,
            "banner": "-DENIED Redis is running in protected mode",
        },
        "expect": {"protocol": "Redis", "product": "Redis"},
    },
    {
        "id": "redis-ok",
        "group": "A-必识别变体",
        "name": "Redis +OK",
        "input": {"ip": "10.1.0.25", "port": 6380, "banner": "+OK"},
        "expect": {"protocol": "Redis", "product": "Redis"},
    },
    {
        "id": "ftp-proftpd",
        "group": "A-必识别变体",
        "name": "FTP ProFTPD",
        "input": {"ip": "10.1.0.26", "port": 21, "banner": "220 ProFTPD 1.3.7 Server (ProFTPD)"},
        "expect": {"protocol": "FTP", "product": "ProFTPD", "version": "1.3.7"},
    },
    {
        "id": "ftp-vsftpd",
        "group": "A-必识别变体",
        "name": "FTP vsFTPd 括号版本",
        "input": {"ip": "10.1.0.27", "port": 21, "banner": "220 (vsFTPd 3.0.5)"},
        "expect": {"protocol": "FTP", "product": "vsFTPd", "version": "3.0.5"},
    },
    {
        "id": "ftp-pureftpd-no-ver",
        "group": "A-必识别变体",
        "name": "FTP Pure-FTPd 无版本",
        "input": {"ip": "10.1.0.28", "port": 21, "banner": "220 Welcome to Pure-FTPd"},
        "expect": {"protocol": "FTP", "product": "Pure-FTPd"},
    },
    {
        "id": "ftp-filezilla",
        "group": "A-必识别变体",
        "name": "FTP FileZilla Server",
        "input": {
            "ip": "10.1.0.29",
            "port": 21,
            "banner": "220-FileZilla Server 1.6.7\r\n220 Please visit https://filezilla-project.org/",
        },
        "expect": {"protocol": "FTP", "product": "FileZilla", "version": "1.6.7"},
    },
    # ---------- B. 空值 / 缺字段 / 非法地址 ----------
    {
        "id": "empty-banner",
        "group": "B-空值缺字段",
        "name": "空 banner → unknown，不能崩",
        "input": {"ip": "10.2.0.1", "port": 80, "banner": ""},
        "expect": {"protocol": "unknown"},
    },
    {
        "id": "whitespace-banner",
        "group": "B-空值缺字段",
        "name": "仅空白 banner",
        "input": {"ip": "10.2.0.2", "port": 80, "banner": "   \t\r\n  "},
        "expect": {"protocol": "unknown"},
    },
    {
        "id": "missing-banner-field",
        "group": "B-空值缺字段",
        "name": "缺 banner 字段",
        "input": {"ip": "10.2.0.3", "port": 22},
        "expect": {"protocol": "unknown"},
    },
    {
        "id": "missing-ip",
        "group": "B-空值缺字段",
        "name": "缺 ip 字段（仍应返回一条结果或 unknown）",
        "input": {"port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1"},
        "expect": {"protocol": "SSH", "product": "OpenSSH"},
    },
    {
        "id": "empty-ip",
        "group": "B-空值缺字段",
        "name": "ip 为空字符串",
        "input": {"ip": "", "port": 22, "banner": "SSH-2.0-OpenSSH_9.0"},
        "expect": {"protocol": "SSH", "product": "OpenSSH"},
    },
    {
        "id": "invalid-ip-text",
        "group": "B-空值缺字段",
        "name": "ip 不是地址",
        "input": {"ip": "not-an-ip", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"},
        "expect": {"protocol": "HTTP", "product": "nginx"},
    },
    {
        "id": "port-zero",
        "group": "B-空值缺字段",
        "name": "port=0 但 banner 是 SSH",
        "input": {"ip": "10.2.0.4", "port": 0, "banner": "SSH-2.0-OpenSSH_8.9p1"},
        "expect": {"protocol": "SSH", "product": "OpenSSH"},
    },
    {
        "id": "port-65535",
        "group": "B-空值缺字段",
        "name": "port=65535 边界合法值",
        "input": {"ip": "10.2.0.5", "port": 65535, "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"},
        "expect": {"protocol": "HTTP", "product": "nginx"},
    },
    {
        "id": "port-out-of-range",
        "group": "B-空值缺字段",
        "name": "port=65536 非法，不能崩",
        "input": {"ip": "10.2.0.6", "port": 65536, "banner": "SSH-2.0-OpenSSH_8.9p1"},
        "expect": {"protocol": "SSH"},
    },
    {
        "id": "port-negative",
        "group": "B-空值缺字段",
        "name": "port=-1，不能崩",
        "input": {"ip": "10.2.0.7", "port": -1, "banner": "+PONG"},
        "expect": {"protocol": "Redis"},
    },
    {
        "id": "ipv6",
        "group": "B-空值缺字段",
        "name": "IPv6 地址",
        "input": {
            "ip": "2001:db8::1",
            "port": 22,
            "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
        },
        "expect": {"protocol": "SSH", "product": "OpenSSH", "os_hint": "Ubuntu"},
    },
    {
        "id": "extra-unknown-fields",
        "group": "B-空值缺字段",
        "name": "输入多未知字段应被忽略",
        "input": {
            "ip": "10.2.0.8",
            "port": 80,
            "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0",
            "ttl": 64,
            "raw": "xxxx",
            "note": "ignore-me",
        },
        "expect": {"protocol": "HTTP", "product": "nginx", "version": "1.24.0"},
    },
    # ---------- C. 二进制 / 超长 / 注入 ----------
    {
        "id": "tls-clienthello-16-03-01",
        "group": "C-二进制超长注入",
        "name": "TLS ClientHello 记录头（可识别为 TLS 或 unknown，但不能当 HTTP/SSH）",
        "input": {"ip": "10.3.0.1", "port": 9999, "banner": "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"},
        "expect": {"protocol_not_in": ["SSH", "HTTP", "FTP", "MySQL", "Redis"]},
    },
    {
        "id": "tls-literal-escape",
        "group": "C-二进制超长注入",
        "name": "TLS 被扫描器写成字面 \\x16\\x03\\x01",
        "input": {"ip": "10.3.0.2", "port": 443, "banner": "\\x16\\x03\\x01\\x00\\xa5\\x01\\x00\\x00\\xa1"},
        "expect": {"protocol_not_in": ["SSH", "HTTP", "FTP", "MySQL", "Redis"]},
    },
    {
        "id": "banner-with-quotes-and-backslash",
        "group": "C-二进制超长注入",
        "name": "banner 含引号、反斜杠",
        "input": {
            "ip": "10.3.0.3",
            "port": 80,
            "banner": 'HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nX-Req: "a\\b"',
        },
        "expect": {"protocol": "HTTP", "product": "nginx"},
    },
    {
        "id": "banner-html-xss",
        "group": "C-二进制超长注入",
        "name": "banner 含 HTML/脚本片段，不能当解析错误",
        "input": {
            "ip": "10.3.0.4",
            "port": 80,
            "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57\r\n\r\n<script>alert(1)</script>",
        },
        "expect": {"protocol": "HTTP", "product": "Apache", "version": "2.4.57"},
    },
    {
        "id": "banner-format-string",
        "group": "C-二进制超长注入",
        "name": "格式化串 %s%s%n",
        "input": {"ip": "10.3.0.5", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 %s%s%n"},
        "expect": {"protocol": "SSH", "product": "OpenSSH"},
    },
    {
        "id": "banner-unicode",
        "group": "C-二进制超长注入",
        "name": "Server 头附近有中文/emoji",
        "input": {
            "ip": "10.3.0.6",
            "port": 80,
            "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nX-Msg: 测试🚀",
        },
        "expect": {"protocol": "HTTP", "product": "nginx", "version": "1.24.0"},
    },
    {
        "id": "banner-very-long",
        "group": "C-二进制超长注入",
        "name": "超长 banner（约 64KB 垃圾 + 有效 Server 头）",
        "input": {
            "ip": "10.3.0.7",
            "port": 80,
            "banner": "HTTP/1.1 200 OK\r\nX-Pad: "
            + ("A" * 65536)
            + "\r\nServer: nginx/1.24.0\r\n",
        },
        "expect": {"protocol": "HTTP", "product": "nginx", "version": "1.24.0"},
    },
    {
        "id": "banner-null-in-middle",
        "group": "C-二进制超长注入",
        "name": "HTTP banner 中间插入 NUL",
        "input": {
            "ip": "10.3.0.8",
            "port": 80,
            "banner": "HTTP/1.1 200 OK\r\nSer\x00ver: nginx/1.24.0",
        },
        "expect": {"protocol": "HTTP"},
    },
    # ---------- D. 易混淆 / 应 unknown ----------
    {
        "id": "smtp-not-ftp",
        "group": "D-易混淆",
        "name": "SMTP 220 ESMTP 必须识别为 SMTP，不能当 FTP",
        "input": {
            "ip": "10.4.0.1",
            "port": 25,
            "banner": "220 mail.example.com ESMTP Postfix",
        },
        "expect": {
            "protocol": "SMTP",
            "product": "Postfix",
            "protocol_not_in": ["FTP", "SSH", "HTTP", "MySQL", "Redis"],
        },
    },
    {
        "id": "bare-220",
        "group": "D-易混淆",
        "name": "裸 220 无产品名：允许 FTP 或 unknown，但不能崩",
        "input": {"ip": "10.4.0.2", "port": 21, "banner": "220"},
        "expect": {"protocol_in": ["FTP", "unknown"]},
    },
    {
        "id": "quit-crlf",
        "group": "D-易混淆",
        "name": "裸 QUIT（题目自测）必须 unknown",
        "input": {"ip": "10.4.0.3", "port": 12345, "banner": "QUIT\r\n"},
        "expect": {"protocol": "unknown"},
    },
    {
        "id": "html-without-http",
        "group": "D-易混淆",
        "name": "只有 HTML 没有 HTTP 状态行",
        "input": {
            "ip": "10.4.0.4",
            "port": 80,
            "banner": "<!DOCTYPE html><html><head><title>nginx</title></head></html>",
        },
        "expect": {"protocol_in": ["HTTP", "unknown"]},
    },
    {
        "id": "multi-product-server",
        "group": "D-易混淆",
        "name": "Server 头同时出现 nginx 和 Apache，应能给出一个主产品且不崩",
        "input": {
            "ip": "10.4.0.5",
            "port": 80,
            "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 Apache/2.4.57",
        },
        "expect": {"protocol": "HTTP", "product_in": ["nginx", "Apache"]},
    },
    {
        "id": "postgres",
        "group": "D-易混淆",
        "name": "PostgreSQL 二进制 FATAL 必须识别，且不能当 MySQL",
        "input": {
            "ip": "10.4.0.6",
            "port": 5432,
            "banner": "E\x00\x00\x00\x4eSFATAL\x00C28P01\x00Mpassword authentication failed",
        },
        "expect": {
            "protocol_in": ["PostgreSQL", "PGSQL", "Postgres"],
            "protocol_not_in": ["MySQL", "Redis", "SSH", "FTP"],
        },
    },
    {
        "id": "dropbear-ssh",
        "group": "D-易混淆",
        "name": "Dropbear SSH（非 OpenSSH）",
        "input": {"ip": "10.4.0.7", "port": 22, "banner": "SSH-2.0-dropbear_2020.81"},
        "expect": {"protocol": "SSH", "product": "dropbear", "version": "2020.81"},
    },
    {
        "id": "http2-preface",
        "group": "D-易混淆",
        "name": "HTTP/2 连接前言",
        "input": {"ip": "10.4.0.8", "port": 443, "banner": "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"},
        "expect": {"protocol_in": ["HTTP", "HTTP2", "unknown"]},
    },
    {
        "id": "banner-looks-like-json",
        "group": "D-易混淆",
        "name": "banner 本身是 JSON",
        "input": {
            "ip": "10.4.0.9",
            "port": 8080,
            "banner": '{"error":"not found","server":"nginx/1.24.0"}',
        },
        "expect": {"protocol_in": ["HTTP", "unknown"]},
    },
    {
        "id": "ssh-looks-http-later",
        "group": "D-易混淆",
        "name": "先 SSH 行再跟一段 HTTP，主体应是 SSH",
        "input": {
            "ip": "10.4.0.10",
            "port": 22,
            "banner": "SSH-2.0-OpenSSH_8.9p1\r\nHTTP/1.1 400 Bad Request",
        },
        "expect": {"protocol": "SSH", "product": "OpenSSH"},
    },

    # ---------- F. 扩展应用层协议 ----------
    {
        "id": "smtp-exim",
        "group": "F-扩展协议-邮件",
        "name": "SMTP Exim",
        "input": {"ip": "10.5.0.1", "port": 25, "banner": "220 mx.example.com ESMTP Exim 4.96"},
        "expect": {"protocol": "SMTP", "product": "Exim", "version": "4.96"},
    },
    {
        "id": "smtp-sendmail",
        "group": "F-扩展协议-邮件",
        "name": "SMTP Sendmail",
        "input": {"ip": "10.5.0.2", "port": 25, "banner": "220 mail.example.com ESMTP Sendmail 8.17.1/8.17.1"},
        "expect": {"protocol": "SMTP", "product": "Sendmail", "version": "8.17.1"},
    },
    {
        "id": "smtp-microsoft",
        "group": "F-扩展协议-邮件",
        "name": "SMTP Microsoft ESMTP",
        "input": {
            "ip": "10.5.0.3",
            "port": 25,
            "banner": "220 EXCH01.contoso.com Microsoft ESMTP MAIL Service ready at Tue, 22 Sep 2026 10:00:00 +0800",
        },
        "expect": {"protocol": "SMTP", "product_in": ["Microsoft", "Exchange", "ESMTP"]},
    },
    {
        "id": "smtp-submission-587",
        "group": "F-扩展协议-邮件",
        "name": "SMTP 开在 587（submission），端口不能压过 banner",
        "input": {"ip": "10.5.0.4", "port": 587, "banner": "220 mail.example.com ESMTP Postfix (Ubuntu)"},
        "expect": {"protocol": "SMTP", "product": "Postfix", "os_hint": "Ubuntu"},
    },
    {
        "id": "smtp-multiline-220",
        "group": "F-扩展协议-邮件",
        "name": "SMTP 多行 220-",
        "input": {
            "ip": "10.5.0.5",
            "port": 25,
            "banner": "220-mail.example.com ESMTP Exim 4.94.2\r\n220-TLS is available\r\n220 End",
        },
        "expect": {"protocol": "SMTP", "product": "Exim", "version": "4.94.2"},
    },
    {
        "id": "smtp-lowercase",
        "group": "F-扩展协议-邮件",
        "name": "SMTP banner 小写 esmtp",
        "input": {"ip": "10.5.0.6", "port": 25, "banner": "220 mx.example.net esmtp postfix"},
        "expect": {"protocol": "SMTP", "product": "Postfix"},
    },
    {
        "id": "smtp-hostname-has-ftp",
        "group": "F-扩展协议-邮件",
        "name": "主机名含 ftp 但 ESMTP 仍是 SMTP",
        "input": {"ip": "10.5.0.7", "port": 25, "banner": "220 ftp.example.com ESMTP Postfix"},
        "expect": {"protocol": "SMTP", "product": "Postfix", "protocol_not_in": ["FTP"]},
    },
    {
        "id": "pop3-dovecot",
        "group": "F-扩展协议-邮件",
        "name": "POP3 Dovecot",
        "input": {"ip": "10.5.0.8", "port": 110, "banner": "+OK Dovecot ready."},
        "expect": {"protocol": "POP3", "product": "Dovecot", "protocol_not_in": ["Redis"]},
    },
    {
        "id": "pop3-exchange",
        "group": "F-扩展协议-邮件",
        "name": "POP3 Microsoft Exchange",
        "input": {"ip": "10.5.0.9", "port": 110, "banner": "+OK Microsoft Exchange POP3 server ready"},
        "expect": {"protocol": "POP3", "product_in": ["Exchange", "Microsoft"]},
    },
    {
        "id": "imap-dovecot-debian",
        "group": "F-扩展协议-邮件",
        "name": "IMAP Dovecot + Debian",
        "input": {
            "ip": "10.5.0.10",
            "port": 143,
            "banner": "* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS] Dovecot (Debian) ready.",
        },
        "expect": {"protocol": "IMAP", "product": "Dovecot", "os_hint": "Debian"},
    },
    {
        "id": "imap-cyrus",
        "group": "F-扩展协议-邮件",
        "name": "IMAP Cyrus",
        "input": {
            "ip": "10.5.0.11",
            "port": 143,
            "banner": "* OK [CAPABILITY IMAP4rev1] Cyrus IMAP v3.6.1 server ready",
        },
        "expect": {"protocol": "IMAP", "product": "Cyrus", "version": "3.6.1"},
    },
    {
        "id": "pgsql-fatal-text",
        "group": "F-扩展协议-数据库",
        "name": "PostgreSQL 文本 FATAL 认证失败",
        "input": {
            "ip": "10.6.0.1",
            "port": 5432,
            "banner": 'FATAL:  password authentication failed for user "postgres"',
        },
        "expect": {
            "protocol_in": ["PostgreSQL", "PGSQL", "Postgres"],
            "protocol_not_in": ["MySQL"],
        },
    },
    {
        "id": "pgsql-no-hba",
        "group": "F-扩展协议-数据库",
        "name": "PostgreSQL 无 pg_hba.conf 条目",
        "input": {
            "ip": "10.6.0.2",
            "port": 5432,
            "banner": 'FATAL:  no pg_hba.conf entry for host "10.6.0.2", user "app", database "app"',
        },
        "expect": {"protocol_in": ["PostgreSQL", "PGSQL", "Postgres"]},
    },
    {
        "id": "pgsql-unsupported-frontend",
        "group": "F-扩展协议-数据库",
        "name": "PostgreSQL 不支持的前端协议",
        "input": {
            "ip": "10.6.0.3",
            "port": 5432,
            "banner": "FATAL:  unsupported frontend protocol 0.0: server supports 3.0 to 3.0",
        },
        "expect": {"protocol_in": ["PostgreSQL", "PGSQL", "Postgres"]},
    },
    {
        "id": "pgsql-nonstandard-port",
        "group": "F-扩展协议-数据库",
        "name": "PostgreSQL 开在 15432",
        "input": {
            "ip": "10.6.0.4",
            "port": 15432,
            "banner": 'FATAL:  password authentication failed for user "app"',
        },
        "expect": {"protocol_in": ["PostgreSQL", "PGSQL", "Postgres"]},
    },
    {
        "id": "mongodb-http-native-port",
        "group": "F-扩展协议-数据库",
        "name": "MongoDB 原生端口误用 HTTP",
        "input": {
            "ip": "10.6.0.5",
            "port": 27017,
            "banner": "It looks like you are trying to access MongoDB over HTTP on the native driver port.",
        },
        "expect": {"protocol_in": ["MongoDB", "Mongo"], "protocol_not_in": ["HTTP"]},
    },
    {
        "id": "mongodb-json-errmsg",
        "group": "F-扩展协议-数据库",
        "name": "MongoDB JSON 错误",
        "input": {
            "ip": "10.6.0.6",
            "port": 27017,
            "banner": '{"ok":0,"errmsg":"no such cmd: foo","code":59,"codeName":"CommandNotFound"}',
        },
        "expect": {"protocol_in": ["MongoDB", "Mongo"]},
    },
    {
        "id": "memcached-version",
        "group": "F-扩展协议-数据库",
        "name": "Memcached VERSION",
        "input": {"ip": "10.6.0.7", "port": 11211, "banner": "VERSION 1.6.18\r\n"},
        "expect": {"protocol": "Memcached", "product": "Memcached", "version": "1.6.18"},
    },
    {
        "id": "memcached-stat",
        "group": "F-扩展协议-数据库",
        "name": "Memcached STAT",
        "input": {"ip": "10.6.0.8", "port": 11211, "banner": "STAT pid 1\r\nSTAT version 1.6.15\r\nEND\r\n"},
        "expect": {"protocol": "Memcached", "version": "1.6.15"},
    },
    {
        "id": "mssql-banner",
        "group": "F-扩展协议-数据库",
        "name": "Microsoft SQL Server",
        "input": {
            "ip": "10.6.0.9",
            "port": 1433,
            "banner": "Microsoft SQL Server 2019 (RTM-CU18) - 15.0.4261.1",
        },
        "expect": {
            "protocol_in": ["MSSQL", "SQLServer", "TDS"],
            "product_in": ["SQL Server", "MSSQL"],
            "version": "2019",
        },
    },
    {
        "id": "oracle-tns",
        "group": "F-扩展协议-数据库",
        "name": "Oracle TNS 错误描述",
        "input": {
            "ip": "10.6.0.10",
            "port": 1521,
            "banner": "(DESCRIPTION=(ERR=12514)(VSNNUM=318767104)(ERROR_STACK=(ERROR=(CODE=12514)(EMFI=4))))",
        },
        "expect": {"protocol_in": ["Oracle", "TNS"], "product_in": ["Oracle", "TNS"]},
    },
    {
        "id": "elasticsearch-tagline",
        "group": "F-扩展协议-数据库",
        "name": "Elasticsearch Welcome JSON",
        "input": {
            "ip": "10.6.0.11",
            "port": 9200,
            "banner": 'HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{"name":"es01","cluster_name":"docker-cluster","version":{"number":"8.11.1"},"tagline":"You Know, for Search"}',
        },
        "expect": {
            "protocol_in": ["Elasticsearch", "ES", "HTTP"],
            "product_in": ["Elasticsearch", "ES"],
            "version": "8.11.1",
        },
    },
    {
        "id": "couchdb-welcome",
        "group": "F-扩展协议-数据库",
        "name": "CouchDB Welcome JSON",
        "input": {
            "ip": "10.6.0.12",
            "port": 5984,
            "banner": 'HTTP/1.1 200 OK\r\nServer: CouchDB/3.3.2\r\n\r\n{"couchdb":"Welcome","version":"3.3.2"}',
        },
        "expect": {"protocol_in": ["CouchDB", "HTTP"], "product": "CouchDB", "version": "3.3.2"},
    },
    {
        "id": "cassandra-protocol",
        "group": "F-扩展协议-数据库",
        "name": "Cassandra 协议版本错误",
        "input": {
            "ip": "10.6.0.13",
            "port": 9042,
            "banner": "Invalid or unsupported protocol version (4); supported versions are (3/v3, 5/v5-beta)",
        },
        "expect": {"protocol": "Cassandra", "product": "Cassandra"},
    },
    {
        "id": "clickhouse-exception",
        "group": "F-扩展协议-数据库",
        "name": "ClickHouse 认证异常",
        "input": {
            "ip": "10.6.0.14",
            "port": 8123,
            "banner": "Code: 516. DB::Exception: default: Authentication failed: password is incorrect, or there is no user with such name. (AUTHENTICATION_FAILED)",
        },
        "expect": {"protocol": "ClickHouse", "product": "ClickHouse"},
    },
    {
        "id": "influxdb-header",
        "group": "F-扩展协议-数据库",
        "name": "InfluxDB HTTP 版本头",
        "input": {
            "ip": "10.6.0.15",
            "port": 8086,
            "banner": "HTTP/1.1 204 No Content\r\nX-Influxdb-Version: 1.8.10\r\nX-Influxdb-Build: OSS",
        },
        "expect": {"protocol_in": ["InfluxDB", "HTTP"], "product": "InfluxDB", "version": "1.8.10"},
    },
    {
        "id": "telnet-ubuntu-login",
        "group": "F-扩展协议-远程",
        "name": "Telnet Ubuntu 登录提示",
        "input": {"ip": "10.7.0.1", "port": 23, "banner": "Ubuntu 22.04.3 LTS\r\nlogin: "},
        "expect": {"protocol": "Telnet", "os_hint": "Ubuntu"},
    },
    {
        "id": "telnet-iac",
        "group": "F-扩展协议-远程",
        "name": "Telnet IAC 协商",
        "input": {"ip": "10.7.0.2", "port": 23, "banner": "\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27"},
        "expect": {"protocol": "Telnet"},
    },
    {
        "id": "rdp-tpkt",
        "group": "F-扩展协议-远程",
        "name": "RDP TPKT 头",
        "input": {
            "ip": "10.7.0.3",
            "port": 3389,
            "banner": "\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x00\x08\x00\x02\x00\x00\x00",
        },
        "expect": {"protocol": "RDP"},
    },
    {
        "id": "vnc-rfb-008",
        "group": "F-扩展协议-远程",
        "name": "VNC RFB 003.008",
        "input": {"ip": "10.7.0.4", "port": 5900, "banner": "RFB 003.008\n"},
        "expect": {"protocol": "VNC", "version": "003.008"},
    },
    {
        "id": "vnc-rfb-003",
        "group": "F-扩展协议-远程",
        "name": "VNC RFB 003.003",
        "input": {"ip": "10.7.0.5", "port": 5901, "banner": "RFB 003.003\n"},
        "expect": {"protocol": "VNC", "version": "003.003"},
    },
    {
        "id": "mqtt-connack",
        "group": "F-扩展协议-远程",
        "name": "MQTT CONNACK",
        "input": {"ip": "10.7.0.6", "port": 1883, "banner": "\x20\x02\x00\x00"},
        "expect": {"protocol": "MQTT"},
    },
    {
        "id": "amqp-header",
        "group": "F-扩展协议-远程",
        "name": "AMQP / RabbitMQ 协议头",
        "input": {"ip": "10.7.0.7", "port": 5672, "banner": "AMQP\x00\x00\x09\x01"},
        "expect": {"protocol_in": ["AMQP", "RabbitMQ"], "product_in": ["AMQP", "RabbitMQ"]},
    },
    {
        "id": "modbus-mbap",
        "group": "F-扩展协议-远程",
        "name": "Modbus TCP MBAP",
        "input": {"ip": "10.7.0.8", "port": 502, "banner": "\x00\x01\x00\x00\x00\x03\x01\x83\x01"},
        "expect": {"protocol": "Modbus"},
    },
    {
        "id": "ldap-bind-fail",
        "group": "F-扩展协议-基础设施",
        "name": "LDAP bind 失败文本",
        "input": {
            "ip": "10.8.0.1",
            "port": 389,
            "banner": "ldap_bind: Invalid credentials (49)\nadditional info: 80090308: LdapErr: DSID-0C090447",
        },
        "expect": {"protocol": "LDAP"},
    },
    {
        "id": "sip-asterisk",
        "group": "F-扩展协议-基础设施",
        "name": "SIP Asterisk",
        "input": {
            "ip": "10.8.0.2",
            "port": 5060,
            "banner": "SIP/2.0 200 OK\r\nServer: Asterisk PBX 18.12.0\r\nVia: SIP/2.0/UDP 10.8.0.9:5060",
        },
        "expect": {
            "protocol": "SIP",
            "product": "Asterisk",
            "version": "18.12.0",
            "protocol_not_in": ["HTTP"],
        },
    },
    {
        "id": "rtsp-vlc",
        "group": "F-扩展协议-基础设施",
        "name": "RTSP VLC",
        "input": {"ip": "10.8.0.3", "port": 554, "banner": "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: VLC/3.0.18"},
        "expect": {
            "protocol": "RTSP",
            "product": "VLC",
            "version": "3.0.18",
            "protocol_not_in": ["HTTP"],
        },
    },
    {
        "id": "socks5-noauth",
        "group": "F-扩展协议-基础设施",
        "name": "SOCKS5 无认证应答",
        "input": {"ip": "10.8.0.4", "port": 1080, "banner": "\x05\x00"},
        "expect": {"protocol_in": ["SOCKS", "SOCKS5"]},
    },
    {
        "id": "tls-serverhello",
        "group": "F-扩展协议-基础设施",
        "name": "TLS ServerHello 记录",
        "input": {"ip": "10.8.0.5", "port": 443, "banner": "\x16\x03\x03\x00\x3a\x02\x00\x00\x36\x03\x03"},
        "expect": {"protocol_in": ["TLS", "SSL"], "protocol_not_in": ["HTTP", "SSH", "FTP"]},
    },
    {
        "id": "smb-ntlm",
        "group": "F-扩展协议-基础设施",
        "name": "SMB 方言头 \\xffSMB",
        "input": {"ip": "10.8.0.6", "port": 445, "banner": "\xffSMB\x72\x00\x00\x00\x00"},
        "expect": {"protocol": "SMB"},
    },
    {
        "id": "rsyncd",
        "group": "F-扩展协议-基础设施",
        "name": "Rsync 守护进程问候",
        "input": {"ip": "10.8.0.7", "port": 873, "banner": "@RSYNCD: 31.0\n"},
        "expect": {"protocol": "Rsync", "version": "31.0"},
    },
    {
        "id": "zookeeper-stat",
        "group": "F-扩展协议-基础设施",
        "name": "ZooKeeper stat 版本行",
        "input": {
            "ip": "10.8.0.8",
            "port": 2181,
            "banner": "Zookeeper version: 3.8.0-e4d3d3, built on 2022-02-23 16:21 UTC\nLatency min/avg/max: 0/0/0",
        },
        "expect": {
            "protocol_in": ["ZooKeeper", "Zookeeper"],
            "product_in": ["ZooKeeper", "Zookeeper"],
            "version": "3.8.0",
        },
    },
    {
        "id": "irc-notice",
        "group": "F-扩展协议-基础设施",
        "name": "IRC NOTICE AUTH",
        "input": {
            "ip": "10.8.0.9",
            "port": 6667,
            "banner": ":irc.example.com NOTICE AUTH :*** Looking up your hostname",
        },
        "expect": {"protocol": "IRC"},
    },
    {
        "id": "nntp-ready",
        "group": "F-扩展协议-基础设施",
        "name": "NNTP 200 Ready",
        "input": {"ip": "10.8.0.10", "port": 119, "banner": "200 NNTP Service Ready, posting allowed"},
        "expect": {"protocol": "NNTP", "protocol_not_in": ["HTTP", "SMTP", "FTP"]},
    },
    {
        "id": "xmpp-stream",
        "group": "F-扩展协议-基础设施",
        "name": "XMPP stream 开场",
        "input": {
            "ip": "10.8.0.11",
            "port": 5222,
            "banner": "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' from='example.com' version='1.0'>",
        },
        "expect": {"protocol": "XMPP"},
    },
    {
        "id": "docker-api",
        "group": "F-扩展协议-基础设施",
        "name": "Docker API HTTP 头",
        "input": {
            "ip": "10.8.0.12",
            "port": 2375,
            "banner": "HTTP/1.1 200 OK\r\nApi-Version: 1.43\r\nDocker-Experimental: false\r\nServer: Docker/24.0.7 (linux)",
        },
        "expect": {"protocol_in": ["Docker", "HTTP"], "product": "Docker", "version": "24.0.7"},
    },
    {
        "id": "k8s-unauthorized",
        "group": "F-扩展协议-基础设施",
        "name": "Kubernetes API 401 JSON",
        "input": {
            "ip": "10.8.0.13",
            "port": 6443,
            "banner": 'HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{"kind":"Status","apiVersion":"v1","status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}',
        },
        "expect": {
            "protocol_in": ["Kubernetes", "K8s", "HTTP"],
            "product_in": ["Kubernetes", "K8s"],
        },
    },
    {
        "id": "etcd-version",
        "group": "F-扩展协议-基础设施",
        "name": "etcd version JSON",
        "input": {
            "ip": "10.8.0.14",
            "port": 2379,
            "banner": 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}',
        },
        "expect": {"protocol_in": ["etcd", "HTTP"], "product": "etcd", "version": "3.5.9"},
    },
    {
        "id": "consul-agent",
        "group": "F-扩展协议-基础设施",
        "name": "Consul agent JSON",
        "input": {
            "ip": "10.8.0.15",
            "port": 8500,
            "banner": 'HTTP/1.1 200 OK\r\nX-Consul-Index: 12\r\n\r\n{"Config":{"Datacenter":"dc1","NodeName":"consul-1","Version":"1.16.2"}}',
        },
        "expect": {"protocol_in": ["Consul", "HTTP"], "product": "Consul", "version": "1.16.2"},
    },
    {
        "id": "jenkins-header",
        "group": "F-扩展协议-基础设施",
        "name": "Jenkins X-Jenkins 头",
        "input": {
            "ip": "10.8.0.16",
            "port": 8080,
            "banner": "HTTP/1.1 200 OK\r\nX-Jenkins: 2.426.1\r\nX-Hudson: 1.395\r\nServer: Jetty(10.0.17)",
        },
        "expect": {"protocol": "HTTP", "product_in": ["Jenkins", "Jetty"]},
    },
    {
        "id": "ipp-cups",
        "group": "F-扩展协议-基础设施",
        "name": "IPP / CUPS",
        "input": {
            "ip": "10.8.0.17",
            "port": 631,
            "banner": "HTTP/1.1 200 OK\r\nServer: CUPS/2.4.2\r\nContent-Type: application/ipp",
        },
        "expect": {"protocol_in": ["IPP", "HTTP"], "product": "CUPS", "version": "2.4.2"},
    },
    {
        "id": "winrm-httpapi",
        "group": "F-扩展协议-基础设施",
        "name": "WinRM / Microsoft-HTTPAPI",
        "input": {
            "ip": "10.8.0.18",
            "port": 5985,
            "banner": "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\nWWW-Authenticate: Kerberos\r\nServer: Microsoft-HTTPAPI/2.0",
        },
        "expect": {
            "protocol_in": ["WinRM", "HTTP"],
            "product_in": ["WinRM", "HTTPAPI", "Microsoft"],
        },
    },
    {
        "id": "snmp-public-text",
        "group": "F-扩展协议-基础设施",
        "name": "SNMP 社区/错误可见文本",
        "input": {
            "ip": "10.8.0.19",
            "port": 161,
            "banner": "public\nSNMPv2-MIB::sysDescr.0 = STRING: Linux host 5.15.0-91-generic",
        },
        "expect": {"protocol": "SNMP", "os_hint": "Linux"},
    },
    {
        "id": "dns-bind-chaos",
        "group": "F-扩展协议-基础设施",
        "name": "BIND version CHAOS 文本",
        "input": {
            "ip": "10.8.0.20",
            "port": 53,
            "banner": 'version.bind.        CH      TXT     "9.18.18-0ubuntu0.22.04.1-Ubuntu"',
        },
        "expect": {
            "protocol": "DNS",
            "product_in": ["BIND", "named"],
            "version": "9.18.18",
            "os_hint": "Ubuntu",
        },
    },
    {
        "id": "http-tomcat",
        "group": "F-扩展协议-HTTP家族",
        "name": "Apache Tomcat",
        "input": {"ip": "10.9.0.1", "port": 8080, "banner": "HTTP/1.1 404 \r\nServer: Apache-Coyote/1.1\r\n"},
        "expect": {"protocol": "HTTP", "product_in": ["Tomcat", "Coyote"]},
    },
    {
        "id": "http-tomcat-full",
        "group": "F-扩展协议-HTTP家族",
        "name": "Apache Tomcat 完整产品名",
        "input": {"ip": "10.9.0.2", "port": 8080, "banner": "HTTP/1.1 200 OK\r\nServer: Apache Tomcat/9.0.75"},
        "expect": {"protocol": "HTTP", "product": "Tomcat", "version": "9.0.75"},
    },
    {
        "id": "http-caddy",
        "group": "F-扩展协议-HTTP家族",
        "name": "Caddy",
        "input": {"ip": "10.9.0.3", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: Caddy"},
        "expect": {"protocol": "HTTP", "product": "Caddy"},
    },
    {
        "id": "http-lighttpd",
        "group": "F-扩展协议-HTTP家族",
        "name": "lighttpd",
        "input": {"ip": "10.9.0.4", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.69"},
        "expect": {"protocol": "HTTP", "product": "lighttpd", "version": "1.4.69"},
    },
    {
        "id": "http-openresty",
        "group": "F-扩展协议-HTTP家族",
        "name": "OpenResty",
        "input": {"ip": "10.9.0.5", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: openresty/1.21.4.1"},
        "expect": {"protocol": "HTTP", "product": "openresty", "version": "1.21.4.1"},
    },
    {
        "id": "http-gunicorn",
        "group": "F-扩展协议-HTTP家族",
        "name": "gunicorn",
        "input": {"ip": "10.9.0.6", "port": 8000, "banner": "HTTP/1.1 200 OK\r\nServer: gunicorn/20.1.0"},
        "expect": {"protocol": "HTTP", "product": "gunicorn", "version": "20.1.0"},
    },
    {
        "id": "http-weblogic",
        "group": "F-扩展协议-HTTP家族",
        "name": "WebLogic",
        "input": {
            "ip": "10.9.0.7",
            "port": 7001,
            "banner": "HTTP/1.1 200 OK\r\nServer: WebLogic Server 12.2.1.4.0 Tue Jan 14 12:00:00 PST 2020",
        },
        "expect": {"protocol": "HTTP", "product": "WebLogic", "version": "12.2.1.4.0"},
    },
    {
        "id": "http-wildfly",
        "group": "F-扩展协议-HTTP家族",
        "name": "WildFly / JBoss",
        "input": {"ip": "10.9.0.8", "port": 8080, "banner": "HTTP/1.1 200 OK\r\nServer: WildFly/26.1.3"},
        "expect": {"protocol": "HTTP", "product_in": ["WildFly", "JBoss"], "version": "26.1.3"},
    },
    {
        "id": "http-squid",
        "group": "F-扩展协议-HTTP家族",
        "name": "Squid 代理",
        "input": {
            "ip": "10.9.0.9",
            "port": 3128,
            "banner": "HTTP/1.1 400 Bad Request\r\nServer: squid/5.7\r\nX-Squid-Error: ERR_INVALID_URL 0",
        },
        "expect": {"protocol": "HTTP", "product": "squid", "version": "5.7"},
    },
    {
        "id": "ssh-cisco",
        "group": "F-扩展协议-SSH/FTP",
        "name": "SSH Cisco",
        "input": {"ip": "10.9.0.10", "port": 22, "banner": "SSH-2.0-Cisco-1.25"},
        "expect": {"protocol": "SSH", "product": "Cisco", "version": "1.25"},
    },
    {
        "id": "ssh-libssh",
        "group": "F-扩展协议-SSH/FTP",
        "name": "SSH libssh",
        "input": {"ip": "10.9.0.11", "port": 22, "banner": "SSH-2.0-libssh_0.9.6"},
        "expect": {"protocol": "SSH", "product": "libssh", "version": "0.9.6"},
    },
    {
        "id": "ftp-microsoft",
        "group": "F-扩展协议-SSH/FTP",
        "name": "Microsoft FTP Service 不能当 SMTP",
        "input": {"ip": "10.9.0.12", "port": 21, "banner": "220 Microsoft FTP Service"},
        "expect": {
            "protocol": "FTP",
            "product_in": ["Microsoft", "IIS", "FTP"],
            "protocol_not_in": ["SMTP"],
        },
    },

    # ---------- G. 扩展协议交叉误判 ----------
    {
        "id": "pop3-not-redis",
        "group": "G-扩展协议混淆",
        "name": "POP3 +OK 不能当 Redis",
        "input": {"ip": "10.10.0.1", "port": 110, "banner": "+OK Dovecot ready."},
        "expect": {"protocol": "POP3", "protocol_not_in": ["Redis"]},
    },
    {
        "id": "redis-plus-ok-still-redis",
        "group": "G-扩展协议混淆",
        "name": "6379 上裸 +OK 仍是 Redis，不能当 POP3",
        "input": {"ip": "10.10.0.2", "port": 6379, "banner": "+OK"},
        "expect": {"protocol": "Redis", "protocol_not_in": ["POP3"]},
    },
    {
        "id": "memcached-error-not-redis",
        "group": "G-扩展协议混淆",
        "name": "Memcached ERROR 不能当 Redis -ERR",
        "input": {"ip": "10.10.0.3", "port": 11211, "banner": "ERROR\r\n"},
        "expect": {"protocol": "Memcached", "protocol_not_in": ["Redis"]},
    },
    {
        "id": "sip-not-http",
        "group": "G-扩展协议混淆",
        "name": "SIP/2.0 不能当 HTTP",
        "input": {
            "ip": "10.10.0.4",
            "port": 5060,
            "banner": 'SIP/2.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm="asterisk"',
        },
        "expect": {"protocol": "SIP", "protocol_not_in": ["HTTP"]},
    },
    {
        "id": "rtsp-not-http",
        "group": "G-扩展协议混淆",
        "name": "RTSP/1.0 不能当 HTTP",
        "input": {"ip": "10.10.0.5", "port": 554, "banner": "RTSP/1.0 401 Unauthorized\r\nCSeq: 2"},
        "expect": {"protocol": "RTSP", "protocol_not_in": ["HTTP"]},
    },
    {
        "id": "nntp-200-not-http",
        "group": "G-扩展协议混淆",
        "name": "NNTP 200 不能当 HTTP 200",
        "input": {
            "ip": "10.10.0.6",
            "port": 119,
            "banner": "200 news.example.com InterNetNews NNRP server INN 2.6.4 ready",
        },
        "expect": {
            "protocol": "NNTP",
            "product_in": ["INN", "NNTP"],
            "version": "2.6.4",
            "protocol_not_in": ["HTTP", "SMTP", "FTP"],
        },
    },
    {
        "id": "imap-star-ok-not-http",
        "group": "G-扩展协议混淆",
        "name": "IMAP * OK 不能当 HTTP",
        "input": {"ip": "10.10.0.7", "port": 143, "banner": "* OK IMAP4rev1 Server ready"},
        "expect": {"protocol": "IMAP", "protocol_not_in": ["HTTP", "Redis"]},
    },
    {
        "id": "es-not-couchdb",
        "group": "G-扩展协议混淆",
        "name": "Elasticsearch tagline 不能当 CouchDB",
        "input": {
            "ip": "10.10.0.8",
            "port": 9200,
            "banner": '{"tagline":"You Know, for Search","version":{"number":"7.17.14"}}',
        },
        "expect": {
            "protocol_in": ["Elasticsearch", "ES", "HTTP"],
            "product_in": ["Elasticsearch", "ES"],
            "protocol_not_in": ["CouchDB", "MongoDB"],
        },
    },
    {
        "id": "ftp-not-smtp-microsoft",
        "group": "G-扩展协议混淆",
        "name": "220 Microsoft FTP 不能当 SMTP",
        "input": {"ip": "10.10.0.9", "port": 21, "banner": "220 Microsoft FTP Service"},
        "expect": {"protocol": "FTP", "protocol_not_in": ["SMTP"]},
    },
    {
        "id": "http-connect-proxy",
        "group": "G-扩展协议混淆",
        "name": "HTTP CONNECT 代理仍是 HTTP",
        "input": {
            "ip": "10.10.0.10",
            "port": 8080,
            "banner": "HTTP/1.1 403 Forbidden\r\nProxy-Agent: tinyproxy/1.11.1",
        },
        "expect": {"protocol": "HTTP", "product": "tinyproxy", "version": "1.11.1"},
    },
]

REQUIRED_RESULT_FIELDS = (
    "ip",
    "port",
    "protocol",
    "product",
    "version",
    "os_hint",
    "confidence",
)


def dump_inputs() -> list[dict[str, Any]]:
    return [case["input"] for case in IDENTIFY_CASES]


def _norm(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _norm_lower(value: Any) -> str:
    return _norm(value).lower()


def _contains(haystack: Any, needle: str) -> bool:
    return _norm_lower(needle) in _norm_lower(haystack)


def validate_schema(item: Any, idx: int) -> list[str]:
    errors: list[str] = []
    if not isinstance(item, dict):
        return [f"[{idx}] 结果不是对象: {type(item).__name__}"]
    for field in REQUIRED_RESULT_FIELDS:
        if field not in item:
            errors.append(f"[{idx}] 缺少字段 {field}")
    protocol = _norm(item.get("protocol"))
    if protocol == "":
        errors.append(f"[{idx}] protocol 不能为空，认不出应返回 unknown")
    conf = item.get("confidence")
    if conf is None:
        errors.append(f"[{idx}] confidence 缺失")
    else:
        try:
            conf_f = float(conf)
            if conf_f < 0 or conf_f > 1:
                errors.append(f"[{idx}] confidence={conf} 超出 [0,1]")
        except (TypeError, ValueError):
            errors.append(f"[{idx}] confidence 不是数字: {conf!r}")
    return errors


def match_expect(item: dict[str, Any], expect: dict[str, Any], idx: int, case_id: str) -> list[str]:
    errors: list[str] = []
    prefix = f"[{idx} {case_id}]"

    if "protocol" in expect and _norm_lower(item.get("protocol")) != _norm_lower(expect["protocol"]):
        errors.append(f"{prefix} protocol 期望 {expect['protocol']!r} 实际 {item.get('protocol')!r}")

    if "protocol_in" in expect:
        allowed = [_norm_lower(x) for x in expect["protocol_in"]]
        if _norm_lower(item.get("protocol")) not in allowed:
            errors.append(f"{prefix} protocol={item.get('protocol')!r} 不在 {expect['protocol_in']}")

    if "protocol_not_in" in expect:
        banned = [_norm_lower(x) for x in expect["protocol_not_in"]]
        if _norm_lower(item.get("protocol")) in banned:
            errors.append(f"{prefix} protocol={item.get('protocol')!r} 不应是 {expect['protocol_not_in']}")

    if "product" in expect and not _contains(item.get("product"), expect["product"]):
        errors.append(f"{prefix} product 期望包含 {expect['product']!r} 实际 {item.get('product')!r}")

    if "product_in" in expect:
        ok = any(_contains(item.get("product"), p) for p in expect["product_in"])
        if not ok:
            errors.append(f"{prefix} product={item.get('product')!r} 不在 {expect['product_in']}")

    if "version" in expect:
        actual_ver = _norm(item.get("version"))
        if expect["version"] not in actual_ver:
            errors.append(f"{prefix} version 期望包含 {expect['version']!r} 实际 {item.get('version')!r}")

    if "os_hint" in expect and not _contains(item.get("os_hint"), expect["os_hint"]):
        errors.append(f"{prefix} os_hint 期望包含 {expect['os_hint']!r} 实际 {item.get('os_hint')!r}")

    return errors


def http_json(url: str, method: str = "GET", body: Any = None, timeout: float = 10) -> tuple[int, Any, str]:
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            parsed: Any
            try:
                parsed = json.loads(raw) if raw.strip() else None
            except json.JSONDecodeError:
                parsed = raw
            return resp.status, parsed, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw) if raw.strip() else None
        except json.JSONDecodeError:
            parsed = raw
        return exc.code, parsed, raw


def post_raw(url: str, raw_body: bytes, content_type: str, timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(
        url,
        data=raw_body,
        headers={"Content-Type": content_type, "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def print_case(ok: bool, title: str, detail: str = "") -> None:
    mark = "PASS" if ok else "FAIL"
    line = f"  [{mark}] {title}"
    if detail and not ok:
        line += f"\n         {detail}"
    print(line)


class Reporter:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.errors: list[str] = []

    def check(self, ok: bool, title: str, detail: str = "") -> None:
        print_case(ok, title, detail)
        if ok:
            self.passed += 1
        else:
            self.failed += 1
            if detail:
                self.errors.append(f"{title}: {detail}")
            else:
                self.errors.append(title)


def run_health(base: str, timeout: float, reporter: Reporter) -> None:
    print("\n== E. GET /health ==")
    try:
        status, _, _ = http_json(f"{base}/health", timeout=timeout)
        reporter.check(200 <= status < 300, f"健康检查返回 2xx（实际 {status}）")
    except Exception as exc:  # noqa: BLE001 — 测试脚本需要兜住连通性错误
        reporter.check(False, "健康检查可访问", str(exc))


def run_identify(base: str, timeout: float, reporter: Reporter) -> None:
    print("\n== A/B/C/D. POST /fingerprint 批量识别 ==")
    payload = dump_inputs()
    try:
        status, parsed, raw = http_json(
            f"{base}/fingerprint", method="POST", body=payload, timeout=timeout
        )
    except Exception as exc:  # noqa: BLE001
        reporter.check(False, "批量识别接口可访问", str(exc))
        return

    reporter.check(status == 200, f"批量识别 HTTP 200（实际 {status}）")
    if not isinstance(parsed, list):
        reporter.check(False, "响应必须是 JSON 数组", f"实际类型 {type(parsed).__name__} body={raw[:200]!r}")
        return

    reporter.check(
        len(parsed) == len(payload),
        f"结果条数等于输入条数（输入 {len(payload)} 输出 {len(parsed)}）",
    )

    n = min(len(parsed), len(IDENTIFY_CASES))
    for i in range(n):
        case = IDENTIFY_CASES[i]
        item = parsed[i]
        schema_errs = validate_schema(item, i)
        match_errs = []
        if isinstance(item, dict):
            match_errs = match_expect(item, case["expect"], i, case["id"])
        errs = schema_errs + match_errs
        reporter.check(not errs, f"{case['group']} | {case['name']}", "; ".join(errs))


def run_api_contract(base: str, timeout: float, reporter: Reporter) -> None:
    print("\n== E. API 契约 / 抗造情况 ==")
    url = f"{base}/fingerprint"

    try:
        status, parsed, raw = http_json(url, method="POST", body=[], timeout=timeout)
        ok = status == 200 and parsed == []
        reporter.check(ok, "空数组 [] → 200 且返回 []", f"status={status} body={raw[:200]!r}")
    except Exception as exc:  # noqa: BLE001
        reporter.check(False, "空数组 []", str(exc))

    try:
        status, parsed, _ = http_json(
            url,
            method="POST",
            body=[{"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}],
            timeout=timeout,
        )
        ok = status == 200 and isinstance(parsed, list) and len(parsed) == 1
        if ok and isinstance(parsed[0], dict):
            ok = _norm_lower(parsed[0].get("protocol")) == "ssh"
        reporter.check(ok, "单条数组也能识别 SSH", f"status={status} body={parsed!r}")
    except Exception as exc:  # noqa: BLE001
        reporter.check(False, "单条数组", str(exc))

    try:
        status, _, raw = post_raw(url, b"", "application/json", timeout)
        reporter.check(
            status != 0 and status < 500,
            f"空 body 不能 5xx（实际 {status}）",
            raw[:200],
        )
    except Exception as exc:  # noqa: BLE001
        reporter.check(True, "空 body 被拒绝但进程仍在", str(exc)[:120])

    try:
        status, _, raw = post_raw(url, b"{not-json", "application/json", timeout)
        reporter.check(
            status != 0 and status < 500,
            f"非法 JSON 不能 5xx（实际 {status}）",
            raw[:200],
        )
    except Exception as exc:  # noqa: BLE001
        reporter.check(True, "非法 JSON 被拒绝但进程仍在", str(exc)[:120])

    try:
        status, parsed, raw = http_json(
            url,
            method="POST",
            body={"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1"},
            timeout=timeout,
        )
        reporter.check(
            status < 500,
            f"误传对象而不是数组，不能 5xx（实际 {status}）",
            raw[:200],
        )
    except Exception as exc:  # noqa: BLE001
        reporter.check(True, "对象 body 被拒绝但进程仍在", str(exc)[:120])

    try:
        big = [
            {"ip": f"11.0.{i // 256}.{i % 256}", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"}
            for i in range(200)
        ]
        t0 = time.time()
        status, parsed, raw = http_json(url, method="POST", body=big, timeout=max(timeout, 30))
        elapsed = time.time() - t0
        ok = status == 200 and isinstance(parsed, list) and len(parsed) == 200
        if ok:
            ok = all(_norm_lower(x.get("protocol")) == "http" for x in parsed if isinstance(x, dict))
        reporter.check(
            ok,
            f"200 条批量识别（{elapsed:.2f}s）",
            f"status={status} n={len(parsed) if isinstance(parsed, list) else type(parsed).__name__}",
        )
    except Exception as exc:  # noqa: BLE001
        reporter.check(False, "200 条批量识别", str(exc))

    try:
        status, parsed, _ = http_json(
            url,
            method="POST",
            body=[
                {"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
                {"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
            ],
            timeout=timeout,
        )
        ok = status == 200 and isinstance(parsed, list) and len(parsed) == 2
        reporter.check(ok, "完全重复的两条输入仍返回两条", f"status={status} parsed={parsed!r}")
    except Exception as exc:  # noqa: BLE001
        reporter.check(False, "重复输入", str(exc))

    mix = [
        {"ip": "8.8.8.1", "port": 25, "banner": "220 mail.example.com ESMTP Postfix"},
        {"ip": "8.8.8.2", "port": 5432, "banner": 'FATAL:  password authentication failed for user "postgres"'},
        {"ip": "8.8.8.3", "port": 5900, "banner": "RFB 003.008\n"},
        {"ip": "8.8.8.4", "port": 6379, "banner": "+PONG"},
        {"ip": "8.8.8.5", "port": 5060, "banner": "SIP/2.0 200 OK\r\nServer: Asterisk PBX 18.12.0"},
        {"ip": "8.8.8.6", "port": 110, "banner": "+OK Dovecot ready."},
    ]
    want = [
        ["smtp"],
        ["postgresql", "pgsql", "postgres"],
        ["vnc"],
        ["redis"],
        ["sip"],
        ["pop3"],
    ]
    try:
        status, parsed, raw = http_json(url, method="POST", body=mix, timeout=timeout)
        ok = status == 200 and isinstance(parsed, list) and len(parsed) == len(mix)
        detail = f"status={status}"
        if ok:
            for i, item in enumerate(parsed):
                proto = _norm_lower(item.get("protocol"))
                if proto not in want[i]:
                    ok = False
                    detail = f"[{i}] protocol={item.get('protocol')!r} 期望 {want[i]}"
                    break
        reporter.check(ok, "混合协议小批量（SMTP/PostgreSQL/VNC/Redis/SIP/POP3）", detail)
    except Exception as exc:  # noqa: BLE001
        reporter.check(False, "混合协议小批量", str(exc))


def print_offline_catalog() -> None:
    print(f"共 {len(IDENTIFY_CASES)} 条识别用例：\n")
    current = ""
    for case in IDENTIFY_CASES:
        if case["group"] != current:
            current = case["group"]
            print(f"[{current}]")
        print(f"  - {case['id']}: {case['name']}")
        print(f"      expect={case['expect']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Banner 指纹识别边界/特殊用例测试")
    parser.add_argument("--url", default=os.environ.get("FINGERPRINT_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--dump", metavar="PATH", help="把识别用例的 input 导出为 client 可用 JSON")
    parser.add_argument("--offline", action="store_true", help="不访问服务，只打印用例清单")
    args = parser.parse_args()

    if args.dump:
        path = args.dump
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(dump_inputs(), fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print(f"已导出 {len(IDENTIFY_CASES)} 条 input → {path}")
        if args.offline:
            return 0

    if args.offline:
        print_offline_catalog()
        return 0

    base = args.url.rstrip("/")
    print(f"目标服务: {base}")
    print(f"识别用例: {len(IDENTIFY_CASES)} 条")

    reporter = Reporter()
    run_health(base, args.timeout, reporter)
    run_identify(base, args.timeout, reporter)
    run_api_contract(base, args.timeout, reporter)

    print("\n== 汇总 ==")
    total = reporter.passed + reporter.failed
    print(f"通过 {reporter.passed}/{total}，失败 {reporter.failed}")
    if reporter.failed:
        print("\n失败明细：")
        for err in reporter.errors:
            print(f"  - {err}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
