# Banner 指纹识别系统

接收一批网络扫描原始数据（`ip` / `port` / `banner`），识别协议、软件与版本，以 **client + server** 交付，`docker compose up` 一键启动。

认不出时统一返回 `protocol: "unknown"`，服务不会因此退出。

## 快速启动

```bash
docker compose up --build
```

Compose 项目名写死为 `bannerfp`（见 `docker-compose.yml` 的 `name`），避免仓库目录名无法推导项目名时启动失败。

- 宿主机访问识别接口：`http://127.0.0.1:8080`
- client 只在内部网用服务名 `http://server:8080` 调 server，不走宿主机端口
- server 健康后 client 才启动，读取 `testdata/sample.json`，把识别结果打印到日志

换一批数据：

```bash
docker compose run --rm -v ${PWD}/testdata:/data:ro client -input /data/edge_cases.json
```

## 接口

### `GET /health`

健康检查。容器 `HEALTHCHECK` 与 Compose `depends_on: service_healthy` 都打这个接口。

```json
{"status":"ok"}
```

### `POST /fingerprint`

批量识别。请求体必须是 JSON 数组。非法 JSON 或非数组返回 4xx，不返回 5xx。

```bash
curl -s http://127.0.0.1:8080/fingerprint \
  -H 'Content-Type: application/json' \
  --data-binary @testdata/sample.json
```

单条结果字段：

| 字段 | 说明 |
| --- | --- |
| `ip` | 原样回传 |
| `port` | 原样回传 |
| `protocol` | 协议；认不出为 `unknown` |
| `product` | 软件名，可空 |
| `version` | 版本，可空 |
| `os_hint` | 操作系统线索，可空 |
| `confidence` | 0~1 |

## 本地开发（不走容器）

```bash
go run ./cmd/server -listen :8080 -rules ./rules
go run ./cmd/client -server http://127.0.0.1:8080 -input testdata/sample.json
```

边界 / 扩展协议回归：

```bash
go run ./scripts/test_edge_cases.go -url http://127.0.0.1:8080
```

## 识别规则与代码解耦

匹配逻辑全部在 `rules/*.yaml`，程序只负责加载、转义还原、按优先级执行。

- 镜像内默认带一份规则（`/app/rules`）
- Compose 把宿主机 `./rules` 只读挂进容器，改 YAML 不用重新编译
- 规则按文件名加载，按 `priority` 降序匹配，先命中者生效

规则字段：

```yaml
- id: ssh-openssh
  protocol: SSH
  product: OpenSSH
  priority: 100
  confidence: 0.95
  banner_regex: '(?i)SSH-[\d.]+-OpenSSH[_-](?P<version>[\d.]+p?\d*)'
  banner_contains: []
  banner_not_contains: []
  port_in: []          # 可选，用于 +OK 这类歧义 banner
  port_not_in: []
  os_hints:
    - value: Ubuntu
      regex: '(?i)Ubuntu'
```

命名捕获组 `version` / `product` 会写入结果。扫描器常见的字面 `\xHH`、`\n` 会先还原再匹配，所以 MySQL handshake、TLS ClientHello 无论是真实二进制还是转义文本都能认。

当前覆盖（规则可继续加，不必改 Go）：

- 基础：SSH、HTTP（nginx / Apache / Jetty / IIS 等）、MySQL / MariaDB、Redis、FTP
- 邮件：SMTP / POP3 / IMAP
- 数据：PostgreSQL、MongoDB、Memcached、MSSQL、Oracle、Elasticsearch、CouchDB、Cassandra、ClickHouse、InfluxDB
- 远程：Telnet、RDP、VNC、MQTT、AMQP、Modbus
- 基础设施：TLS、SIP、RTSP、SMB、Rsync、ZooKeeper、LDAP、DNS、SNMP、SOCKS、IRC、NNTP、XMPP、Docker、Kubernetes、etcd、Consul、Jenkins、IPP、WinRM

## 目录

```text
cmd/server          HTTP 服务
cmd/client          读本地 JSON，调用 server，打印结果
internal/api        路由与入参容错
internal/fingerprint 规则加载与匹配
internal/normalize  banner 转义还原
rules/              识别规则（与代码解耦）
testdata/           自测数据
docker/             多阶段 Dockerfile
```

## 部署上的取舍

评估者会看容器怎么互访、依赖是否真健康、镜像会不会编译打包、权限是否收紧、规则是否外置。对应做法：

1. **访问收敛**：`backend` 网段 `internal: true`，client 只连 `http://server:8080`；`frontend` 只给 server 发到宿主机的 8080。client 不发布端口。
2. **真实健康检测**：镜像 `HEALTHCHECK` 和 Compose `healthcheck` 都执行 `/app/server -healthcheck`（请求本机 `/health`）。client `depends_on` 使用 `service_healthy`。
3. **编译打包**：Go 多阶段构建，`CGO_ENABLED=0` 出静态二进制，运行镜像只有 alpine + 二进制 + 规则，不含编译器和源码。
4. **权限收紧**：`user 65532`、`cap_drop: ALL`、`no-new-privileges`、`read_only: true`，可写目录仅 `tmpfs /tmp`。
5. **规则外置**：识别特征在 YAML，不写死在 Go 里。

## 容错

- 空数组返回 `[]`
- 缺 `banner` / 非法 IP / 越界端口：仍返回一条结果，认不出则为 `unknown`
- 请求体不是数组或不是 JSON：400
- 引擎内部 panic 会被接住，对应条目按 `unknown` 返回
