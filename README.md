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

## 测试

栈起来之后（`docker compose up --build -d`），按下面自测。Windows PowerShell 把 `curl` 换成 `curl.exe`，`${PWD}` 一般可直接用。

### 1. 健康检查与容器状态

```bash
docker compose ps
curl -s http://127.0.0.1:8080/health
docker inspect bannerfp-server-1 --format "{{.State.Health.Status}}"
```

期望：`{"status":"ok"}`，server 为 `healthy`。

### 2. 题目自测数据（sample）

宿主机直接打 server：

```bash
curl -s http://127.0.0.1:8080/fingerprint \
  -H "Content-Type: application/json" \
  --data-binary @testdata/sample.json
```

用容器里的 client（只走内部服务名 `http://server:8080`）：

```bash
docker compose run --rm client -input /data/sample.json
```

期望至少识别出 OpenSSH 8.9p1 / nginx 1.24.0 / Apache 2.4.57 / MySQL 8.0.32 / Redis / ProFTPD 1.3.7 / Jetty 9.4.51；`1.2.3.23` 的 `QUIT` 为 `protocol: "unknown"`。

看 client 启动时打过的结果：

```bash
docker compose logs client
```

### 3. 边界值与扩展协议回归（135 条 + API 契约）

对着容器里的 server 跑脚本，应 **146/146 通过**：

```bash
go run ./scripts/test_edge_cases.go -url http://127.0.0.1:8080
```

只导出 / 看用例清单，不访问服务：

```bash
go run ./scripts/test_edge_cases.go -offline
go run ./scripts/test_edge_cases.go -dump testdata/edge_cases.json
```

用 client 喂同一批边界数据：

```bash
docker compose run --rm -v ${PWD}/testdata:/data:ro client -input /data/edge_cases.json
```

### 4. 接口容错（不能 5xx）

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/fingerprint -H "Content-Type: application/json" --data-binary "[]"
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/fingerprint -H "Content-Type: application/json" --data-binary "{not-json"
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080/fingerprint -H "Content-Type: application/json" --data-binary "{}"
```

期望：空数组 `200`，非法 JSON / 对象 body 为 `4xx`（本地实测为 `400`）。

PowerShell：

```powershell
curl.exe -s -o NUL -w "%{http_code}`n" http://127.0.0.1:8080/fingerprint -H "Content-Type: application/json" --data-binary "[]"
```

### 5. 不走容器的单元测试

```bash
go test ./...
go run ./cmd/server -listen :8080 -rules ./rules
go run ./cmd/client -server http://127.0.0.1:8080 -input testdata/sample.json
```

`go test` 覆盖题目示例深度（SSH/HTTP/MySQL/Redis/FTP）以及 unknown。8080 已被 Compose 占用时，先 `docker compose down` 或给本地 server 换端口。

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

完整回归命令见上面的「测试」。

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
