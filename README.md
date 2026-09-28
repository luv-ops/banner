# Banner 指纹识别系统

接收一批网络扫描原始数据（`ip`、`port`、`banner`），识别出对应的**协议、软件、版本、操作系统提示**，并以 **client + server** 架构、**Docker Compose 一键启动**的方式交付。

## 架构

```
            JSON 文件                POST /fingerprint            识别结果
 client  ───────────────▶  server  ───────────────────▶  client  ──────────▶ 终端/文件
(读本地JSON)              (HTTP API)                      (tabwriter表格)
```

- **server**：无状态 HTTP 服务，提供 `POST /fingerprint`（批量识别）与 `GET /health`（健康检查）。
- **client**：独立程序，读取本地 JSON 文件、发给 server、以表格展示识别结果（可选写出 JSON）。
- 识别引擎在 `internal/fingerprint`，对未识别 banner 一律返回 `protocol: "unknown"`，**绝不报错或崩溃**。

## 目录结构

```
banner/
├── cmd/
│   ├── server/main.go          # HTTP 服务入口
│   └── client/main.go          # 独立客户端
├── internal/
│   ├── models/models.go        # 数据结构
│   ├── fingerprint/engine.go   # 识别引擎（核心逻辑）
│   └── server/server.go        # 路由与处理函数
├── testdata/input.json         # 示例原始数据
├── Dockerfile                  # 多阶段构建（server+client 同一镜像）
├── docker-compose.yml          # 一键启动
└── go.mod
```

## 识别能力

| 协议 | 触发条件 | 可解析字段 |
|------|----------|------------|
| SSH | `SSH-<ver>-<product>_<version> [os]` | product / version / os_hint |
| HTTP | 含 `HTTP/` 状态行或 `Server:` 头 | product（nginx / Apache / Jetty）/ version / 平台 |
| MySQL | 端口 3306 + 版本串，或显式 `mysql` 字样 | version / 发行版 OS 提示 |
| Redis | 端口 6379 + 响应前缀(`-+*:$`)，或含 `redis` | version（若可得） |
| FTP | `220` 问候码 | product（ProFTPD / vsftpd / FileZilla / Pure-FTPd）/ version |
| unknown | 以上均不匹配 | —（confidence 低，不报错） |

## 快速开始（Docker Compose 一键启动）

```bash
docker compose up --build
```

这条命令会：构建镜像 → 启动 server（健康检查通过后）→ 运行 client 读取 `testdata/input.json` → 打印识别结果表格。

常驻 server 后随时重跑 client（无需重新构建，输入通过只读卷挂载）：

```bash
docker compose up -d --build                         # 仅常驻 server
docker compose run --rm client \
  -input /work/testdata/input.json \
  -server http://server:8080
```

编辑 `testdata/input.json` 后直接重跑即可。

## API 参考

### `POST /fingerprint`

请求体：

```json
{
  "records": [
    { "ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" }
  ]
}
```

也接受裸数组形式（client 自动兼容）：

```json
[
  { "ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" }
]
```

响应体：

```json
{
  "total": 2,
  "results": [
    {
      "ip": "1.2.3.4", "port": 22,
      "protocol": "SSH", "product": "OpenSSH",
      "version": "8.9p1", "os_hint": "Ubuntu", "confidence": 0.95
    }
  ]
}
```

### `GET /health`

```json
{ "status": "ok", "time": "2026-09-28T09:26:19Z" }
```

## 输入 / 输出示例

输入（`testdata/input.json`）：

```json
[
  { "ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" },
  { "ip": "1.2.3.5", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html" },
  { "ip": "1.2.3.6", "port": 443, "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57" },
  { "ip": "1.2.3.9", "port": 21, "banner": "220 ProFTPD 1.3.7 Server (ProFTPD)" }
]
```

输出（client 表格）：

```
IP        PORT  PROTOCOL  PRODUCT  VERSION  OS_HINT  CONFIDENCE
1.2.3.4   22    SSH       OpenSSH  8.9p1    Ubuntu   0.95
1.2.3.5   80    HTTP      nginx    1.24.0            0.90
1.2.3.6   443   HTTP      Apache   2.4.57            0.90
1.2.3.9   21    FTP       ProFTPD  1.3.7             0.90
```

## 本地运行（不使用 Docker）

```bash
go build -o bin/server ./cmd/server
go build -o bin/client ./cmd/client
./bin/server &                       # 默认监听 :8080，可用 SERVER_ADDR 覆盖
./bin/client -input testdata/input.json -server http://localhost:8080
# 可选：-out results.json 将结果写入文件
```

## 测试

```bash
go test ./internal/fingerprint/ -v
```

## 字段说明

| 字段 | 含义 |
|------|------|
| `protocol` | 识别出的协议；认不出为 `unknown` |
| `product` | 软件/产品名（如 `OpenSSH`、`nginx`） |
| `version` | 版本号（无则空） |
| `os_hint` | 操作系统提示（如 `Ubuntu`、`Windows`） |
| `confidence` | 置信度 `0~1` |
