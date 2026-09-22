# 多阶段构建：编译机与运行机分离，最终镜像只含静态二进制 + 规则文件。
FROM golang:1.23-alpine AS build
WORKDIR /src

RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -buildid=" \
    -o /out/server ./cmd/server

FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 65532 app \
    && adduser -S -u 65532 -G app app

WORKDIR /app
COPY --from=build --chown=65532:65532 /out/server /app/server
COPY --chown=65532:65532 rules /app/rules

USER 65532:65532
EXPOSE 8080

# 镜像自带健康探测：用同一二进制访问本机 /health，不依赖 curl/wget。
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=5 \
    CMD ["/app/server", "-healthcheck"]

ENTRYPOINT ["/app/server"]
CMD ["-listen", ":8080", "-rules", "/app/rules"]
