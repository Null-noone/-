FROM golang:1.23-alpine AS build
WORKDIR /src

RUN apk add --no-cache ca-certificates git
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -buildid=" \
    -o /out/client ./cmd/client

FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 65532 app \
    && adduser -S -u 65532 -G app app

WORKDIR /app
COPY --from=build --chown=65532:65532 /out/client /app/client

USER 65532:65532
ENTRYPOINT ["/app/client"]
