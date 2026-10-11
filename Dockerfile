FROM golang:1.27.1-bookworm AS build

ARG VERSION=dev
ENV GOFLAGS=-mod=vendor
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${VERSION}" -o /out/yellowdns .

FROM debian:bookworm-slim
WORKDIR /app
# bookworm-slim 默认不含 ca-certificates：外部上游默认走 DoH(HTTPS)，
# 缺少系统根证书会导致 TLS 握手失败。安装后清理 apt 缓存保持镜像精简。
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system app \
    && useradd --system --gid app --home-dir /app --no-create-home app
COPY --from=build /out/yellowdns ./yellowdns
COPY GeoLite2-Country.mmdb ./GeoLite2-Country.mmdb
# -update 的默认落盘目录是工作目录 /app，需要对非 root 用户可写。
RUN chown -R app:app /app
USER app
# 853/tcp 仅在启用 -tls 时监听；EXPOSE 仅作文档声明，不改变运行行为。
EXPOSE 53/udp 53/tcp 853/tcp
CMD ["./yellowdns"]
