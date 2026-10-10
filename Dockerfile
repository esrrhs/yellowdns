FROM golang:1.27.1-bookworm AS build

ARG VERSION=dev
ENV GOFLAGS=-mod=vendor
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${VERSION}" -o /out/yellowdns .

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /out/yellowdns ./yellowdns
COPY GeoLite2-Country.mmdb ./GeoLite2-Country.mmdb
EXPOSE 53/udp 53/tcp
CMD ["./yellowdns"]
