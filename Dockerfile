FROM golang:1.27.1-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/yellowdns .

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /out/yellowdns ./yellowdns
COPY GeoLite2-Country.mmdb ./GeoLite2-Country.mmdb
EXPOSE 53/udp
CMD ["./yellowdns"]
