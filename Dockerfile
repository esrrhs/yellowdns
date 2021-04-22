FROM golang AS build-env

RUN GO111MODULE=off go get -u github.com/esrrhs/yellowdns
RUN GO111MODULE=off go get -u github.com/esrrhs/yellowdns/...
RUN GO111MODULE=off go install github.com/esrrhs/yellowdns

FROM debian
COPY --from=build-env /go/bin/yellowdns .
COPY GeoLite2-Country.mmdb .
WORKDIR ./
