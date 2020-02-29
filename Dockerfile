FROM golang AS build-env

RUN go get -u github.com/esrrhs/yellowdns
RUN go get -u github.com/esrrhs/yellowdns/...
RUN go install github.com/esrrhs/yellowdns

FROM debian
COPY --from=build-env /go/bin/yellowdns .
COPY GeoLite2-Country.mmdb .
WORKDIR ./
