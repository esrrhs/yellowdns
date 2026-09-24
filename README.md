# yellowdns

[<img src="https://img.shields.io/github/license/esrrhs/yellowdns">](https://github.com/esrrhs/yellowdns)
[<img src="https://img.shields.io/github/languages/top/esrrhs/yellowdns">](https://github.com/esrrhs/yellowdns)
[![Go Report Card](https://goreportcard.com/badge/github.com/esrrhs/yellowdns)](https://goreportcard.com/report/github.com/esrrhs/yellowdns)
[<img src="https://img.shields.io/github/v/release/esrrhs/yellowdns">](https://github.com/esrrhs/yellowdns/releases)
[<img src="https://img.shields.io/github/downloads/esrrhs/yellowdns/total">](https://github.com/esrrhs/yellowdns/releases)
[<img src="https://img.shields.io/docker/pulls/esrrhs/yellowdns">](https://hub.docker.com/repository/docker/esrrhs/yellowdns)
[<img src="https://img.shields.io/github/actions/workflow/status/esrrhs/yellowdns/go.yml?branch=master">](https://github.com/esrrhs/yellowdns/actions)
[<img src="https://img.shields.io/github/actions/workflow/status/esrrhs/yellowdns/test.yml?branch=master&label=test">](https://github.com/esrrhs/yellowdns/actions)

DNS proxy that picks an upstream from the name and the country of the answer. Domestic names stay on a local resolver. Interfered names go straight to an external resolver.

# Usage

```
./yellowdns
```

is the same as

```
./yellowdns -l :53 -los 114.114.114.114:53 -exs 8.8.8.8:53 -lor CN -lof GeoLite2-Country.mmdb
```

Docker:

```
docker run --name yellowdns -d --net=host --restart=always -p 55353:55353/udp esrrhs/yellowdns ./yellowdns -l :55353 -exs 127.0.0.1:55354
```

If port 53 is already taken by another interface, listen on `127.0.0.1:53` instead.

# Flags

* `-l`: UDP listen address, default `:53`
* `-los`: domestic DNS server, default `114.114.114.114:53`
* `-exs`: external DNS server, default `8.8.8.8:53`
* `-lor`: domestic region code, default `CN`
* `-lof`: country database. The file shipped in this repo is DB-IP Country Lite
* `-china`: extra domestic domain list. One domain per line, or dnsmasq `server=/name/address` lines
* `-gfw`: extra interfered domain list, same format
* `-version`: show version and exit
* other options: `./yellowdns -h`

Features & Routing:

* **Modern `gohome/dns` Integration**: Powered by `gohome/dns` with parallel dual-stack queries and GeoIP anti-poisoning validation.
* **Routing Priority**:
  1. `.cn`, `.中国`, `.公司`, `.网络`, and the built-in domestic list go directly to the domestic DNS. A domestic name is not sent to the external DNS just because its address is on a foreign CDN.
  2. The built-in interfered list goes directly to the external DNS.
  3. A more specific domestic name wins over a blocked parent. `google.com` is external, while `adservice.google.com` stays domestic.
  4. Any other name is queried using parallel dual-stack racing. If the domestic answer is poisoned or outside the domestic region, the secure external response is automatically preferred.

# Data

The country database is [DB-IP](https://db-ip.com/) Country Lite, licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Domestic names come from [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list). Interfered names come from the gfw list in [v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat).

# Release

Push a version tag to build archives and publish them to GitHub Releases. Each zip contains the binary and `GeoLite2-Country.mmdb`.

```
git tag 0.3
git push origin 0.3
```
