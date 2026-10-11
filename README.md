# yellowdns

[<img src="https://img.shields.io/github/license/esrrhs/yellowdns">](https://github.com/esrrhs/yellowdns)
[<img src="https://img.shields.io/github/languages/top/esrrhs/yellowdns">](https://github.com/esrrhs/yellowdns)
[<img src="https://img.shields.io/github/v/release/esrrhs/yellowdns">](https://github.com/esrrhs/yellowdns/releases)
[<img src="https://img.shields.io/github/downloads/esrrhs/yellowdns/total">](https://github.com/esrrhs/yellowdns/releases)
[<img src="https://img.shields.io/docker/pulls/esrrhs/yellowdns">](https://hub.docker.com/repository/docker/esrrhs/yellowdns)
[<img src="https://img.shields.io/github/actions/workflow/status/esrrhs/yellowdns/go.yml?branch=master">](https://github.com/esrrhs/yellowdns/actions)
[<img src="https://img.shields.io/github/actions/workflow/status/esrrhs/yellowdns/test.yml?branch=master&label=test">](https://github.com/esrrhs/yellowdns/actions)

Yellowdns is a DNS proxy that keeps domestic names on a local resolver and sends interfered names to an external resolver, based on the queried name and the country of the answer.

# Usage

```
./yellowdns
```

is the same as

```
./yellowdns -l :53 -los 114.114.114.114:53 -exs https://1.1.1.1/dns-query,https://8.8.8.8/dns-query -lor CN -lof GeoLite2-Country.mmdb
```

Docker:

```
docker run --name yellowdns -d --net=host --restart=always -p 55353:55353/udp -p 55353:55353/tcp esrrhs/yellowdns ./yellowdns -l :55353 -exs 127.0.0.1:55354
```

If port 53 is already taken by another interface, listen on `127.0.0.1:53` instead.

# Flags

* `-l`: listen address serving both UDP and TCP, default `:53`
* `-los`: domestic DNS servers, comma-separated for failover, default `114.114.114.114:53`. Address formats: plain `host:port` uses UDP, `tcp://host:port` forces TCP, `https://host/dns-query` uses DoH
* `-exs`: external DNS servers, comma-separated for failover, same formats as `-los`. Defaults to DoH (`https://1.1.1.1/dns-query,https://8.8.8.8/dns-query`) so the external query itself cannot be poisoned; use plain UDP only if your network blocks DoH
* `-lor`: domestic region code, default `CN`. Answers from the domestic DNS whose IPs fall outside this region are treated as suspect and the external answer is preferred instead
* `-lof`: country database. The file shipped in this repo is DB-IP Country Lite
* `-china`: extra domestic domain list. One domain per line, or dnsmasq `server=/name/address` lines
* `-gfw`: extra interfered domain list, same format
* `-update`: auto-update the remote domain lists at this interval (e.g. `-update 24h`); default `0` disables it. On startup the lists are checked once and applied immediately, then rechecked every interval
* `-update-dir`: directory for the downloaded remote lists (`china.remote.txt`, `gfw.remote.txt`), default `.`. Lists already present there are loaded at startup even without `-update`
* `-stats`: HTTP listen address serving query statistics as JSON at `/stats` (e.g. `-stats 127.0.0.1:8053`); empty disables
* `-stats-token`: bearer token required to access `/stats`; defaults to the `YELLOWDNS_STATS_TOKEN` environment variable (preferred, so the token does not show up in `ps`). When unset the endpoint is open, so bind `-stats` to loopback; a non-loopback bind without a token logs a warning
* `-version`: show version and exit
* other options: `./yellowdns -h`

Features & Routing:

* **UDP + TCP Listening**: Large answers that exceed the UDP size limit are served over TCP as required by RFC 1035.
* **Hot Reload (Unix)**: `kill -HUP <pid>` reloads the domain lists and the GeoIP database without dropping the listener; failed reloads keep the previous rules. SIGINT/SIGTERM shut the server down gracefully.
* **Optional Auto-Update**: `-update 24h` keeps the embedded domestic/interfered lists fresh directly from dnsmasq-china-list and v2ray-rules-dat over HTTPS. Downloads are size-limited and health-checked (minimum domain count), saved atomically, and skipped when the content hash is unchanged; any failure keeps the previous rules. The GeoIP database is not auto-updated and ships with releases.
* **Stats Endpoint**: `-stats 127.0.0.1:8053` exposes `GET /stats` with JSON counters: query totals by route (local/extern/auto), shadowed bypasses, resolver fallbacks, upstream attempts/errors, query types, domain list sizes, version and uptime. Disabled by default; bind to loopback unless the endpoint is trusted by your network. Protect it with `-stats-token` (or `YELLOWDNS_STATS_TOKEN`): clients must send `Authorization: Bearer <token>`, and requests without it get `401`.
* **Encrypted External Queries by Default**: `-exs` defaults to DNS-over-HTTPS, so interference cannot poison the external lookup itself. `-los`/`-exs` accept comma-separated lists of UDP, TCP and DoH addresses with in-order failover.
* **Modern `gohome/dns` Integration**: Powered by `gohome/dns` with parallel dual-stack queries, response caching and GeoIP anti-poisoning validation. The embedded domestic/interfered lists are loaded straight into the resolver.
* **Routing Priority**:
  1. `.cn`, `.中国`, `.公司`, `.网络`, and the built-in domestic list go directly to the domestic DNS. A domestic name is not sent to the external DNS just because its address is on a foreign CDN.
  2. The built-in interfered list goes directly to the external DNS.
  3. A more specific domestic name wins over a blocked parent. `google.com` is external, while `adservice.google.com` stays domestic. The reverse conflict (a blocked name under a domestic parent, such as `api.recaptcha.net` under `recaptcha.net`) is forced to the external path as well.
  4. Any other name is queried using parallel dual-stack racing. If the domestic answer is poisoned or outside the domestic region, the secure external response is automatically preferred.

Example with token auth via environment variable:

```
YELLOWDNS_STATS_TOKEN=s3cret ./yellowdns -stats 127.0.0.1:8053
curl -H "Authorization: Bearer s3cret" http://127.0.0.1:8053/stats
```

# Data

The country database is [DB-IP](https://db-ip.com/) Country Lite, licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Domestic names come from [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list). Interfered names come from the gfw list in [v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat).

# Release

Push a version tag to build archives and publish them to GitHub Releases. Each zip contains the binary (with the tag baked in via `-X main.version`, shown by `-version`) and `GeoLite2-Country.mmdb`.

```
git tag 0.5
git push origin 0.5
```
