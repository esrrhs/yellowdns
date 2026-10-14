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

The release image is based on `debian:bookworm-slim` with `ca-certificates` installed (required for the default DoH upstreams) and runs as a non-root user; `/app` is writable so `-update` can persist the downloaded lists and GeoIP database in the default working directory.

# Flags

* `-l`: listen address serving both UDP and TCP, default `:53`
* `-tls` / `-tls-cert` / `-tls-key`: DNS-over-TLS (RFC 7858) inbound listener, e.g. `-tls :853 -tls-cert fullchain.pem -tls-key privkey.pem`; `-tls` empty (default) disables it. The DoT listener uses the same resolver as `-l`, so routing, cache, serve-stale, ECS policy and the query log apply identically. TLS 1.0/1.1 are refused (1.2 minimum). The certificate is reloaded on SIGHUP together with the rules (a bad reload keeps serving the old certificate), so ACME renewals need no restart; example: `kdig -d @127.0.0.1 +tls example.com`
* `-los`: domestic DNS servers, comma-separated for failover, default `114.114.114.114:53`. Address formats: plain `host:port` uses UDP, `tcp://host:port` forces TCP, `https://host/dns-query` uses DoH
* `-exs`: external DNS servers, comma-separated for failover, same formats as `-los`. Defaults to DoH (`https://1.1.1.1/dns-query,https://8.8.8.8/dns-query`) so the external query itself cannot be poisoned; use plain UDP only if your network blocks DoH
* `-lor`: domestic region code, default `CN`. Answers from the domestic DNS whose IPs fall outside this region are treated as suspect and the external answer is preferred instead
* `-lof`: country database. The file shipped in this repo is DB-IP Country Lite
* `-china`: extra domestic domain list. One domain per line, or dnsmasq `server=/name/address` lines
* `-gfw`: extra interfered domain list, same format
* `-hosts`: static hosts file. Accepts standard `/etc/hosts` lines (`1.2.3.4 a.test b.test`, IPv6 included) and dnsmasq `address=/name/ip` lines (matches the name and all subdomains). Hits are answered directly with TTL 60 and never sent upstream; reloaded on SIGHUP
* `-update`: auto-update the remote domain lists and the GeoIP database at this interval (e.g. `-update 24h`); default `0` disables it. On startup everything is checked once and applied immediately, then rechecked every interval
* `-update-dir`: directory for the downloaded remote lists (`china.remote.txt`, `gfw.remote.txt`) and GeoIP database (`geoip.country.mmdb`), default `.`. Files already present there are loaded at startup even without `-update`
* `-shutdown-delay`: when set (e.g. `-shutdown-delay 2s`), SIGINT/SIGTERM flips `/readyz` to 503, keeps serving DNS for the delay so load balancers can drain the instance, then closes listeners; default `0` closes immediately
* `-cache-size`: response cache capacity in entries, shared by the gohome cache, the serve-stale backup and the negative cache, default `2000`
* `-cache-min-ttl` / `-cache-max-ttl`: floor/ceiling applied to every upstream answer's TTL before caching and replying (e.g. `-cache-min-ttl 60s -cache-max-ttl 24h`); `0` disables the corresponding clamp. Only positive answers are cached; OPT records are never rewritten
* `-negcache-ttl`: maximum TTL for cached negative answers (NXDOMAIN/NODATA, RFC 2308), default `1h`; `0` disables negative caching. The effective TTL is the smaller of the authority SOA's TTL and MINIMUM fields, capped by this flag and then passed through the same `-cache-min-ttl`/`-cache-max-ttl` clamps; answers without an SOA are not cached. On hit the reply is served locally with the remaining TTL decayed — no upstream is consulted, so AAAA-NODATA (dual-stack clients asking IPv6-only-less names) and typo NXDOMAIN storms stop re-querying upstreams. The cache is cleared by `POST /cache/flush`, SIGHUP reloads and rule auto-updates
* `-serve-stale`: when all upstreams fail, keep answering with the last good response for up to this long past its TTL (e.g. `-serve-stale 24h`, RFC 8767-style). Stale replies carry a 5s TTL so clients re-resolve soon after recovery; default `0` disables. The backup is also cleared by SIGHUP reloads and `POST /cache/flush`
* `-query-log`: append one JSON line per query to this file (e.g. `-query-log query.log`); `-` writes to stdout; empty (default) disables. Each line records timestamp, client `ip:port`, qname/qtype/qclass, resolved route, rcode, stale flag, answer summaries and end-to-end latency. Writes are async (queue drops are counted, DNS replies never block on disk), size-rotated (`-query-log-max-mb`, default 100 MiB; `0` disables) keeping `-query-log-max-files` old files (`.1`..`.N`, default 5), and the file is reopened on SIGHUP for external logrotate
* `-ecs` / `-ecs-strip`: EDNS Client Subnet (RFC 7871) policy for upstream A/AAAA queries, mutually exclusive. `-ecs 8.8.4.0/24` adds (or overrides the client's) ECS so CDN-savvy upstreams answer for that region; `-ecs-strip` removes client ECS before forwarding so internal topology is not leaked. Unset (default) forwards the client's ECS untouched. A fixed subnet is used instead of per-client synthesis on purpose: it stays consistent with the qname/type/class-only cache key, so answers cannot be cross-subnet cache pollution. The DO bit and other EDNS options are never touched; private-range CIDRs only produce a startup warning
* `-allow` / `-deny`: per-client access control by source CIDR or bare IP (bare IP = `/32` or `/128`), comma-separated, applied identically to UDP, TCP and DoT at the resolver entry — rejected queries never touch hosts, cache or upstreams and get `REFUSED` so clients fail over fast. `-allow 10.0.0.0/8,192.168.1.5` switches to whitelist mode (only listed sources are served); empty (default) serves everyone. `-deny 8.8.8.8/32` always wins over any allow match
* `-allow-file` / `-deny-file`: same rules loaded from files (one CIDR/IP per line, `#` comments, comma-per-line allowed), e.g. `-allow-file clients.txt`; both files are reloaded on SIGHUP and combine with the inline `-allow`/`-deny` lists. A missing or malformed file aborts startup; a broken reload keeps the old rules
* `-rate-limit` / `-rate-burst`: per-client query rate limit. `-rate-limit 100` caps each source IP at 100 sustained QPS via a token bucket; `-rate-burst 200` sets the burst capacity (default twice the rate, minimum 1). New clients start with a full bucket so a burst of parallel queries at connect time is not rejected; clients without traffic for 10 minutes expire, and the table self-caps at 50k sources. `0` (default) disables limiting
* `-stats`: HTTP listen address serving operational endpoints (e.g. `-stats 127.0.0.1:8053`); empty disables:
  * `GET /stats` — JSON counters (queries by route, shadowed bypasses, fallbacks, hosts hits, in-flight gauge, response-code breakdown with NODATA/no-response errors/TC truncation, response-cache size with cumulative hits/misses and hit ratio, negative-cache entries/hits/misses/hit-ratio, serve-stale backup entries and stale-served count, aggregate and per-upstream attempts/errors/last-error/response-time, end-to-end query latency histograms by route, GeoIP database freshness, query-log enabled/written/dropped counters, EDNS client-subnet policy mode and applied count, DNS-over-TLS listener state, client ACL allow/deny entry counts, per-client rate-limit QPS/burst, active bucket count and acl/ratelimit refusal counters, auto-update health per source with last-success timestamp and consecutive failures, qtypes, list sizes, version, uptime)
  * `GET /metrics` — the same counters in Prometheus text exposition format
  * `POST /cache/flush` — clear the resolver response cache and the serve-stale backup, returns `{"cleared_entries": N}`; POST-only, same bearer auth as `/stats`
  * `POST /update/refresh` — trigger an immediate china/gfw/GeoIP refresh (serialized with the periodic check, hot-reloads on change) and return per-source results; POST-only, same bearer auth. `200` when at least one source is reachable (partial failures stay in the body), `502` when all three fail, `503` when `-update` is disabled
  * `GET /readyz` — unauthenticated readiness probe: `503 not ready` until all enabled listeners (UDP, TCP and DoT) are up, `200 ready` afterwards (flips back to 503 during graceful shutdown). Intended for K8s readinessProbe / load-balancer drain; it exposes no data
  * `GET /healthz` — unauthenticated liveness probe returning `200 ok` (intended for Docker/K8s health checks; it exposes no data)
  * `GET /debug/pprof/` — Go runtime profiler pages (`goroutine`, `heap`, `profile?seconds=N`, `trace?seconds=N`, ...), only registered with `-pprof`; same bearer auth as `/stats`. Point `go tool pprof http://127.0.0.1:8053/debug/pprof/profile?seconds=30` at it for a CPU profile
* `-stats-token`: bearer token required to access `/stats`, `/metrics`, `POST /cache/flush`, `POST /update/refresh` and `/debug/pprof/`; defaults to the `YELLOWDNS_STATS_TOKEN` environment variable (preferred, so the token does not show in `ps`). `/healthz` and `/readyz` stay unauthenticated. When unset the endpoints are open, so bind `-stats` to loopback; a non-loopback bind without a token logs a warning
* `-pprof`: enable the `net/http/pprof` profiler under `/debug/pprof/` on the `-stats` server for live CPU/heap/goroutine/trace debugging; default off. Starting with pprof on a non-loopback `-stats` address and no token is refused; `-pprof` without `-stats` logs a warning and has no effect
* `-timeout`: upstream query timeout in milliseconds, default `5000`
* `-loglevel`: log level (`debug`, `info`, `warn`, `error`), default `info`
* `-nolog`: set to a non-zero value to stop writing log files (`yellowdns_<LEVEL>_<date>.log`) in the working directory
* `-noprint`: set to a non-zero value to stop echoing log lines to stdout
* `-version`: show version and exit
* other options: `./yellowdns -h`

Features & Routing:

* **UDP + TCP Listening**: Large answers that exceed the UDP size limit are served over TCP as required by RFC 1035.
* **DNS-over-TLS Inbound (RFC 7858)**: `-tls :853` serves the same resolver over TLS 1.2+ on TCP port 853, so clients on hostile networks can reach the resolver with encrypted queries; the certificate hot-reloads on SIGHUP.
* **Hot Reload (Unix)**: `kill -HUP <pid>` reloads the domain lists, the GeoIP database, the client ACL rule files and the DoT certificate without dropping listeners; failed reloads keep the previous rules/cert. SIGINT/SIGTERM shut the server down gracefully.
* **Optional Auto-Update**: `-update 24h` keeps the embedded domestic/interfered lists fresh directly from dnsmasq-china-list and v2ray-rules-dat, and the GeoIP country database fresh from [DB-IP](https://dbip.com/)'s free monthly `DBIP-Country-Lite` (current month, falling back to the previous one). Downloads are size-limited and health-checked (minimum domain count; the mmdb is gunzipped and opened to verify it is a real MaxMind country database), saved atomically, and skipped when the content hash is unchanged; any failure keeps the previously active rules and database. A downloaded database takes precedence over the `-lof` file and is hot-reloaded.
* **Static Hosts**: `-hosts rules.txt` forces names to fixed addresses using standard hosts or dnsmasq `address=/` syntax (with wildcard subdomains, IPv4 and IPv6). Static answers take precedence over all routing and upstreams and are hot-reloaded on SIGHUP.
* **Serve-Stale & TTL Tuning**: `-serve-stale 24h` keeps a backup of the last good answer per question; when every upstream is unreachable, stale answers are returned (with a 5s TTL) instead of SERVFAIL, riding through upstream outages. `-cache-min-ttl`/`-cache-max-ttl` clamp upstream TTLs and `-cache-size` bounds all three caches. Backup usage is exposed as `yellowdns_cache_stale_served_total` and `yellowdns_cache_stale_entries`.
* **Negative Answer Caching (RFC 2308)**: NXDOMAIN and NODATA answers are cached locally (the response cache only holds positive answers), keyed by qname/qtype/qclass like every other layer, with the TTL taken from the SOA record (TTL vs MINIMUM, whichever is smaller), capped by `-negcache-ttl` (default 1h; `0` disables) and clamped by `-cache-min-ttl`/`-cache-max-ttl`. Cache hits are answered without touching any upstream, which matters on dual-stack networks where AAAA queries for IPv4-only names (NODATA) and typo domains (NXDOMAIN) make up a large share of traffic. Entries, cumulative hits/misses and hit ratio are exposed as `yellowdns_cache_negative_entries`, `yellowdns_cache_negative_hits_total` and `yellowdns_cache_negative_misses_total`; the cache is flushed together with the response cache (`POST /cache/flush`, SIGHUP, auto-update reloads) so rule changes never keep a stale NXDOMAIN alive.
* **Query Log**: `-query-log query.log` writes one JSON object per query (timestamp, client, qname/qtype, route, rcode, stale, answers, latency) for audit and pollution troubleshooting. Logging is fully async and non-blocking with size-based rotation and SIGHUP reopen; queue drops are visible as `yellowdns_querylog_dropped_total`.
* **EDNS Client Subnet Policy**: `-ecs 8.8.4.0/24` pins a fixed client subnet on upstream A/AAAA queries so CDN-savvy resolvers return region-targeted answers, `-ecs-strip` removes client ECS for privacy; the DO bit and other EDNS options are preserved. Policy mode and rewrite count are exposed as `yellowdns_ecs_info{mode=...}` and `yellowdns_ecs_applied_total`.
* **Per-Client Access Control & Rate Limiting**: `-allow`/`-deny` (plus `-allow-file`/`-deny-file`, hot-reloaded) filter clients by source CIDR for UDP/TCP/DoT alike; deny always wins, a non-empty allow list means whitelist mode, and rejected queries get `REFUSED` before consuming any cache or upstream resource. `-rate-limit 100` adds a per-source-IP token bucket (default burst 2x, idle clients expire, 50k-source cap) to blunt floods/abuse without punishing legitimate bursty clients. Rule counts, active clients and refusals are visible at `/stats` and as `yellowdns_acl_entries`, `yellowdns_acl_rate_limit_qps`, `yellowdns_acl_rate_burst`, `yellowdns_acl_active_clients` and `yellowdns_acl_denied_total{reason=acl|ratelimit}`.
* **Operational Endpoints**: `-stats 127.0.0.1:8053` serves JSON counters at `/stats` (including live response-cache size with cumulative cache hits/misses and hit ratio, per-source auto-update health, response-code breakdown with error and TC-truncation counts, and fallback-path per-upstream health: attempts/errors, last error, last success, response-time count/sum/min/max), Prometheus metrics at `/metrics` (plus `yellowdns_responses_total`, `yellowdns_query_errors_total`, `yellowdns_cache_hits/misses_total`, `yellowdns_upstream_server_*` per configured upstream, and the `yellowdns_query_duration_seconds` end-to-end latency histogram by route), token-protected `POST /cache/flush` (clear the response cache) and `POST /update/refresh` (pull lists/GeoIP immediately instead of waiting for the interval), an unauthenticated `/healthz` liveness probe, and a `/readyz` readiness probe that gates on listener startup and graceful shutdown.
* **Encrypted External Queries by Default**: `-exs` defaults to DNS-over-HTTPS, so interference cannot poison the external lookup itself. `-los`/`-exs` accept comma-separated lists of UDP, TCP and DoH addresses with in-order failover.
* **Modern `gohome/dns` Integration**: Powered by `gohome/dns` with parallel dual-stack queries, response caching and GeoIP anti-poisoning validation. The embedded domestic/interfered lists are loaded straight into the resolver.
* **Routing Priority**:
  1. Static `-hosts` entries win over everything and are answered locally.
  2. `.cn`, `.中国`, `.公司`, `.网络`, and the built-in domestic list go directly to the domestic DNS. A domestic name is not sent to the external DNS just because its address is on a foreign CDN.
  3. The built-in interfered list goes directly to the external DNS.
  4. A more specific domestic name wins over a blocked parent. `google.com` is external, while `adservice.google.com` stays domestic. The reverse conflict (a blocked name under a domestic parent, such as `api.recaptcha.net` under `recaptcha.net`) is forced to the external path as well.
  5. Any other name is queried using parallel dual-stack racing. If the domestic answer is poisoned or outside the domestic region, the secure external response is automatically preferred.

Example with token auth via environment variable:

```
YELLOWDNS_STATS_TOKEN=s3cret ./yellowdns -stats 127.0.0.1:8053
curl -H "Authorization: Bearer s3cret" http://127.0.0.1:8053/stats
curl -X POST -H "Authorization: Bearer s3cret" http://127.0.0.1:8053/cache/flush
curl -X POST -H "Authorization: Bearer s3cret" http://127.0.0.1:8053/update/refresh
```

# Data

The country database is [DB-IP](https://db-ip.com/) Country Lite, licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Domestic names come from [dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list). Interfered names come from the gfw list in [v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat).

# Release

Push a version tag to build archives and publish them to GitHub Releases. Each zip contains the binary (with the tag baked in via `-X main.version`, shown by `-version`) and `GeoLite2-Country.mmdb`.

```
git tag 0.5
git push origin 0.5
```
