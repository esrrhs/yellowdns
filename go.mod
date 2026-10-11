module github.com/esrrhs/yellowdns

go 1.27.1

require (
	github.com/esrrhs/gohome v0.0.0-20261008233426-8124be7601dc
	github.com/miekg/dns v1.1.73
	github.com/oschwald/geoip2-golang v1.13.0
	github.com/oschwald/maxminddb-golang v1.13.1
	golang.org/x/net v0.59.0
)

// gohome 未发布 RegionCode 改动前的临时本地替换；
// gohome 推送新版本后可移除本行并重新 go mod vendor。
replace github.com/esrrhs/gohome => ../gohome

require (
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
