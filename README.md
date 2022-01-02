# yellowdns

[<img src="https://img.shields.io/github/license/esrrhs/yellowdns">](https://github.com/esrrhs/yellowdns)
[<img src="https://img.shields.io/github/languages/top/esrrhs/yellowdns">](https://github.com/esrrhs/yellowdns)
[![Go Report Card](https://goreportcard.com/badge/github.com/esrrhs/yellowdns)](https://goreportcard.com/report/github.com/esrrhs/yellowdns)
[<img src="https://img.shields.io/github/v/release/esrrhs/yellowdns">](https://github.com/esrrhs/yellowdns/releases)
[<img src="https://img.shields.io/github/downloads/esrrhs/yellowdns/total">](https://github.com/esrrhs/yellowdns/releases)
[<img src="https://img.shields.io/docker/pulls/esrrhs/yellowdns">](https://hub.docker.com/repository/docker/esrrhs/yellowdns)
[<img src="https://img.shields.io/github/workflow/status/esrrhs/yellowdns/Go">](https://github.com/esrrhs/yellowdns/actions)

简单的dns proxy，根据地域转发到不同的dns server，解决访问境外dns的问题

# 使用
直接启动
```
./yellowdns
```
等价于
```
./yellowdns -l :53 -los 114.114.114.114:53 -exs 8.8.8.8:53 -lor CN -lof GeoLite2-Country.mmdb
```
或者使用docker
```
docker run --name yellowdns -d --net=host --restart=always -p 55353:55353/udp esrrhs/yellowdns ./yellowdns -l :55353 -exs 127.0.0.1:55354
```
如果提示53端口被占用，看看是不是其他网卡被占了，那么修改成127.0.0.1:53即可

# 参数说明
* -l：监听的udp地址，默认53

* -los: 境内的dns server，默认114.114.114.114:53，域名解析时，先走境内dns server，发现如果是境外ip，则再重新走境外的dns server

* -exs：境外的dns server，默认8.8.8.8:53，境外的ip都用这个dns server做解析

* -lor: 境内的定义，默认CN

* -lof: ip查询国家的数据库文件

* 其他的选项，参考-h
