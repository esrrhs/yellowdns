//go:build windows

package main

import (
	"os"
	"os/signal"
)

// setupSignalHandler 在 Windows 上没有 SIGHUP 概念，仅支持 Ctrl+C 退出；
// 域名列表更新后需重启进程。
func setupSignalHandler(onReload func(), onStop func()) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	go func() {
		<-stop
		onStop()
	}()
}
