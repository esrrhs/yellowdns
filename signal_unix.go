//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// setupSignalHandler 在 Unix 上：SIGHUP 触发热重载，SIGINT/SIGTERM 优雅退出。
func setupSignalHandler(onReload func(), onStop func()) {
	hup := make(chan os.Signal, 1)
	stop := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		for {
			select {
			case <-hup:
				onReload()
			case <-stop:
				onStop()
				return
			}
		}
	}()
}
