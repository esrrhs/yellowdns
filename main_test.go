package main

import (
	"os"
	"testing"

	"github.com/esrrhs/gohome/loggo"
)

// TestMain 静默日志：loggo 未初始化时会向工作目录写 default_*.log，
// 测试只关心路由结果，关闭文件与标准输出。
func TestMain(m *testing.M) {
	loggo.Ini(loggo.Config{
		Level:     loggo.LEVEL_ERROR + 1,
		Prefix:    "test",
		NoLogFile: true,
		NoPrint:   true,
	})
	os.Exit(m.Run())
}
