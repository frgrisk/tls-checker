package cmd

import (
	"os"

	"github.com/charmbracelet/log"
)

var logger *log.Logger

func init() {
	logger = log.NewWithOptions(os.Stderr, log.Options{
		ReportCaller:    false,
		Level:           log.InfoLevel,
		CallerFormatter: log.LongCallerFormatter,
	})
}
