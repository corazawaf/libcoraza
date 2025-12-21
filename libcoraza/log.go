package main

import "C"
import (
	"io"
	"log"

	"github.com/corazawaf/coraza/v3/debuglog"
)

var _ debuglog.Logger = logger{}

type logger struct {
	debuglog.Logger
	writer io.Writer
}

var _ debuglog.Logger = logger{}

func newDebugLogger(defaultPrinter debuglog.Printer) debuglog.Logger {
	logger := logger{
		writer: nil,
	}
	logger.Logger = debuglog.DefaultWithPrinterFactory(func(w io.Writer) debuglog.Printer {
		if logger.writer != nil {
			return func(lvl debuglog.Level, message, fields string) {
				log.New(logger.writer, "", log.LstdFlags).Printf("[%s] %s %s", lvl.String(), message, fields)
			}
		}
		return defaultPrinter
	})
	return logger
}

func (l logger) WithLevel(lvl debuglog.Level) debuglog.Logger {
	return logger{
		Logger: l.Logger.WithLevel(lvl),
	}
}

func (l logger) WithOutput(w io.Writer) debuglog.Logger {
	return logger{
		Logger: l,
		writer: w,
	}
}
