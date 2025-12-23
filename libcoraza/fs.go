package main

import "C"

import (
	"io/fs"
	"os"
	"path"
)

// combinedFS is a filesystem that routes paths by checking both the local and root filesystems.
type combinedFS struct {
	localFS fs.FS // local filesystem
	rootFS  fs.FS // root filesystem
}

func (c *combinedFS) Open(name string) (fs.File, error) {
	if path.IsAbs(name) {
		return c.rootFS.Open(name)
	} else {
		return c.localFS.Open(name)
	}
}

var rootFS fs.FS

func init() {
	rootFS = &combinedFS{
		localFS: os.DirFS("."),
		rootFS:  os.DirFS("/"),
	}
}
