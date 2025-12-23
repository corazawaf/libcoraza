package main

import "C"

import (
	"io/fs"
	"os"
	"path"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
)

// combinedFS is a filesystem that routes paths first by checking the local filesystem
// and then the coreruleset rootfs.
type combinedFS struct {
	corerulesetFS fs.FS // coreruleset rootfs
	localFS       fs.FS // local filesystem
	rootFS        fs.FS // root filesystem
}

func (c *combinedFS) Open(name string) (fs.File, error) {
	// First try the local filesystem using os.Open directly
	var file fs.File
	var fileErr error
	if path.IsAbs(name) {
		file, fileErr = c.rootFS.Open(name)
	} else {
		file, fileErr = c.localFS.Open(name)
	}
	if fileErr != nil {
		return nil, fileErr
	}

	// Fallback to coreruleset FS
	if file, err := c.corerulesetFS.Open(name); err == nil {
		return file, nil
	}
	return file, nil
}

var rootFS fs.FS

func init() {
	rootFS = &combinedFS{
		corerulesetFS: coreruleset.FS,
		localFS:       os.DirFS("."),
		rootFS:        os.DirFS("/"),
	}
}
