package aissh

import "fmt"

// Version and Commit are supplied by the release build; local builds use dev.
var Version = "dev"
var Commit = "unknown"

func VersionString() string { return fmt.Sprintf("aissh %s (%s)", Version, Commit) }
