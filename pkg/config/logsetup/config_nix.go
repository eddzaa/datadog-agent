//go:build linux || freebsd || netbsd || openbsd || solaris || dragonfly || darwin || aix

package logsetup

const defaultSyslogURI = "unixgram:///dev/log"
