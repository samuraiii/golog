//go:build windows

package main

import (
	"os"
	"os/signal"
	"sync"

	"github.com/samuraiii/golog/internal/golog"
)

var (
	curMu  sync.Mutex
	curSrv *golog.Server
)

// handleSignals stops the daemon gracefully on Ctrl-C / console close and
// remembers the server so the service handler can stop it.
func handleSignals(s *golog.Server) {
	curMu.Lock()
	curSrv = s
	curMu.Unlock()
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, os.Interrupt)
	go func() {
		<-ch
		golog.Logf("golog: interrupt received, shutting down")
		s.Shutdown()
	}()
}

// stopCurrent shuts the running server down (service stop); false when it has
// not started yet.
func stopCurrent() bool {
	curMu.Lock()
	s := curSrv
	curMu.Unlock()
	if nil == s {
		return false
	}
	s.Shutdown()
	return true
}
