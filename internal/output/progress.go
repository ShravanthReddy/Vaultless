// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package output

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Spinner shows an animated spinner for long-running operations.
type Spinner struct {
	message string
	stop    chan struct{}
	done    sync.WaitGroup
	active  bool
}

// NewSpinner creates a new spinner with the given message.
func NewSpinner(message string) *Spinner {
	return &Spinner{
		message: message,
		stop:    make(chan struct{}),
	}
}

// Start begins the spinner animation.
func (s *Spinner) Start() {
	if s.active {
		return
	}
	s.active = true
	s.done.Add(1)
	go func() {
		defer s.done.Done()
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		i := 0
		for {
			select {
			case <-s.stop:
				fmt.Fprintf(os.Stderr, "\r\033[K")
				return
			default:
				fmt.Fprintf(os.Stderr, "\r%s %s", frames[i%len(frames)], s.message)
				i++
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
}

// Stop stops the spinner.
func (s *Spinner) Stop() {
	if !s.active {
		return
	}
	close(s.stop)
	s.done.Wait()
	s.active = false
}
