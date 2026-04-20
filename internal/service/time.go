// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Shravanth. All rights reserved.

package service

import "time"

// timeNow returns the current UTC time. It is a package-level var so tests can override it.
var timeNow = func() time.Time {
	return time.Now().UTC()
}
