package engine

import "time"

// wallClock mirrors time.Time behind an indirection so tests stay readable;
// production code simply uses the real clock.
type wallClock = time.Time

func currentTime() time.Time { return time.Now().UTC() }
