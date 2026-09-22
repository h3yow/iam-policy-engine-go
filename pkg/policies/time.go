package policies

import "time"

// timeLayouts are the accepted timestamp encodings in policy documents.
var timeLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05Z",
	"2006-01-02",
}

func parseTime(s string) (time.Time, error) {
	var lastErr error
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		} else {
			lastErr = err
		}
	}
	return time.Time{}, lastErr
}
