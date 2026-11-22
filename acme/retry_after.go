package acme

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

const DefaultInterval = 5 * time.Second

type retryAfter time.Time

func (r *retryAfter) parse(res *http.Response, interval time.Duration) {
	t := parseRetryAfterHeader(res.Header.Get("Retry-After"))
	if t.IsZero() {
		*r = retryAfter((time.Now().Add(interval)))
	} else {
		*r = retryAfter(t)
	}
}

func pause(ctx context.Context, r retryAfter) error {
	wait := time.Until(time.Time(r))
	if wait <= 0 {
		return nil
	}

	select {
	case <-time.After(wait):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func parseRetryAfterHeader(s string) time.Time {
	var (
		t   time.Time
		n   int64
		err error
	)
	if s == "" {
		return t
	}
	// implemented either as a non-negative number of seconds OR a date time
	if n, err = strconv.ParseInt(s, 10, 64); err == nil {
		if n < 0 {
			return t
		}
		return time.Now().Add(time.Duration(n) * time.Second)
	}

	t, _ = time.Parse(http.TimeFormat, s)

	return t
}
