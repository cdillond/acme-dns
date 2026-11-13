package acme

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

type RetryError int

func (r RetryError) Error() string {
	return fmt.Sprintf("retries exhausted: %d", r)
}

const DefaultInterval = 5 * time.Second

type retryAfter time.Time

func (r *retryAfter) parseRetryAfter(res *http.Response) {
	t := parseRetryAfterHeader(res.Header.Get("Retry-After"))
	if t.IsZero() {
		*r = retryAfter((time.Now().Add(DefaultInterval)))
	} else {
		*r = retryAfter(t)
	}
}

func (r *retryAfter) wait() <-chan time.Time {
	return time.After(time.Until(time.Time(*r)))
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
