package acme

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"testing/synctest"
	"time"
)

func TestParseRetryAfterHeaderSeconds(t *testing.T) {
	before := time.Now()
	got := parseRetryAfterHeader("2")
	after := time.Now()

	if got.Before(before.Add(2*time.Second)) || got.After(after.Add(2*time.Second)) {
		t.Fatalf("retry time = %v, want about %v", got, before.Add(2*time.Second))
	}
}

func TestParseRetryAfterHeaderHTTPDate(t *testing.T) {
	want := time.Date(2026, time.November, 26, 12, 0, 0, 0, time.UTC)
	if got := parseRetryAfterHeader(want.Format(http.TimeFormat)); !got.Equal(want) {
		t.Fatalf("retry time = %v, want %v", got, want)
	}
}

func TestParseRetryAfterHeaderInvalid(t *testing.T) {
	for _, s := range []string{"", "-1", "nope"} {
		if got := parseRetryAfterHeader(s); !got.IsZero() {
			t.Errorf("parseRetryAfterHeader(%q) = %v, want zero time", s, got)
		}
	}
}

func TestRetryAfterParseUsesIntervalFallback(t *testing.T) {
	res := &http.Response{Header: make(http.Header)}
	before := time.Now()

	var r retryAfter
	r.parse(res, time.Minute)
	after := time.Now()

	want := before.Add(time.Minute)
	if got := time.Time(r); got.Before(want) || got.After(after.Add(time.Minute)) {
		t.Fatalf("retry time = %v, want about %v", got, want)
	}
}

func TestRetryAfterParseUsesHeader(t *testing.T) {
	t.Run("delta seconds", func(t *testing.T) {
		res := &http.Response{Header: make(http.Header)}
		res.Header.Set("Retry-After", "2")

		before := time.Now()
		var r retryAfter
		// A long fallback interval makes it clear the header value won.
		r.parse(res, time.Hour)
		after := time.Now()

		want := before.Add(2 * time.Second)
		if got := time.Time(r); got.Before(want) || got.After(after.Add(2*time.Second)) {
			t.Fatalf("retry time = %v, want about %v", got, want)
		}
	})

	t.Run("HTTP date", func(t *testing.T) {
		wantTime := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
		res := &http.Response{Header: make(http.Header)}
		res.Header.Set("Retry-After", wantTime.Format(http.TimeFormat))

		var r retryAfter
		r.parse(res, time.Hour)
		if got := time.Time(r); !got.Equal(wantTime) {
			t.Fatalf("retry time = %v, want %v", got, wantTime)
		}
	})
}

func TestPauseWithPastDeadline(t *testing.T) {
	if err := pause(context.Background(), retryAfter(time.Now().Add(-time.Second))); err != nil {
		t.Fatalf("pause with past deadline returned %v", err)
	}
}

func TestPauseWithCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := pause(ctx, retryAfter(time.Now().Add(time.Hour)))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("pause error = %v, want context.Canceled", err)
	}
}

func TestPauseWaitsUntilDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const wait = 2 * time.Second

		start := time.Now()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			done <- pause(ctx, retryAfter(start.Add(wait)))
		}()

		synctest.Wait()
		assertNotReturned := func() {
			t.Helper()
			select {
			case err := <-done:
				t.Fatalf("pause returned before the deadline: %v", err)
			default:
			}
		}
		assertNotReturned()

		time.Sleep(wait - time.Nanosecond)
		synctest.Wait()
		assertNotReturned()

		time.Sleep(time.Nanosecond)
		synctest.Wait()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("pause error = %v, want nil", err)
			}
		default:
			t.Fatal("pause did not return at the deadline")
		}
		if elapsed := time.Since(start); elapsed != wait {
			t.Fatalf("elapsed = %v, want %v", elapsed, wait)
		}
	})
}
