package acme

import (
	"errors"
	"sync"
)

const cacheSize = 32

// validateNonce returns a non-nil error if nonce is empty or nonce contains any character not included in the
// base64url charset.
func validateNonce(nonce string) error {
	var (
		i int
		c byte
	)
	if nonce == "" {
		return errors.New("no nonce provided")
	}
	for i = range nonce {
		c = nonce[i]
		switch {
		case c == '-':
		case c >= '0' && c <= '9':
		case c >= 'A' && c <= 'Z':
		case c == '_':
		case c >= 'a' && c <= 'z':
		default:
			return errors.New("invalid nonce: " + nonce)
		}
	}
	return nil
}

type nonceCache struct {
	sync.Mutex
	r, w uint64
	buf  [cacheSize]string
}

func (n *nonceCache) get() string {
	n.Lock()
	defer n.Unlock()
	if n.r < n.w {
		// we can take
		x := n.buf[n.r%cacheSize]
		n.r++
		return x
	}
	return ""
}

func (n *nonceCache) put(s string) {
	n.Lock()
	if n.w-n.r == cacheSize {
		n.r++
	}
	n.buf[n.w%cacheSize] = s
	n.w++
	defer n.Unlock()
}
