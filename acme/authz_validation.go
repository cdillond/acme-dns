package acme

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

func (c *Client) provisionChallenge(ctx context.Context, key es256Key, az authz, x *challenge, domains map[string]Provider, ttl uint16) (TXTRecord, CleanupFunc, error) {

	n := az.Identifier.Value
	if az.Wildcard {
		n = "*." + n
	}

	p := domains[n]
	if p == nil {
		return TXTRecord{}, nil, errors.New("could not find registered provider")
	}

	txt := TXTRecord{
		TTL:   ttl,
		Name:  "_acme-challenge." + az.Identifier.Value,
		Value: newDNS01Txt(x.Token, key),
	}

	fn, err := p.Provision(withLogger(ctx, c.Log), txt)
	if err != nil {
		return TXTRecord{}, nil, err
	}

	return txt, fn, nil
}

func (c *Client) handleChallenge(ctx context.Context, id string, key es256Key, az authz, domains map[string]Provider, cfg OrderCfg) (err error) {
	x := pickDNSChallenge(az.Challenges)
	if x == nil {
		return errors.New("no dns challenge available for Authz")
	}

	switch x.Status {
	case challengeStatusInvalid:
		return joinProblem(errors.Join(ErrFailedChallenge, fmt.Errorf("challenge %q invalid", x.URL)), x.Error)
	case challengeStatusPending:
		break
	case challengeStatusProcessing:
		// the challenge has already been accepted, but has not been completed.
		// if we are here, then it means a previous challenge aborted after accepting.
		// we should re-provision the record, but avoid sending an accept request.
		break
	case challengeStatusValid:
		return nil
	default:
		return UnexpectedChallengeStatusError(x.Status)
	}

	var (
		txt TXTRecord
		fn  CleanupFunc
		raw rawChallenge
	)

	// step 1: provision dns record
	if txt, fn, err = c.provisionChallenge(ctx, key, az, x, domains, cfg.RecordTTLSeconds); err != nil {
		return err
	}

	defer func() {
		err = errors.Join(err, cleanup(ctx, fn))
	}()

	// step 2: confirm propagation
	if err = pollForDNS(ctx, c.Log, cfg.Resolver, txt, c.PollInterval); err != nil {
		return err
	}

	// step 3: accept challenge if pending
	if x.Status == challengeStatusPending {
		if raw, err = c.acceptChallenge(ctx, x.URL, id, key); err != nil {
			return err
		}
	} else {
		raw = rawChallenge{
			Type:   x.Type,
			URL:    x.URL,
			Status: x.Status,
			Token:  x.Token,
			Error:  x.Error,
		}
	}

	return raw.poll(ctx, c, id, key)

}

func (c *Client) handleAuth(ctx context.Context, url, id string, key es256Key, domains map[string]Provider, cfg OrderCfg) (err error) {
	var a authz
	if err = c.fetchUnmarshalAuthz(ctx, url, id, key, &a); err != nil {
		return err
	}

	switch a.Status {
	case authzStatusPending:
		if err = c.handleChallenge(ctx, id, key, a, domains, cfg); err != nil {
			return err
		}
		return c.pollForAuth(ctx, url, id, key)
	case authzStatusValid:
		return nil
	case authzStatusInvalid, authzStatusDeactivated, authzStatusExpired, authzStatusRevoked:
		return fmt.Errorf("%q has status %s: %w", a.Identifier.Value, a.Status, ErrFailedAuthz)
	default:
		return UnexpectedAuthzStatusError(a.Status)
	}
}

func (c *Client) handlePendingOrder(ctx context.Context, id string, key es256Key, o *order, providers map[string]Provider, cfg OrderCfg) error {
	var (
		wg            sync.WaitGroup
		ch            = make(chan error, len(o.Authorizations))
		child, cancel = context.WithCancel(ctx)
		err           error
	)

	defer cancel()

	for _, s := range o.Authorizations {
		url := s
		wg.Go(
			func() {
				res := c.handleAuth(child, url, id, key, providers, cfg)
				if res != nil {
					res = fmt.Errorf("authorization %q: %w", url, res)
				}
				ch <- res
			},
		)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	for authzErr := range ch {
		if authzErr == nil {
			continue
		}
		if err == nil {
			cancel()
		}
		err = errors.Join(err, authzErr)
	}

	return err
}
