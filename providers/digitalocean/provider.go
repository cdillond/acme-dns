package digitalocean

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"go.ciaran.lol/acme-dns/acme"
)

type ErrorResponse struct {
	Id      string `json:"id"`
	Message string `json:"message"`
}

func (e *ErrorResponse) Error() string {
	return fmt.Sprintf("digitalocean error: {id: %s, message: %s}", e.Id, e.Message)
}

const (
	BaseUrl = "https://api.digitalocean.com/v2/domains"
)

type Provider struct {
	token      string
	baseDomain string
}

func NewProvider(token string, baseDomain string) *Provider {
	return &Provider{
		token:      token,
		baseDomain: baseDomain,
	}
}

type domainRecordEditRequest struct {
	Type     string `json:"type,omitempty"`
	Name     string `json:"name,omitempty"`
	Data     string `json:"data,omitempty"`
	Priority int    `json:"priority"`
	Port     int    `json:"port"`
	TTL      int    `json:"ttl,omitempty"`
	Weight   int    `json:"weight"`
	Flags    int    `json:"flags"`
	Tag      string `json:"tag,omitempty"`
}

type domainResponse struct {
	domainRecord `json:"domain_record"`
}

type domainRecord struct {
	ID       int    `json:"id,omitempty"`
	Type     string `json:"type,omitempty"`
	Name     string `json:"name,omitempty"`
	Data     string `json:"data,omitempty"`
	Priority int    `json:"priority"`
	Port     int    `json:"port"`
	TTL      int    `json:"ttl,omitempty"`
	Weight   int    `json:"weight"`
	Flags    int    `json:"flags"`
	Tag      string `json:"tag,omitempty"`
}

func (p *Provider) do(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	var (
		err error
		req *http.Request
	)

	if req, err = http.NewRequest(method, url, body); err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", acme.UserAgent)
	req.Header.Set("Authorization", "Bearer "+p.token)

	return http.DefaultClient.Do(req)
}

func (p *Provider) deprovision(ctx context.Context, id int) error {
	var (
		err    error
		url    string
		res    *http.Response
		bad    ErrorResponse
		dec    *jsontext.Decoder
		log, _ = ctx.Value(acme.LogKey{}).(*slog.Logger)
	)

	if log != nil {
		log = log.With("provider", "digitalocean", "record_id", id)
		log.Info("deprovisioning dns record")
	}

	url = fmt.Sprintf("%s/%s/records/%d", BaseUrl, p.baseDomain, id)

	if res, err = p.do(ctx, http.MethodDelete, url, nil); err != nil {
		return err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	dec = jsontext.NewDecoder(res.Body)

	if res.StatusCode != http.StatusNoContent {
		if err = json.UnmarshalDecode(dec, &bad); err != nil {
			return err
		}
		err = &bad
		return err
	}

	if log != nil {
		log.Info("deprovisioned dns record")
	}

	return nil
}

func (p *Provider) Provision(ctx context.Context, txt acme.TxtRecord) (acme.CleanupFunc, error) {
	var (
		err error
		res *http.Response
		ans domainResponse
		bad ErrorResponse
		dec *jsontext.Decoder
		url = fmt.Sprintf("%s/%s/records", BaseUrl, p.baseDomain)
		d   = domainRecordEditRequest{
			Type: "TXT",
			Name: txt.Name,
			Data: txt.Value,
			TTL:  int(txt.TTL),
		}
		buf    = new(bytes.Buffer)
		enc    = jsontext.NewEncoder(buf)
		log, _ = ctx.Value(acme.LogKey{}).(*slog.Logger)
	)

	if log != nil {
		log = log.With("provider", "digitalocean", "record", txt)
		log.Info("provisioning dns record")
	}

	d.Name, _ = strings.CutSuffix(d.Name, "."+p.baseDomain)

	if err = json.MarshalEncode(enc, d); err != nil {
		return nil, err
	}

	if res, err = p.do(ctx, http.MethodPost, url, buf); err != nil {
		return nil, err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	dec = jsontext.NewDecoder(res.Body)

	if res.StatusCode != http.StatusCreated {
		if err = json.UnmarshalDecode(dec, &bad); err != nil {
			return nil, err
		}
		err = &bad
		return nil, err
	}

	if err = json.UnmarshalDecode(dec, &ans); err != nil {
		return nil, err
	}

	if log != nil {
		log.Info("provisioned dns record", "record_id", ans.ID)
	}

	return func(c context.Context) error {
		return p.deprovision(c, ans.ID)
	}, nil
}
