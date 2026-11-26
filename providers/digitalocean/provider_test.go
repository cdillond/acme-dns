package digitalocean

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/digitalocean/godo"

	"go.ciaran.lol/acme-dns/acme"
)

type fakeDomainsClient struct {
	createReq  *godo.DomainRecordEditRequest
	createResp *godo.DomainRecord
	createErr  error

	deleteID  int
	deleteErr error
}

func (f *fakeDomainsClient) CreateRecord(_ context.Context, _ string, req *godo.DomainRecordEditRequest) (*godo.DomainRecord, *godo.Response, error) {
	f.createReq = req
	return f.createResp, nil, f.createErr
}

func (f *fakeDomainsClient) DeleteRecord(_ context.Context, _ string, id int) (*godo.Response, error) {
	f.deleteID = id
	return nil, f.deleteErr
}

func TestProvisionCreatesRelativeTXTRecord(t *testing.T) {
	client := &fakeDomainsClient{
		createResp: &godo.DomainRecord{ID: 42},
	}
	p := &Provider{client: client, baseDomain: "example.com"}

	cleanup, err := p.Provision(context.Background(), acme.TXTRecord{
		TTL:   60,
		Name:  "_acme-challenge.www.example.com",
		Value: "challenge-value",
	})
	if err != nil {
		t.Fatalf("Provision returned an error: %v", err)
	}
	if cleanup == nil {
		t.Fatal("Provision returned a nil cleanup function")
	}

	if client.createReq == nil {
		t.Fatal("CreateRecord was not called")
	}
	want := &godo.DomainRecordEditRequest{
		Type: "TXT",
		Name: "_acme-challenge.www",
		Data: "challenge-value",
		TTL:  60,
	}
	if *client.createReq != *want {
		t.Fatalf("CreateRecord request = %#v, want %#v", *client.createReq, *want)
	}

	if err = cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup returned an error: %v", err)
	}
	if client.deleteID != 42 {
		t.Fatalf("DeleteRecord ID = %d, want 42", client.deleteID)
	}
}

func TestProvisionRejectsRecordOutsideBaseDomain(t *testing.T) {
	client := &fakeDomainsClient{}
	p := &Provider{client: client, baseDomain: "example.com"}

	if _, err := p.Provision(context.Background(), acme.TXTRecord{
		Name:  "_acme-challenge.example.net",
		Value: "challenge-value",
	}); err == nil {
		t.Fatal("Provision accepted a record outside the managed domain")
	}
	if client.createReq != nil {
		t.Fatal("CreateRecord was called for an invalid record")
	}
}

func TestCleanupIgnoresMissingRecord(t *testing.T) {
	client := &fakeDomainsClient{
		deleteErr: &godo.ErrorResponse{
			Response: &http.Response{StatusCode: http.StatusNotFound},
			Message:  "record not found",
		},
	}
	p := &Provider{client: client, baseDomain: "example.com"}

	err := p.deprovision(context.Background(), 42)
	if err != nil {
		t.Fatalf("deprovision returned an error for a missing record: %v", err)
	}
	if client.deleteID != 42 {
		t.Fatalf("DeleteRecord ID = %d, want 42", client.deleteID)
	}
}

func TestCleanupReturnsOtherAPIErrors(t *testing.T) {
	apiErr := &godo.ErrorResponse{
		Response: &http.Response{StatusCode: http.StatusInternalServerError},
		Message:  "server error",
	}
	client := &fakeDomainsClient{deleteErr: apiErr}
	p := &Provider{client: client, baseDomain: "example.com"}

	err := p.deprovision(context.Background(), 42)
	if !errors.Is(err, apiErr) {
		t.Fatalf("deprovision error = %v, want wrapped %v", err, apiErr)
	}
}
