package cloudflare

import (
	"context"
	"errors"
	"testing"
)

var errSimulatedMarshal = errors.New("simulated marshal error")

func mockJSONMarshalFail(_ any) ([]byte, error) {
	return nil, errSimulatedMarshal
}

func TestClient_AddItems_MarshalError(t *testing.T) {
	prev := jsonMarshal
	jsonMarshal = mockJSONMarshalFail
	t.Cleanup(func() {
		jsonMarshal = prev
	})

	client := NewClient("cf-auth-add", nil)
	err := client.AddItems(context.Background(), "acc-add", "list-add", []ItemPayload{{IP: "192.0.2.1"}})
	if err == nil || !errors.Is(err, errSimulatedMarshal) {
		t.Fatalf("AddItems() error = %v, want %v", err, errSimulatedMarshal)
	}
}

func TestClient_DeleteItems_MarshalError(t *testing.T) {
	prev := jsonMarshal
	jsonMarshal = mockJSONMarshalFail
	t.Cleanup(func() {
		jsonMarshal = prev
	})

	client := NewClient("cf-auth-del", nil)
	err := client.DeleteItems(context.Background(), "acc-del", "list-del", []string{"id-del-1"})
	if err == nil || !errors.Is(err, errSimulatedMarshal) {
		t.Fatalf("DeleteItems() error = %v, want %v", err, errSimulatedMarshal)
	}
}
