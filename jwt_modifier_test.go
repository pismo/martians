package jwt

import (
	"net/http"
	"testing"

	"github.com/google/martian/log"
)

func TestJwtClaimModifier(t *testing.T) {

	log.SetLevel(3)

	m := NewJwtClaimModifier("user_id", "x-account-id")

	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("http.NewRequest(): got %v, want no error", err)
	}

	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ1c2VyX2lkIjoiMjQxMzk2NzAifQ.jAFwj5C6RTtTTx0If6An3gy_ZdaUZjHqRgTiuPLDbes")

	if err := m.ModifyRequest(req); err != nil {
		t.Fatalf("ModifyRequest(): got %v, want no error", err)
	}

	if got, want := req.Header.Get("x-account-id"), "24139670"; got != want {
		t.Errorf("req.Header.Get(%q): got %q, want %q", "x-account-id", got, want)
	}
}
