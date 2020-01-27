package header

import (
	"net/http"
	"testing"

	"github.com/google/martian"
	"github.com/google/martian/v3/log"
)

func TestJwtUriVerification(t *testing.T) {
	log.SetLevel(3)

	v := NewJwtUriVerifier("user_id", "accounts")

	tt := []struct {
		url   string
		token string
		got   string
		want  string
	}{
		{
			url:   "https://api.example.com/accounts/v1/accounts/24139670",
			token: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ1c2VyX2lkIjoiMjQxMzk2NzAifQ.jAFwj5C6RTtTTx0If6An3gy_ZdaUZjHqRgTiuPLDbes",
			got:   "24139670",
			want:  "24139670",
		},
	}

	for i, tc := range tt {
		req, err := http.NewRequest("GET", tc.url, nil)
		if err != nil {
			t.Fatalf("%d. http.NewRequest(): got %v, want no error", i, err)
		}

		req.Header.Set("Authorization", tc.token)

		_, remove, err := martian.TestContext(req, nil, nil)
		if err != nil {
			t.Fatalf("TestContext(): got %v, want no error", err)
		}
		defer remove()

		if err := v.ModifyRequest(req); err != nil {
			t.Fatalf("%d. ModifyRequest(): got %v, want no error", i, err)
		}
	}

	err := v.VerifyRequests()
	if err != nil {
		t.Fatal("VerifyRequests(): got err, want no error")
	}

}

func TestJwtUriVerificationErrors(t *testing.T) {

	log.SetLevel(3)

	v := NewJwtUriVerifier("user_id", "accounts")

	tt := []struct {
		url   string
		token string
		got   string
		want  string
	}{
		{
			url:   "https://api.example.com/accounts/v1/accounts/10",
			token: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ1c2VyX2lkIjoiMjQxMzk2NzAifQ.jAFwj5C6RTtTTx0If6An3gy_ZdaUZjHqRgTiuPLDbes",
			got:   "10",
			want:  "24139670",
		},
		{
			url:   "https://api.example.com/crm/v1/customers/10/accounts/50",
			token: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ1c2VyX2lkIjoiMjQxMzk2NzAifQ.jAFwj5C6RTtTTx0If6An3gy_ZdaUZjHqRgTiuPLDbes",
			got:   "50",
			want:  "24139670",
		},
	}

	for i, tc := range tt {
		req, err := http.NewRequest("GET", tc.url, nil)
		if err != nil {
			t.Fatalf("%d. http.NewRequest(): got %v, want no error", i, err)
		}

		req.Header.Set("Authorization", tc.token)

		_, remove, err := martian.TestContext(req, nil, nil)
		if err != nil {
			t.Fatalf("TestContext(): got %v, want no error", err)
		}
		defer remove()

		if err := v.ModifyRequest(req); err != nil {
			t.Fatalf("%d. ModifyRequest(): got %v, want no error", i, err)
		}
	}

	merr, ok := v.VerifyRequests().(*martian.MultiError)
	if !ok {
		t.Fatal("VerifyRequests(): got nil, want *verify.MultiError")
	}

	errs := merr.Errors()
	if got, want := len(errs), len(tt); got != want {
		t.Fatalf("len(merr.Errors(): got %d, want %d", got, want)
	}
}
