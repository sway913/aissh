package aissh

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegistrationURL(t *testing.T) {
	for _, raw := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/v1", "https://example.com?q=1", "https://example.com#x", ""} {
		if _, err := registrationURL(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	if got, err := registrationURL(DefaultAPIURL + "/"); err != nil || got != DefaultAPIURL {
		t.Fatalf("%q %v", got, err)
	}
	h := registrationClient()
	defer h.CloseIdleConnections()
	cfg := h.Transport.(*http.Transport).TLSClientConfig
	if cfg.RootCAs != nil || cfg.InsecureSkipVerify {
		t.Fatal("registration must verify with public system roots")
	}
	if h.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("registration must not follow redirects")
	}
}

func TestRegistrationIP(t *testing.T) {
	for _, tc := range []struct{ peer, header, want string }{
		{"127.0.0.1:1234", "198.51.100.1", "198.51.100.1"},
		{"[::1]:1234", "198.51.100.2", "198.51.100.2"},
		{"198.51.100.3:1234", "198.51.100.1", "198.51.100.3"},
		{"127.0.0.1:1234", "invalid", "127.0.0.1"},
	} {
		r := httptest.NewRequest("POST", "/v1/register", nil)
		r.RemoteAddr = tc.peer
		r.Header.Set("CF-Connecting-IP", tc.header)
		if got := registrationIP(r); got != tc.want {
			t.Errorf("%s: got %s want %s", tc.peer, got, tc.want)
		}
	}
}
