package aissh

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

//go:embed admin.html
var adminHTML []byte

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return fmt.Errorf("one JSON object required")
	}
	return nil
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	respond(w, status, map[string]string{"error": message})
}

type rateEntry struct {
	minute int64
	count  int
}

// Cloudflare overwrites this header. Only a local tunnel may supply it.
func registrationIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if peer := net.ParseIP(host); peer != nil && peer.IsLoopback() {
		if ip := net.ParseIP(r.Header.Get("CF-Connecting-IP")); ip != nil {
			return ip.String()
		}
	}
	return host
}

func DeviceHandler(s *Store) http.Handler {
	mux := http.NewServeMux()
	var mu sync.Mutex
	limits := map[string]rateEntry{}
	mux.HandleFunc("POST /v1/register", func(w http.ResponseWriter, r *http.Request) {
		ip := registrationIP(r)
		minute := time.Now().Unix() / 60
		mu.Lock()
		entry := limits[ip]
		if entry.minute != minute {
			entry = rateEntry{minute: minute}
		}
		entry.count++
		if len(limits) > 4096 {
			for k, v := range limits {
				if v.minute != minute {
					delete(limits, k)
				}
			}
		}
		blocked := entry.count > 10 || len(limits) > 8192
		limits[ip] = entry
		mu.Unlock()
		if blocked {
			fail(w, 429, "registration rate limit; retry later")
			return
		}
		var body Registration
		if e := decode(w, r, &body); e != nil {
			fail(w, 400, "invalid registration")
			return
		}
		c, e := s.Register(body)
		if e != nil {
			if e == ErrDenied {
				fail(w, 403, "device disabled")
			} else {
				fail(w, 400, "registration failed")
			}
			return
		}
		respond(w, 200, c)
	})
	mux.HandleFunc("GET /v1/config", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		c, e := s.Config(r.Header.Get("X-Aissh-Device"), token)
		if e != nil {
			fail(w, 401, "register again or contact administrator")
			return
		}
		respond(w, 200, c)
	})
	return mux
}

func AdminHandler(s *Store, password string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(adminHTML)
	})
	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) {
		ds, rs := s.Snapshot()
		respond(w, 200, map[string]any{"devices": ds, "rules": rs})
	})
	mux.HandleFunc("POST /api/devices", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		}
		if e := decode(w, r, &body); e != nil {
			fail(w, 400, "invalid request")
			return
		}
		if e := s.SetEnabled(body.ID, body.Enabled); e != nil {
			fail(w, 400, e.Error())
			return
		}
		s.RevokeConnections()
		respond(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/rules", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Source string `json:"source"`
			Target string `json:"target"`
			Allow  bool   `json:"allow"`
		}
		if e := decode(w, r, &body); e != nil {
			fail(w, 400, "invalid request")
			return
		}
		if e := s.SetRule(body.Source, body.Target, body.Allow); e != nil {
			fail(w, 400, e.Error())
			return
		}
		s.RevokeConnections()
		respond(w, 200, map[string]bool{"ok": true})
	})
	expected := sha256.Sum256([]byte(password))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'")
		user, pass, ok := r.BasicAuth()
		actual := sha256.Sum256([]byte(pass))
		if !ok || user != "admin" || subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="aissh", charset="UTF-8"`)
			http.Error(w, "authentication required", 401)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				fail(w, 415, "JSON required")
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" {
				u, e := url.Parse(origin)
				if e != nil || u.Host != r.Host {
					fail(w, 403, "origin denied")
					return
				}
			}
		}
		mux.ServeHTTP(w, r)
	})
}
