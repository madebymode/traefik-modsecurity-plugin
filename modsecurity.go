// Package traefik_modsecurity_plugin a modsecurity plugin.
package traefik_modsecurity_plugin

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// Config the plugin configuration.
type Config struct {
	TimeoutMillis                  int64  `json:"timeoutMillis,omitempty"`
	ModSecurityUrl                 string `json:"modSecurityUrl,omitempty"`
	UnhealthyWafBackOffPeriodSecs  int    `json:"unhealthyWafBackOffPeriodSecs,omitempty"`  // If the WAF is unhealthy, back off
	ModSecurityStatusRequestHeader string `json:"modSecurityStatusRequestHeader,omitempty"` // Header name to add to request when blocked (for logging)
	MaxConnsPerHost                int    `json:"maxConnsPerHost,omitempty"`                // Maximum connections per host (0 = unlimited, original default)
	MaxIdleConnsPerHost            int    `json:"maxIdleConnsPerHost,omitempty"`            // Maximum idle connections per host (0 = unlimited, original default)
	ResponseHeaderTimeoutMillis    int64  `json:"responseHeaderTimeoutMillis,omitempty"`    // Timeout for response headers (0 = no timeout, original default)
	ExpectContinueTimeoutMillis    int64  `json:"expectContinueTimeoutMillis,omitempty"`    // Timeout for Expect: 100-continue (default 1000ms)
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		TimeoutMillis:                  2000, // Original default: 2 seconds
		UnhealthyWafBackOffPeriodSecs:  0,    // 0 to NOT backoff (original behaviour)
		ModSecurityStatusRequestHeader: "",   // Empty string means no header will be added
		MaxConnsPerHost:                0,    // 0 = unlimited connections per host (original default)
		MaxIdleConnsPerHost:            0,    // 0 = unlimited idle connections per host (original default)
		ResponseHeaderTimeoutMillis:    0,    // 0 = no response header timeout (original default)
		ExpectContinueTimeoutMillis:    1000, // 1 second (original default)
	}
}

// Modsecurity a Modsecurity plugin.
type Modsecurity struct {
	next                           http.Handler
	modSecurityUrl                 string
	name                           string
	httpClient                     *http.Client
	logger                         *log.Logger
	unhealthyWafBackOffPeriodSecs  int
	unhealthyWaf                   bool // If the WAF is unhealthy
	unhealthyWafMutex              sync.Mutex
	modSecurityStatusRequestHeader string // Header name to add to request when blocked (for logging)
}

// New creates a new Modsecurity plugin with the given configuration.
// It returns an HTTP handler that can be integrated into the Traefik middleware chain.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.ModSecurityUrl) == 0 {
		return nil, fmt.Errorf("modSecurityUrl cannot be empty")
	}

	// Use a custom client with configurable timeout
	var timeout time.Duration
	if config.TimeoutMillis == 0 {
		timeout = 2 * time.Second // Original default: 2 seconds
	} else {
		timeout = time.Duration(config.TimeoutMillis) * time.Millisecond
	}

	// dialer is a custom net.Dialer with a specified timeout and keep-alive duration.
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// transport is a custom http.Transport with configurable timeouts and connection limits
	transport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}

	// Configure connection limits (0 = unlimited, original behavior)
	if config.MaxConnsPerHost > 0 {
		transport.MaxConnsPerHost = config.MaxConnsPerHost
	}
	if config.MaxIdleConnsPerHost > 0 {
		transport.MaxIdleConnsPerHost = config.MaxIdleConnsPerHost
	}

	// Configure response header timeout (0 = no timeout, original behavior)
	if config.ResponseHeaderTimeoutMillis > 0 {
		transport.ResponseHeaderTimeout = time.Duration(config.ResponseHeaderTimeoutMillis) * time.Millisecond
	}

	// Configure Expect: 100-continue timeout
	if config.ExpectContinueTimeoutMillis > 0 {
		transport.ExpectContinueTimeout = time.Duration(config.ExpectContinueTimeoutMillis) * time.Millisecond
	}

	return &Modsecurity{
		modSecurityUrl:                 config.ModSecurityUrl,
		next:                           next,
		name:                           name,
		httpClient:                     &http.Client{Timeout: timeout, Transport: transport},
		logger:                         log.New(os.Stdout, "", log.LstdFlags),
		unhealthyWafBackOffPeriodSecs:  config.UnhealthyWafBackOffPeriodSecs,
		modSecurityStatusRequestHeader: config.ModSecurityStatusRequestHeader,
	}, nil
}

func (a *Modsecurity) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if isWebsocket(req) {
		a.next.ServeHTTP(rw, req)
		return
	}

	// If the WAF is unhealthy just forward the request early. No concurrency control here on purpose.
	if a.unhealthyWaf {
		if a.modSecurityStatusRequestHeader != "" {
			req.Header.Set(a.modSecurityStatusRequestHeader, "unhealthy")
		}
		a.next.ServeHTTP(rw, req)
		return
	}

	// Buffer the body if we want to read it here and send it in the request.
	body, err := io.ReadAll(req.Body)
	if err != nil {
		a.logger.Printf("fail to read incoming request: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	url := a.modSecurityUrl + req.RequestURI

	proxyReq, err := http.NewRequest(req.Method, url, bytes.NewReader(body))
	if err != nil {
		if a.modSecurityStatusRequestHeader != "" {
			req.Header.Set(a.modSecurityStatusRequestHeader, "cannotforward")
		}
		a.logger.Printf("fail to prepare forwarded request: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return
	}

	// We may want to filter some headers, otherwise we could just use a shallow copy
	proxyReq.Header = make(http.Header)
	for h, val := range req.Header {
		proxyReq.Header[h] = val
	}

	resp, err := a.httpClient.Do(proxyReq)
	if err != nil {
		if a.unhealthyWafBackOffPeriodSecs > 0 {
			a.unhealthyWafMutex.Lock()
			if !a.unhealthyWaf {
				a.logger.Printf("marking modsec as unhealthy for %ds fail to send HTTP request to modsec: %s", a.unhealthyWafBackOffPeriodSecs, err.Error())
				a.unhealthyWaf = true
				if a.modSecurityStatusRequestHeader != "" {
					req.Header.Set(a.modSecurityStatusRequestHeader, "error")
				}
				time.AfterFunc(time.Duration(a.unhealthyWafBackOffPeriodSecs)*time.Second, func() {
					a.unhealthyWafMutex.Lock()
					defer a.unhealthyWafMutex.Unlock()
					a.unhealthyWaf = false
					a.logger.Printf("modsec unhealthy backoff expired")
				})
			}
			a.unhealthyWafMutex.Unlock()
			a.next.ServeHTTP(rw, req)
			return
		}

		a.logger.Printf("fail to send HTTP request to modsec: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		// Add remediation header to request if configured (for logging purposes)
		if a.modSecurityStatusRequestHeader != "" {
			req.Header.Set(a.modSecurityStatusRequestHeader, fmt.Sprintf("%d", resp.StatusCode))
		}
		forwardResponse(resp, rw)
		return
	}

	a.next.ServeHTTP(rw, req)
}

func isWebsocket(req *http.Request) bool {
	for _, header := range req.Header["Upgrade"] {
		if header == "websocket" {
			return true
		}
	}
	return false
}

func forwardResponse(resp *http.Response, rw http.ResponseWriter) {
	dst := rw.Header()
	for k, vv := range resp.Header {
		dst[k] = append(dst[k][:0], vv...)
	}
	// Copy status
	rw.WriteHeader(resp.StatusCode)
	// Copy body
	io.Copy(rw, resp.Body)
}
