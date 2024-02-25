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
	TimeoutMillis              int64  `json:"timeoutMillis"`
	ModSecurityUrl             string `json:"modSecurityUrl,omitempty"`
	JailEnabled                bool   `json:"jailEnabled"`
	BadRequestsThresholdCount  int    `json:"badRequestsThresholdCount"`
	BadRequestsThresholdPeriod int    `json:"badRequestsThresholdPeriod"` // Period in seconds to track attempts
	JailTimeDuration           int    `json:"jailTimeDuration"`           // How long a client spends in Jail in seconds
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		TimeoutMillis:              2000,
		JailEnabled:                false,
		BadRequestsThresholdCount:  25,
		BadRequestsThresholdPeriod: 600,
		JailTimeDuration:           600,
	}
}

// Modsecurity a Modsecurity plugin.
type Modsecurity struct {
	next                       http.Handler
	modSecurityUrl             string
	name                       string
	httpClient                 *http.Client
	logger                     *log.Logger
	jailEnabled                bool
	badRequestsThresholdCount  int
	badRequestsThresholdPeriod int
	jailTimeDuration           int
	jail                       map[string][]time.Time
	jailRelease                map[string]time.Time
	jailMutex                  sync.RWMutex
}

// New creates a new Modsecurity plugin with the given configuration.
// It returns an HTTP handler that can be integrated into the Traefik middleware chain.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.ModSecurityUrl) == 0 {
		return nil, fmt.Errorf("modSecurityUrl cannot be empty")
	}

	// Use a custom client with predefined timeout of 2 seconds
	var timeout time.Duration
	if config.TimeoutMillis == 0 {
		timeout = 2 * time.Second
	} else {
		timeout = time.Duration(config.TimeoutMillis) * time.Millisecond
	}

	// dialer is a custom net.Dialer with a specified timeout and keep-alive duration.
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// transport is a custom http.Transport with various timeouts and configurations for optimal performance.
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

	return &Modsecurity{
		modSecurityUrl:             config.ModSecurityUrl,
		next:                       next,
		name:                       name,
		httpClient:                 &http.Client{Timeout: timeout, Transport: transport},
		logger:                     log.New(os.Stdout, "", log.LstdFlags),
		jailEnabled:                config.JailEnabled,
		badRequestsThresholdCount:  config.BadRequestsThresholdCount,
		badRequestsThresholdPeriod: config.BadRequestsThresholdPeriod,
		jailTimeDuration:           config.JailTimeDuration,
		jail:                       make(map[string][]time.Time),
		jailRelease:                make(map[string]time.Time),
	}, nil
}

func (a *Modsecurity) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if isWebsocket(req) {
		a.next.ServeHTTP(rw, req)
		return
	}

	clientIP := req.RemoteAddr

	// Check if the client is in jail, if jail is enabled
	if a.jailEnabled {
		a.jailMutex.RLock()
		if a.isClientInJail(clientIP) {
			a.jailMutex.RUnlock()
			a.logger.Printf("client %s is jailed", clientIP)
			http.Error(rw, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		a.jailMutex.RUnlock()
	}

	// Buffer the body if we want to read it here and send it in the request.
	body, err := io.ReadAll(req.Body)
	if err != nil {
		a.logger.Printf("fail to read incoming request: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	// Create a new URL from the raw RequestURI sent by the client
	url := fmt.Sprintf("%s%s", a.modSecurityUrl, req.RequestURI)

	proxyReq, err := http.NewRequest(req.Method, url, bytes.NewReader(body))
	if err != nil {
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
		a.logger.Printf("fail to send HTTP request to modsec: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		if resp.StatusCode == http.StatusForbidden && a.jailEnabled {
			a.recordOffense(clientIP)
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
	// Copy headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			rw.Header().Add(k, v)
		}
	}
	// Copy status
	rw.WriteHeader(resp.StatusCode)
	// Copy body
	io.Copy(rw, resp.Body)
}

func (a *Modsecurity) recordOffense(clientIP string) {
	a.jailMutex.Lock()
	defer a.jailMutex.Unlock()

	now := time.Now()
	// Remove offenses that are older than the threshold period
	if offenses, exists := a.jail[clientIP]; exists {
		var newOffenses []time.Time
		for _, offense := range offenses {
			if now.Sub(offense) <= time.Duration(a.badRequestsThresholdPeriod)*time.Second {
				newOffenses = append(newOffenses, offense)
			}
		}
		a.jail[clientIP] = newOffenses
	}

	// Record the new offense
	a.jail[clientIP] = append(a.jail[clientIP], now)

	// Check if the client should be jailed
	if len(a.jail[clientIP]) >= a.badRequestsThresholdCount {
		a.logger.Printf("client %s reached threshold, putting in jail", clientIP)
		a.jailRelease[clientIP] = now.Add(time.Duration(a.jailTimeDuration) * time.Second)
	}
}

func (a *Modsecurity) isClientInJail(clientIP string) bool {
	if releaseTime, exists := a.jailRelease[clientIP]; exists {
		if time.Now().Before(releaseTime) {
			return true
		}
		a.releaseFromJail(clientIP)
	}
	return false
}

func (a *Modsecurity) releaseFromJail(clientIP string) {
	a.jailMutex.Lock()
	defer a.jailMutex.Unlock()

	delete(a.jail, clientIP)
	delete(a.jailRelease, clientIP)
	a.logger.Printf("client %s released from jail", clientIP)
}
