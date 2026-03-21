// Package traefik_modsecurity_plugin a modsecurity plugin.
package traefik_modsecurity_plugin

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
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
	JailEnabled                    bool   `json:"jailEnabled,omitempty"`
	BadRequestsThresholdCount      int    `json:"badRequestsThresholdCount,omitempty"`
	BadRequestsThresholdPeriodSecs int    `json:"badRequestsThresholdPeriodSecs,omitempty"` // Period in seconds to track attempts
	JailTimeDurationSecs           int    `json:"jailTimeDurationSecs,omitempty"`           // How long a client spends in Jail in seconds
	UnhealthyWafBackOffPeriodSecs  int    `json:"unhealthyWafBackOffPeriodSecs,omitempty"`  // How long to bypass WAF after a transport failure
	BypassOnModSecurity502         bool   `json:"bypassOnModSecurity502,omitempty"`         // Allow bypass when ModSecurity responds with 502
	AlertThrottlePeriodSecs        int    `json:"alertThrottlePeriodSecs,omitempty"`        // Minimum time between duplicate alerts for the same event
	AlertWebhookURL                string `json:"alertWebhookUrl,omitempty"`                // Optional webhook endpoint for unhealthy/recovered alerts
	TelegramBotToken               string `json:"telegramBotToken,omitempty"`               // Optional Telegram bot token for alerts
	TelegramChatID                 string `json:"telegramChatId,omitempty"`                 // Optional Telegram chat ID for alerts
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		TimeoutMillis:                  2000,
		JailEnabled:                    false,
		BadRequestsThresholdCount:      25,
		BadRequestsThresholdPeriodSecs: 600,
		JailTimeDurationSecs:           600,
		UnhealthyWafBackOffPeriodSecs:  0,
		AlertThrottlePeriodSecs:        300,
	}
}

// Modsecurity a Modsecurity plugin.
type Modsecurity struct {
	next                           http.Handler
	modSecurityUrl                 string
	name                           string
	httpClient                     *http.Client
	alertHTTPClient                *http.Client
	logger                         *log.Logger
	jailEnabled                    bool
	badRequestsThresholdCount      int
	badRequestsThresholdPeriodSecs int
	unhealthyWafBackOffPeriodSecs  int
	bypassOnModSecurity502         bool
	alertThrottlePeriod            time.Duration
	alertWebhookURL                string
	telegramBotToken               string
	telegramChatID                 string
	unhealthyWaf                   bool
	unhealthyWafMutex              sync.RWMutex
	alertMutex                     sync.Mutex
	lastAlertAt                    map[string]time.Time
	jailTimeDurationSecs           int
	jail                           map[string][]time.Time
	jailRelease                    map[string]time.Time
	jailMutex                      sync.RWMutex
}

// New creates a new Modsecurity plugin with the given configuration.
// It returns an HTTP handler that can be integrated into the Traefik middleware chain.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.ModSecurityUrl) == 0 {
		return nil, fmt.Errorf("modSecurityUrl cannot be empty")
	}
	if (config.TelegramBotToken == "") != (config.TelegramChatID == "") {
		return nil, fmt.Errorf("telegramBotToken and telegramChatId must be configured together")
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
		modSecurityUrl:                 config.ModSecurityUrl,
		next:                           next,
		name:                           name,
		httpClient:                     &http.Client{Timeout: timeout, Transport: transport},
		alertHTTPClient:                &http.Client{Timeout: 5 * time.Second},
		logger:                         log.New(os.Stdout, "", log.LstdFlags),
		jailEnabled:                    config.JailEnabled,
		badRequestsThresholdCount:      config.BadRequestsThresholdCount,
		badRequestsThresholdPeriodSecs: config.BadRequestsThresholdPeriodSecs,
		unhealthyWafBackOffPeriodSecs:  config.UnhealthyWafBackOffPeriodSecs,
		bypassOnModSecurity502:         config.BypassOnModSecurity502,
		alertThrottlePeriod:            time.Duration(config.AlertThrottlePeriodSecs) * time.Second,
		alertWebhookURL:                config.AlertWebhookURL,
		telegramBotToken:               config.TelegramBotToken,
		telegramChatID:                 config.TelegramChatID,
		lastAlertAt:                    make(map[string]time.Time),
		jailTimeDurationSecs:           config.JailTimeDurationSecs,
		jail:                           make(map[string][]time.Time),
		jailRelease:                    make(map[string]time.Time),
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

	if a.isWAFUnhealthy() {
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
		if a.markWAFUnhealthy(err) {
			a.next.ServeHTTP(rw, req)
			return
		}
		a.logger.Printf("fail to send HTTP request to modsec: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusBadGateway && a.bypassOnModSecurity502 {
		if a.markWAFUnhealthy(fmt.Errorf("modsecurity returned status %d", resp.StatusCode)) {
			a.next.ServeHTTP(rw, req)
			return
		}
	}

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

func (a *Modsecurity) isWAFUnhealthy() bool {
	a.unhealthyWafMutex.RLock()
	defer a.unhealthyWafMutex.RUnlock()

	return a.unhealthyWaf
}

func (a *Modsecurity) markWAFUnhealthy(cause error) bool {
	if a.unhealthyWafBackOffPeriodSecs <= 0 {
		return false
	}

	a.unhealthyWafMutex.Lock()
	if a.unhealthyWaf {
		a.unhealthyWafMutex.Unlock()
		return true
	}

	a.unhealthyWaf = true
	backoff := time.Duration(a.unhealthyWafBackOffPeriodSecs) * time.Second
	a.unhealthyWafMutex.Unlock()

	a.logger.Printf("marking modsec as unhealthy for %ds after transport failure: %v", a.unhealthyWafBackOffPeriodSecs, cause)
	a.sendAlertAsync("waf_unhealthy", fmt.Sprintf("ModSecurity backend unhealthy for %ds after transport failure: %v", a.unhealthyWafBackOffPeriodSecs, cause))

	time.AfterFunc(backoff, func() {
		a.clearWAFUnhealthy()
	})

	return true
}

func (a *Modsecurity) clearWAFUnhealthy() {
	a.unhealthyWafMutex.Lock()
	if !a.unhealthyWaf {
		a.unhealthyWafMutex.Unlock()
		return
	}
	a.unhealthyWaf = false
	a.unhealthyWafMutex.Unlock()

	a.logger.Printf("modsec unhealthy backoff expired, resuming WAF checks")
	a.sendAlertAsync("waf_recovered", "ModSecurity backend recovered, resuming WAF checks")
}

func (a *Modsecurity) sendAlertAsync(event, message string) {
	if !a.shouldSendAlert(event) {
		return
	}

	go func() {
		if err := a.sendAlert(event, message); err != nil {
			a.logger.Printf("fail to send %s alert: %v", event, err)
		}
	}()
}

func (a *Modsecurity) shouldSendAlert(event string) bool {
	if a.alertWebhookURL == "" && a.telegramBotToken == "" {
		return false
	}

	a.alertMutex.Lock()
	defer a.alertMutex.Unlock()

	if a.alertThrottlePeriod > 0 {
		if last, ok := a.lastAlertAt[event]; ok && time.Since(last) < a.alertThrottlePeriod {
			return false
		}
	}

	a.lastAlertAt[event] = time.Now()
	return true
}

func (a *Modsecurity) sendAlert(event, message string) error {
	payload := map[string]string{
		"event":          event,
		"message":        message,
		"plugin":         a.name,
		"modSecurityUrl": a.modSecurityUrl,
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
	}

	if a.alertWebhookURL != "" {
		if err := a.sendWebhookAlert(payload); err != nil {
			return err
		}
	}
	if a.telegramBotToken != "" {
		if err := a.sendTelegramAlert(message); err != nil {
			return err
		}
	}

	return nil
}

func (a *Modsecurity) sendWebhookAlert(payload map[string]string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, a.alertWebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.alertHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func (a *Modsecurity) sendTelegramAlert(message string) error {
	payload := map[string]string{
		"chat_id": a.telegramChatID,
		"text":    message,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", a.telegramBotToken)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.alertHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram returned status %d", resp.StatusCode)
	}

	return nil
}

func (a *Modsecurity) recordOffense(clientIP string) {
	a.jailMutex.Lock()
	defer a.jailMutex.Unlock()

	now := time.Now()
	// Remove offenses that are older than the threshold period
	if offenses, exists := a.jail[clientIP]; exists {
		var newOffenses []time.Time
		for _, offense := range offenses {
			if now.Sub(offense) <= time.Duration(a.badRequestsThresholdPeriodSecs)*time.Second {
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
		a.jailRelease[clientIP] = now.Add(time.Duration(a.jailTimeDurationSecs) * time.Second)
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
