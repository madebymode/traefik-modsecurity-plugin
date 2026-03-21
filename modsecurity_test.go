package traefik_modsecurity_plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func responseWith(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func newTestMiddleware(t *testing.T, config *Config, serviceHandler http.Handler, transport roundTripperFunc) *Modsecurity {
	t.Helper()

	if config.ModSecurityUrl == "" {
		config.ModSecurityUrl = "http://modsecurity.local"
	}
	if config.TimeoutMillis == 0 {
		config.TimeoutMillis = 50
	}

	handler, err := New(context.Background(), serviceHandler, config, "modsecurity-middleware")
	if err != nil {
		t.Fatalf("failed to create middleware: %v", err)
	}

	middleware := handler.(*Modsecurity)
	middleware.httpClient.Transport = transport
	return middleware
}

func TestModsecurity_ServeHTTP(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://proxy.com/test", bytes.NewBuffer([]byte("Request")))
	if err != nil {
		t.Fatal(err)
	}

	type response struct {
		Body       string
		StatusCode int
	}

	serviceResponse := response{
		StatusCode: http.StatusOK,
		Body:       "Response from service",
	}

	tests := []struct {
		name                 string
		request              *http.Request
		wafResponse          response
		serviceResponse      response
		expectBody           string
		expectStatus         int
		expectWAFCalls       int
		expectServiceCalls   int
		jailEnabled          bool
		badRequestIterations int
		jailConfig           *Config
	}{
		{
			name:    "Forward request when WAF found no threats",
			request: req.Clone(req.Context()),
			wafResponse: response{
				StatusCode: http.StatusOK,
				Body:       "Response from waf",
			},
			serviceResponse:    serviceResponse,
			expectBody:         "Response from service",
			expectStatus:       http.StatusOK,
			expectWAFCalls:     1,
			expectServiceCalls: 1,
		},
		{
			name:    "Intercepts request when WAF found threats",
			request: req.Clone(req.Context()),
			wafResponse: response{
				StatusCode: http.StatusForbidden,
				Body:       "Response from waf",
			},
			serviceResponse:    serviceResponse,
			expectBody:         "Response from waf",
			expectStatus:       http.StatusForbidden,
			expectWAFCalls:     1,
			expectServiceCalls: 0,
		},
		{
			name: "Does not forward Websockets",
			request: &http.Request{
				Body: http.NoBody,
				Header: http.Header{
					"Upgrade": []string{"websocket"},
				},
				Method: http.MethodGet,
				URL:    req.URL,
			},
			wafResponse: response{
				StatusCode: http.StatusOK,
				Body:       "Response from waf",
			},
			serviceResponse:    serviceResponse,
			expectBody:         "Response from service",
			expectStatus:       http.StatusOK,
			expectWAFCalls:     0,
			expectServiceCalls: 1,
		},
		{
			name:    "Jail client after multiple bad requests",
			request: req.Clone(req.Context()),
			wafResponse: response{
				StatusCode: http.StatusForbidden,
				Body:       "Response from waf",
			},
			serviceResponse:      serviceResponse,
			expectBody:           "Too Many Requests\n",
			expectStatus:         http.StatusTooManyRequests,
			expectWAFCalls:       3,
			expectServiceCalls:   0,
			jailEnabled:          true,
			badRequestIterations: 4,
			jailConfig: &Config{
				JailEnabled:                    true,
				BadRequestsThresholdCount:      3,
				BadRequestsThresholdPeriodSecs: 10,
				JailTimeDurationSecs:           10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wafCalls := 0
			serviceCalls := 0

			serviceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				serviceCalls++
				forwardResponse(responseWith(tt.serviceResponse.StatusCode, tt.serviceResponse.Body), w)
			})

			config := &Config{
				TimeoutMillis:                  2000,
				ModSecurityUrl:                 "http://modsecurity.local",
				JailEnabled:                    tt.jailEnabled,
				BadRequestsThresholdCount:      25,
				BadRequestsThresholdPeriodSecs: 600,
				JailTimeDurationSecs:           600,
			}
			if tt.jailEnabled && tt.jailConfig != nil {
				config = tt.jailConfig
				config.ModSecurityUrl = "http://modsecurity.local"
			}

			middleware := newTestMiddleware(t, config, serviceHandler, func(r *http.Request) (*http.Response, error) {
				wafCalls++
				return responseWith(tt.wafResponse.StatusCode, tt.wafResponse.Body), nil
			})

			iterations := 1
			if tt.badRequestIterations > 0 {
				iterations = tt.badRequestIterations
			}

			var resp *http.Response
			for i := 0; i < iterations; i++ {
				rw := httptest.NewRecorder()
				middleware.ServeHTTP(rw, tt.request.Clone(tt.request.Context()))
				resp = rw.Result()
			}

			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				t.Fatalf("failed to read body: %v", readErr)
			}

			assert.Equal(t, tt.expectStatus, resp.StatusCode)
			assert.Equal(t, tt.expectBody, string(body))
			assert.Equal(t, tt.expectWAFCalls, wafCalls)
			assert.Equal(t, tt.expectServiceCalls, serviceCalls)
		})
	}
}

func TestModsecurity_WAFTransportErrorWithoutBackoffReturnsBadGateway(t *testing.T) {
	serviceCalled := false
	serviceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serviceCalled = true
		w.WriteHeader(http.StatusOK)
	})

	middleware := newTestMiddleware(t, &Config{
		UnhealthyWafBackOffPeriodSecs: 0,
	}, serviceHandler, func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("dial failed")
	})

	rw := httptest.NewRecorder()
	middleware.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "http://proxy.com/test", bytes.NewBufferString("Request")))

	assert.Equal(t, http.StatusBadGateway, rw.Result().StatusCode)
	assert.False(t, serviceCalled)
}

func TestModsecurity_WAFTransportErrorWithBackoffBypassesTemporarilyAndLogs(t *testing.T) {
	serviceCalls := 0
	serviceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serviceCalls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Response from service"))
	})

	middleware := newTestMiddleware(t, &Config{
		UnhealthyWafBackOffPeriodSecs: 1,
	}, serviceHandler, func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("dial failed")
	})

	var logBuffer bytes.Buffer
	middleware.logger = log.New(&logBuffer, "", 0)

	firstRW := httptest.NewRecorder()
	middleware.ServeHTTP(firstRW, httptest.NewRequest(http.MethodGet, "http://proxy.com/test", bytes.NewBufferString("Request")))
	assert.Equal(t, http.StatusOK, firstRW.Result().StatusCode)
	assert.Equal(t, 1, serviceCalls)
	assert.True(t, middleware.isWAFUnhealthy())

	secondRW := httptest.NewRecorder()
	middleware.ServeHTTP(secondRW, httptest.NewRequest(http.MethodGet, "http://proxy.com/test", bytes.NewBufferString("Request")))
	assert.Equal(t, http.StatusOK, secondRW.Result().StatusCode)
	assert.Equal(t, 2, serviceCalls)

	time.Sleep(1100 * time.Millisecond)
	assert.False(t, middleware.isWAFUnhealthy())
	assert.Contains(t, logBuffer.String(), "marking modsec as unhealthy for 1s after transport failure:")
	assert.Contains(t, logBuffer.String(), "dial failed")
	assert.Contains(t, logBuffer.String(), "modsec unhealthy backoff expired, resuming WAF checks")
}

func TestModsecurity_ModSecurity502DoesNotBypassUnlessConfigured(t *testing.T) {
	serviceCalled := false
	serviceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serviceCalled = true
		w.WriteHeader(http.StatusOK)
	})

	middleware := newTestMiddleware(t, &Config{
		UnhealthyWafBackOffPeriodSecs: 1,
		BypassOnModSecurity502:        false,
	}, serviceHandler, func(r *http.Request) (*http.Response, error) {
		return responseWith(http.StatusBadGateway, "waf bad gateway"), nil
	})

	rw := httptest.NewRecorder()
	middleware.ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "http://proxy.com/test", bytes.NewBufferString("Request")))

	body, err := io.ReadAll(rw.Result().Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	assert.Equal(t, http.StatusBadGateway, rw.Result().StatusCode)
	assert.Equal(t, "waf bad gateway", string(body))
	assert.False(t, serviceCalled)
	assert.False(t, middleware.isWAFUnhealthy())
}

func TestModsecurity_ModSecurity502CanBypassWhenConfigured(t *testing.T) {
	serviceCalls := 0
	serviceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serviceCalls++
		w.WriteHeader(http.StatusOK)
	})

	middleware := newTestMiddleware(t, &Config{
		UnhealthyWafBackOffPeriodSecs: 1,
		BypassOnModSecurity502:        true,
	}, serviceHandler, func(r *http.Request) (*http.Response, error) {
		return responseWith(http.StatusBadGateway, "waf bad gateway"), nil
	})

	firstRW := httptest.NewRecorder()
	middleware.ServeHTTP(firstRW, httptest.NewRequest(http.MethodGet, "http://proxy.com/test", bytes.NewBufferString("Request")))
	assert.Equal(t, http.StatusOK, firstRW.Result().StatusCode)
	assert.Equal(t, 1, serviceCalls)
	assert.True(t, middleware.isWAFUnhealthy())

	secondRW := httptest.NewRecorder()
	middleware.ServeHTTP(secondRW, httptest.NewRequest(http.MethodGet, "http://proxy.com/test", bytes.NewBufferString("Request")))
	assert.Equal(t, http.StatusOK, secondRW.Result().StatusCode)
	assert.Equal(t, 2, serviceCalls)
}

func TestModsecurity_SendWebhookAlertAndThrottle(t *testing.T) {
	serviceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := newTestMiddleware(t, &Config{
		AlertWebhookURL:         "https://alerts.example/webhook",
		AlertThrottlePeriodSecs: 60,
	}, serviceHandler, func(r *http.Request) (*http.Response, error) {
		return responseWith(http.StatusOK, "ok"), nil
	})

	var mu sync.Mutex
	requestBodies := []map[string]string{}
	middleware.alertHTTPClient = &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}

			payload := map[string]string{}
			if err := json.Unmarshal(body, &payload); err != nil {
				return nil, err
			}

			mu.Lock()
			requestBodies = append(requestBodies, payload)
			mu.Unlock()

			return responseWith(http.StatusOK, ""), nil
		}),
	}

	assert.True(t, middleware.shouldSendAlert("waf_unhealthy"))
	assert.NoError(t, middleware.sendAlert("waf_unhealthy", "alert one"))
	assert.False(t, middleware.shouldSendAlert("waf_unhealthy"))

	middleware.lastAlertAt["waf_unhealthy"] = time.Now().Add(-time.Hour)

	assert.True(t, middleware.shouldSendAlert("waf_unhealthy"))
	assert.NoError(t, middleware.sendAlert("waf_unhealthy", "alert two"))

	mu.Lock()
	defer mu.Unlock()

	assert.Len(t, requestBodies, 2)
	assert.Equal(t, "waf_unhealthy", requestBodies[0]["event"])
	assert.Equal(t, "alert one", requestBodies[0]["message"])
	assert.Equal(t, "alert two", requestBodies[1]["message"])
}

func TestModsecurity_SendTelegramAlert(t *testing.T) {
	serviceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := newTestMiddleware(t, &Config{
		TelegramBotToken:        "bot-token",
		TelegramChatID:          "chat-id",
		AlertThrottlePeriodSecs: 60,
	}, serviceHandler, func(r *http.Request) (*http.Response, error) {
		return responseWith(http.StatusOK, "ok"), nil
	})

	requests := []struct {
		URL     string
		Payload map[string]string
	}{}
	middleware.alertHTTPClient = &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}

			payload := map[string]string{}
			if err := json.Unmarshal(body, &payload); err != nil {
				return nil, err
			}

			requests = append(requests, struct {
				URL     string
				Payload map[string]string
			}{
				URL:     r.URL.String(),
				Payload: payload,
			})

			return responseWith(http.StatusOK, ""), nil
		}),
	}

	assert.NoError(t, middleware.sendAlert("waf_unhealthy", "telegram alert"))
	assert.Len(t, requests, 1)
	assert.Equal(t, "https://api.telegram.org/botbot-token/sendMessage", requests[0].URL)
	assert.Equal(t, "chat-id", requests[0].Payload["chat_id"])
	assert.Equal(t, "telegram alert", requests[0].Payload["text"])
}

func TestNew_RequiresCompleteTelegramConfig(t *testing.T) {
	_, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), &Config{
		ModSecurityUrl:   "http://modsecurity.local",
		TelegramBotToken: "bot-token",
	}, "modsecurity-middleware")

	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "telegramBotToken and telegramChatId must be configured together")
	}
}
