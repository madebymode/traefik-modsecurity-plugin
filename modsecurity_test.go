package traefik_modsecurity_plugin

import (
	"bytes"
	"github.com/patrickmn/go-cache"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestModsecurity_ServeHTTP(t *testing.T) {

	req, err := http.NewRequest(http.MethodGet, "http://proxy.com/test", bytes.NewBuffer([]byte("Request")))

	if err != nil {
		log.Fatal(err)
	}

	type response struct {
		Body       string
		StatusCode int
	}

	serviceResponse := response{
		StatusCode: 200,
		Body:       "Response from service",
	}

	tests := []struct {
		name            string
		request         http.Request
		wafResponse     response
		serviceResponse response
		expectBody      string
		expectStatus    int
	}{
		{
			name:    "Forward request when WAF found no threats",
			request: *req,
			wafResponse: response{
				StatusCode: 200,
				Body:       "Response from waf",
			},
			serviceResponse: serviceResponse,
			expectBody:      "Response from service",
			expectStatus:    200,
		},
		{
			name:    "Intercepts request when WAF found threats",
			request: *req,
			wafResponse: response{
				StatusCode: 403,
				Body:       "Response from waf",
			},
			serviceResponse: serviceResponse,
			expectBody:      "Response from waf",
			expectStatus:    403,
		},
		{
			name: "Does not forward Websockets",
			request: http.Request{
				Body: http.NoBody,
				Header: http.Header{
					"Upgrade": []string{"Websocket"},
				},
			},
			wafResponse: response{
				StatusCode: 200,
				Body:       "Response from waf",
			},
			serviceResponse: serviceResponse,
			expectBody:      "Response from service",
			expectStatus:    200,
		},
		{
			name: "Accept payloads smaller than limits",
			request: http.Request{
				Body: generateLargeBody(1024),
			},
			wafResponse: response{
				StatusCode: 200,
				Body:       "Response from waf",
			},
			serviceResponse: serviceResponse,
			expectBody:      "Response from service",
			expectStatus:    http.StatusOK,
		},
		{
			name: "Reject too big payloads",
			request: http.Request{
				Body: generateLargeBody(5025),
			},
			wafResponse: response{
				StatusCode: 200,
				Body:       "Response from waf",
			},
			serviceResponse: serviceResponse,
			expectBody:      "\n",
			expectStatus:    http.StatusRequestEntityTooLarge,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			modsecurityMockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := http.Response{
					Body:       io.NopCloser(bytes.NewReader([]byte(tt.wafResponse.Body))),
					StatusCode: tt.wafResponse.StatusCode,
					Header:     http.Header{},
				}
				log.Printf("WAF Mock: status code: %d, body: %s", resp.StatusCode, tt.wafResponse.Body)
				forwardResponse(&resp, w)
			}))

			httpServiceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := http.Response{
					Body:       io.NopCloser(bytes.NewReader([]byte(tt.serviceResponse.Body))),
					StatusCode: tt.serviceResponse.StatusCode,
					Header:     http.Header{},
				}
				log.Printf("Service Handler: status code: %d, body: %s", resp.StatusCode, tt.serviceResponse.Body)
				forwardResponse(&resp, w)
			})

			middleware := &Modsecurity{
				next:           httpServiceHandler,
				modSecurityUrl: modsecurityMockServer.URL,
				maxBodySize:    1024,
				name:           "modsecurity-middleware",
				httpClient:     http.DefaultClient,
				logger:         log.New(io.Discard, "", log.LstdFlags),
				cache:          cache.New(5*time.Minute, 10*time.Minute),
			}

			rw := httptest.NewRecorder()

			log.Printf("Before ServeHTTP: request method: %s, request URL: %s", tt.request.Method, tt.request.URL)
			middleware.ServeHTTP(rw, &tt.request)
			resp := rw.Result()
			body, _ := io.ReadAll(resp.Body)
			log.Printf("After ServeHTTP: response status code: %d, body: %s", resp.StatusCode, string(body))

			assert.Equal(t, tt.expectBody, string(body))
			assert.Equal(t, tt.expectStatus, resp.StatusCode)
		})
	}
}

func generateLargeBody(size int) io.ReadCloser {
	var str = make([]byte, size)
	return io.NopCloser(bytes.NewReader(str))
}
