package traefik_modsecurity_plugin

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// HandleRequestBodyMaxSize - handle request body max size
func (a *Modsecurity) HandleRequestBodyMaxSize(rw http.ResponseWriter, req *http.Request) error {
	if req.Body == nil {
		return nil
	}

	bodyReader := io.LimitReader(req.Body, a.maxBodySize+1)
	bodyBuffer := new(bytes.Buffer)
	n, err := io.Copy(bodyBuffer, bodyReader)
	err = req.Body.Close()

	if err != nil {
		if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
			// Request body size is within limit.
			req.Body = io.NopCloser(bodyBuffer)
			return nil
		}

		a.logger.Printf("fail to read incoming request: %s", err.Error())
		http.Error(rw, "", http.StatusBadGateway)
		return err
	}

	if n <= a.maxBodySize {
		// Request body size is within limit.
		req.Body = io.NopCloser(bodyBuffer)
		return nil
	}

	a.logger.Printf("body max limit reached: content length %d is larger than the allowed limit %d", n, a.maxBodySize)
	http.Error(rw, "", http.StatusRequestEntityTooLarge)
	return fmt.Errorf("http: request body too large")
}

func (a *Modsecurity) HandleCacheAndForwardRequest(req *http.Request) (*http.Response, error) {
	var resp *http.Response

	// If cache is disabled, immediately forward to ModSecurity
	if !a.cacheEnabled {
		return a.PrepareForwardedRequest(req)
	}

	// Get from our memory cache if possible
	if a.cacheConditions.Check(req) {
		resp, err := a.GetCachedResponse(req, a.cacheKey)
		// a.logger.Printf("cache hit: %v", err == nil)
		if err != nil {
			return nil, err
		}
		return resp, nil
	}

	// Forward to ModSecurity
	resp, err := a.PrepareForwardedRequest(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
