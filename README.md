# Traefik Modsecurity Plugin

![Banner](./img/banner.png)

this is a fork of the original: https://github.com/acouvreur/traefik-modsecurity-plugin

This fork introduces alpine images, CRS 4.x suppport, and a custom http.transport

see:  https://github.com/traefik/plugindemo#troubleshooting

----

Traefik plugin to proxy requests to [owasp/modsecurity-crs](https://hub.docker.com/r/owasp/modsecurity-crs):apache

![Github Actions](https://img.shields.io/github/actions/workflow/status/madebymode/traefik-modsecurity-plugin/build.yml?style=flat-square&branch=main)
![Go Report](https://goreportcard.com/badge/github.com/madebymode/traefik-modsecurity-plugin?style=flat-square)
![Go Version](https://img.shields.io/github/go-mod/go-version/madebymode/traefik-modsecurity-plugin?style=flat-square)
![Latest Release](https://img.shields.io/github/release/madebymode/traefik-modsecurity-plugin/all.svg?style=flat-square)

- [Traefik Modsecurity Plugin](#traefik-modsecurity-plugin)
    - [Demo](#demo)
    - [Usage (docker-compose.yml)](#usage-docker-composeyml)
    - [How it works](#how-it-works)
    - [Local development (docker-compose.local.yml)](#local-development-docker-composelocalyml)

## Demo

Demo with WAF intercepting relative access in query param.

![Demo](./img/waf.gif)

## Usage (docker-compose.yml)

See [docker-compose.yml](docker-compose.yml)

1. docker-compose up
2. Go to http://localhost/website, the request is received without warnings
3. Go to http://localhost/website?test=../etc, the request is intercepted and returned with 403 Forbidden by
   owasp/modsecurity
4. You can you bypass the WAF and check attacks at http://localhost/bypass?test=../etc

## How it works

This is a very simple plugin that proxies the query to the owasp/modsecurity apache container.

The plugin checks that the response from the waf container hasn't an http code > 400 before forwarding the request to
the real service.

If it is > 400, then the error page is returned instead.

The *dummy* service is created so the waf container forward the request to a service and respond with 200 OK all the
time.

## Configuration

This plugin supports these configuration:

### Basic Configuration

* `modSecurityUrl`: (**mandatory**) it's the URL for the owasp/modsecurity container.
* `timeoutMillis`: (optional) timeout in milliseconds for the http client to talk with modsecurity container. (default 2000ms)
* `unhealthyWafBackOffPeriodSecs` (optional) the period, in seconds, to backoff if calls to modsecurity fail. Default to 0. Default behaviour is to send a 502 Bad Gateway when there are problems communicating with modsec.
* `modSecurityStatusRequestHeader`: (optional) name of the header to add to the request when requests are blocked by ModSecurity (for logging purposes). The header value will contain the HTTP status code returned by ModSecurity. Default is empty (no header added).

### Advanced Transport Configuration

These parameters allow fine-tuning of the HTTP client behavior for high-load scenarios:

* `maxConnsPerHost`: (optional) maximum number of concurrent connections allowed per ModSecurity host. Set to 0 for unlimited connections (default: 0 - unlimited, original behavior).
* `maxIdleConnsPerHost`: (optional) maximum number of idle connections to keep per ModSecurity host. Set to 0 for unlimited idle connections (default: 0 - unlimited, original behavior).
* `responseHeaderTimeoutMillis`: (optional) timeout in milliseconds for waiting for response headers from ModSecurity. Set to 0 for no timeout (default: 0 - no timeout, original behavior).
* `expectContinueTimeoutMillis`: (optional) timeout in milliseconds for Expect: 100-continue handshake. Used for large payload uploads (default: 1000ms).


## Local development (docker-compose.local.yml)

See [docker-compose.local.yml](docker-compose.local.yml)

`docker-compose -f docker-compose.local.yml up` to load the local plugin
