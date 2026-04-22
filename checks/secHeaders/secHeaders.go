package secheaders

import (
	"log"
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"
)

const (
	safe   = true
	unSafe = false
)

func CheckCSP(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()

	csp := resp.Header.Get("Content-Security-Policy")
	// if csp == "" {
	// 	log.Printf("|Warning| CSP is omitted: %s", url)
	// 	return unSafe
	// }
	// Reddit не проходит проверку
	if strings.Contains(csp, "unsafe-eval") {
		log.Printf("|Warning| unsafe-eval is on: %s", url)
		return unSafe
	}
	if strings.Contains(csp, "unsafe-inline") {
		log.Printf("|Warning| unsafe-inline is on: %s", url)
		return unSafe
	}

	// TODO: добавить проверку по регулярки для wildcard:
	//  чтобы пропускало *.example.com, но не пропускало *.com

	return safe
}

func CheckHSTS(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()

	htst := resp.Header.Get("Strict-Transport-Security")
	if htst == "" {
		log.Printf("|Warning| HTST is omitted: %s", url)
		//return unSafe
	}
	if strings.Contains(htst, "max-age=0") {
		log.Printf("|Warning| max-age is missing: %s", url)
		return unSafe
	}
	// TODO: change checks. Checks below are too strict
	// if strings.Contains(htst, "includeSubDomains") {
	// 	log.Printf("|Warning| includeSubDomains is on: %s", url)
	// }
	// if strings.Contains(htst, "preload") {
	// 	log.Printf("|Warning| preload is on: %s", url)
	// }

	return safe
}

func CheckXFO(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()

	xfo := resp.Header.Get("X-Frame-Options")
	if xfo == "" {
		log.Printf("|Warning| X-Frame-Options is omitted: %s", url)
		return unSafe
	}
	// if strings.Contains(xfo, "DENY") || strings.Contains(xfo, "SAMEORIGIN") {
	// 	log.Printf("|Warning| Correct X-Frame-Options is on: %s", url)
	// 	return safe
	// }

	// return unSafe
	return safe
}

func CheckXCT(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()

	xct := resp.Header.Get("X-Content-Type-Options")
	if xct == "nosniff" {
		log.Printf("|Warning| X-Content-Type-Options is valid: %s", url)
		return safe
	}
	return unSafe
}

func CheckCORS(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()

	origin := ctx.Req.Header.Get("Origin")
	_ = origin
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	// if origin != "" && acao != origin {
	// 	log.Printf("[WARNING] %s - ACAO (%s) doesn't match request origin (%s)", url)
	// 	return unSafe
	// }
	if acao == "*" {
		log.Printf("[CRITICAL] %s - ACAO set to wildcard (*) - allows any domain to access resources", url)
		return unSafe
	}
	// if acao == "null" {
	// 	log.Printf("[WARNING] %s - ACAO set to 'null' - can be exploited in some scenarios", url)
	// 	return unSafe
	// }

	return safe
}
