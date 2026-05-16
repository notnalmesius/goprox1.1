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

// --- Существующие проверки (не изменены) ---

func CheckCSP(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		log.Printf("|Warning| CSP is omitted: %s", url)
		// не блокируем, только логируем — чтобы не ломать большинство сайтов
		return safe
	}
	if strings.Contains(csp, "unsafe-eval") {
		log.Printf("|Warning| unsafe-eval is on: %s", url)
		return unSafe
	}
	if strings.Contains(csp, "unsafe-inline") {
		log.Printf("|Warning| unsafe-inline is on: %s", url)
		return unSafe
	}

	return safe
}

func CheckHSTS(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()

	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		log.Printf("|Warning| HSTS is omitted: %s", url)
		return safe // только предупреждение
	}
	if strings.Contains(hsts, "max-age=0") {
		log.Printf("|Warning| HSTS max-age is zero: %s", url)
		return unSafe
	}

	return safe
}

func CheckCORS(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao == "*" {
		log.Printf("[CRITICAL] %s - ACAO set to wildcard (*) - allows any domain to access resources", url)
		return unSafe
	}

	return safe
}

func CheckXFO(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()

	xfo := resp.Header.Get("X-Frame-Options")
	if xfo == "" {
		log.Printf("|Warning| X-Frame-Options is omitted: %s", url)
		return safe // только предупреждение
	}
	// Допустимые значения: DENY или SAMEORIGIN
	xfoUpper := strings.ToUpper(xfo)
	if !strings.Contains(xfoUpper, "DENY") && !strings.Contains(xfoUpper, "SAMEORIGIN") {
		log.Printf("|Warning| X-Frame-Options has unexpected value (%s): %s", xfo, url)
		return unSafe
	}

	return safe
}

func CheckXCT(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()

	xct := resp.Header.Get("X-Content-Type-Options")
	if xct == "" {
		log.Printf("|Warning| X-Content-Type-Options is omitted: %s", url)
		return safe // только предупреждение
	}
	if strings.ToLower(xct) != "nosniff" {
		log.Printf("|Warning| X-Content-Type-Options unexpected value (%s): %s", xct, url)
		return unSafe
	}

	return safe
}

// --- Новые проверки (Задача 1 итерации 5) ---

// CheckReferrerPolicy проверяет наличие заголовка Referrer-Policy.
// Его отсутствие означает, что браузер будет передавать полный URL страницы
// внешним ресурсам через заголовок Referer, раскрывая внутренние ссылки.
func CheckReferrerPolicy(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()

	rp := resp.Header.Get("Referrer-Policy")
	if rp == "" {
		log.Printf("|Warning| Referrer-Policy is omitted: %s", url)
		return safe // только предупреждение, не блокируем
	}

	// Небезопасные значения: unsafe-url передаёт полный URL всегда
	if strings.ToLower(rp) == "unsafe-url" {
		log.Printf("|Warning| Referrer-Policy set to unsafe-url: %s", url)
		return unSafe
	}

	log.Printf("|Info| Referrer-Policy: %s — %s", rp, url)
	return safe
}

// CheckPermissionsPolicy проверяет наличие заголовка Permissions-Policy.
// Его отсутствие означает, что сайт не ограничивает доступ к API браузера
// (камера, микрофон, геолокация и др.).
func CheckPermissionsPolicy(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()

	pp := resp.Header.Get("Permissions-Policy")
	if pp == "" {
		log.Printf("|Warning| Permissions-Policy is omitted: %s", url)
		return safe // только предупреждение
	}

	log.Printf("|Info| Permissions-Policy present: %s — %s", pp, url)
	return safe
}
