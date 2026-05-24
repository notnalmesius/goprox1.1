package secheaders

import (
	"log"
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"

	rep "prodjects/goprox/checks/report"
)

const (
	safe   = true
	unSafe = false
)

func CheckCSP(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()
	host := ctx.Req.URL.Scheme + "://" + ctx.Req.URL.Host
	r := rep.GetOrCreate(host)

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		log.Printf("|Warning| CSP is omitted: %s", url)
		r.AddHeaderFinding("Content-Security-Policy", "high",
			"Добавьте заголовок Content-Security-Policy. Рекомендуемое значение: default-src 'self'. "+
				"Это защитит от XSS-атак, ограничив загрузку ресурсов только с вашего домена.")
		return safe
	}
	if strings.Contains(csp, "unsafe-eval") {
		log.Printf("|Warning| unsafe-eval is on: %s", url)
		r.AddHeaderFinding("Content-Security-Policy (unsafe-eval)", "high",
			"Уберите директиву 'unsafe-eval' из CSP — она разрешает выполнение произвольного кода через eval().")
		return unSafe
	}
	if strings.Contains(csp, "unsafe-inline") {
		log.Printf("|Warning| unsafe-inline is on: %s", url)
		r.AddHeaderFinding("Content-Security-Policy (unsafe-inline)", "high",
			"Уберите директиву 'unsafe-inline' из CSP — она разрешает выполнение встроенных скриптов.")
		return unSafe
	}
	return safe
}

func CheckHSTS(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()
	host := ctx.Req.URL.Scheme + "://" + ctx.Req.URL.Host
	r := rep.GetOrCreate(host)

	hsts := resp.Header.Get("Strict-Transport-Security")
	if hsts == "" {
		log.Printf("|Warning| HSTS is omitted: %s", url)
		r.AddHeaderFinding("Strict-Transport-Security", "high",
			"Добавьте заголовок Strict-Transport-Security: max-age=31536000; includeSubDomains. "+
				"Это обяжет браузер всегда использовать HTTPS и защитит от MITM-атак.")
		return safe
	}
	if strings.Contains(hsts, "max-age=0") {
		log.Printf("|Warning| HSTS max-age is zero: %s", url)
		r.AddHeaderFinding("Strict-Transport-Security (max-age=0)", "high",
			"Значение max-age=0 фактически отключает HSTS. Установите max-age не менее 31536000 (1 год).")
		return unSafe
	}
	return safe
}

func CheckCORS(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()
	host := ctx.Req.URL.Scheme + "://" + ctx.Req.URL.Host
	r := rep.GetOrCreate(host)

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao == "*" {
		log.Printf("[CRITICAL] %s - ACAO set to wildcard (*)", url)
		r.AddHeaderFinding("Access-Control-Allow-Origin (*)", "critical",
			"Замените значение '*' на конкретный список доверенных доменов. "+
				"Wildcard CORS открывает доступ к ресурсам с любого сайта в интернете.")
		return unSafe
	}
	return safe
}

func CheckXFO(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()
	host := ctx.Req.URL.Scheme + "://" + ctx.Req.URL.Host
	r := rep.GetOrCreate(host)

	xfo := resp.Header.Get("X-Frame-Options")
	if xfo == "" {
		log.Printf("|Warning| X-Frame-Options is omitted: %s", url)
		r.AddHeaderFinding("X-Frame-Options", "medium",
			"Добавьте заголовок X-Frame-Options: DENY или SAMEORIGIN. "+
				"Это предотвратит встраивание страницы в iframe на сторонних сайтах (защита от кликджекинга).")
		return safe
	}
	xfoUpper := strings.ToUpper(xfo)
	if !strings.Contains(xfoUpper, "DENY") && !strings.Contains(xfoUpper, "SAMEORIGIN") {
		log.Printf("|Warning| X-Frame-Options unexpected value (%s): %s", xfo, url)
		r.AddHeaderFinding("X-Frame-Options (неверное значение)", "medium",
			"Установите X-Frame-Options: DENY (запретить встраивание полностью) или SAMEORIGIN.")
		return unSafe
	}
	return safe
}

func CheckXCT(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()
	host := ctx.Req.URL.Scheme + "://" + ctx.Req.URL.Host
	r := rep.GetOrCreate(host)

	xct := resp.Header.Get("X-Content-Type-Options")
	if xct == "" {
		log.Printf("|Warning| X-Content-Type-Options is omitted: %s", url)
		r.AddHeaderFinding("X-Content-Type-Options", "medium",
			"Добавьте заголовок X-Content-Type-Options: nosniff. "+
				"Это запретит браузеру самостоятельно определять MIME-тип содержимого.")
		return safe
	}
	if strings.ToLower(xct) != "nosniff" {
		log.Printf("|Warning| X-Content-Type-Options unexpected value (%s): %s", xct, url)
		r.AddHeaderFinding("X-Content-Type-Options (неверное значение)", "medium",
			"Установите X-Content-Type-Options: nosniff — это единственное корректное значение.")
		return unSafe
	}
	return safe
}

func CheckReferrerPolicy(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()
	host := ctx.Req.URL.Scheme + "://" + ctx.Req.URL.Host
	r := rep.GetOrCreate(host)

	rp := resp.Header.Get("Referrer-Policy")
	if rp == "" {
		log.Printf("|Warning| Referrer-Policy is omitted: %s", url)
		r.AddHeaderFinding("Referrer-Policy", "low",
			"Добавьте заголовок Referrer-Policy: strict-origin-when-cross-origin. "+
				"Это ограничит передачу URL страницы внешним ресурсам.")
		return safe
	}
	if strings.ToLower(rp) == "unsafe-url" {
		log.Printf("|Warning| Referrer-Policy set to unsafe-url: %s", url)
		r.AddHeaderFinding("Referrer-Policy (unsafe-url)", "medium",
			"Значение unsafe-url передаёт полный URL всем ресурсам. Используйте strict-origin-when-cross-origin.")
		return unSafe
	}
	return safe
}

func CheckPermissionsPolicy(resp *http.Response, ctx *goproxy.ProxyCtx) bool {
	url := ctx.Req.URL.String()
	host := ctx.Req.URL.Scheme + "://" + ctx.Req.URL.Host
	r := rep.GetOrCreate(host)

	pp := resp.Header.Get("Permissions-Policy")
	if pp == "" {
		log.Printf("|Warning| Permissions-Policy is omitted: %s", url)
		r.AddHeaderFinding("Permissions-Policy", "low",
			"Добавьте заголовок Permissions-Policy чтобы явно ограничить доступ к API браузера. "+
				"Например: Permissions-Policy: camera=(), microphone=(), geolocation=()")
		return safe
	}
	return safe
}