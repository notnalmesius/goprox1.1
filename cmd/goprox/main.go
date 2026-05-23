package main

import (
	"log"
	"net/http"
	"sync"

	publicfiles "prodjects/goprox/checks/publicFiles"
	secheaders "prodjects/goprox/checks/secHeaders"

	"github.com/elazarl/goproxy"
)

// scannedHosts хранит хосты, для которых уже запущена проверка публичных файлов,
// чтобы не сканировать один и тот же сайт при каждом запросе браузера.
var (
	scannedHosts = make(map[string]bool)
	scannedMu    sync.Mutex
)

func main() {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {

			// Задача 2: сканирование публичных файлов — выполняется ДО любых блокировок,
			// один раз на каждый уникальный хост.
			host := r.URL.Scheme + "://" + r.URL.Host
			scannedMu.Lock()
			alreadyScanned := scannedHosts[host]
			if !alreadyScanned {
				scannedHosts[host] = true
			}
			scannedMu.Unlock()

			if !alreadyScanned {
				publicfiles.CheckPublicFiles(host)
			}

			// Задача 1 (существующая): блокируем не-HTTPS сайты — после сканирования
			if r.URL.Scheme != "https" {
				resp := goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden,
					"Resource doesn't use HTTPS")
				return r, resp
			}

			return r, nil
		})

	// TODO: Внести проверку на urlscan.io

	// Задача 1: проверка HTTP-заголовков безопасности — на уровне ответа
	proxy.OnResponse().DoFunc(
		func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if secheaders.CheckCSP(resp, ctx) &&
				secheaders.CheckCORS(resp, ctx) &&
				secheaders.CheckHSTS(resp, ctx) &&
				secheaders.CheckXCT(resp, ctx) &&
				secheaders.CheckXFO(resp, ctx) &&
				secheaders.CheckReferrerPolicy(resp, ctx) &&
				secheaders.CheckPermissionsPolicy(resp, ctx) {
				return resp
			}

			newResp := goproxy.NewResponse(
				ctx.Req,
				goproxy.ContentTypeText,
				http.StatusForbidden,
				"Connection refused: unsafe site",
			)

			return newResp
		})

	log.Fatal(http.ListenAndServe("localhost:8080", proxy))
}