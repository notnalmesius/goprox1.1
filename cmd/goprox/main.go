package main

import (
	"log"
	"net/http"
	"sync"

	publicfiles "prodjects/goprox/checks/publicFiles"
	rep "prodjects/goprox/checks/report"
	secheaders "prodjects/goprox/checks/secHeaders"
	siteinfo "prodjects/goprox/checks/siteInfo"

	"github.com/elazarl/goproxy"
)

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

			host := r.URL.Scheme + "://" + r.URL.Host
			scannedMu.Lock()
			alreadyScanned := scannedHosts[host]
			if !alreadyScanned {
				scannedHosts[host] = true
			}
			scannedMu.Unlock()

			if !alreadyScanned {
				// Задача 1: сбор информации о сайте
				info, err := siteinfo.Collect(host)
				if err == nil {
					report := rep.GetOrCreate(host)
					report.SetInfo(info)
					log.Print(siteinfo.FormatSiteInfo(info))
				}

				// Задача 2 итерации 5: поиск публичных файлов
				// (внутри вызывает PrintFinalReport — Задачи 2 и 3 текущей итерации)
				publicfiles.CheckPublicFiles(host)
			}

			// Блокируем не-HTTPS после сканирования
			if r.URL.Scheme != "https" {
				resp := goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden,
					"Resource doesn't use HTTPS")
				return r, resp
			}

			return r, nil
		})

	// Задача 1 итерации 5: проверка HTTP-заголовков — на уровне ответа
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