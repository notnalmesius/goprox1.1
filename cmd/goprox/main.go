package main

import (
	"log"
	"net/http"
	secheaders "prodjects/goprox/checks/secHeaders"

	"github.com/elazarl/goproxy"
)

func main() {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	// Check if TLS using
	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			if r.URL.Scheme != "https" {
				resp := goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden, "Resource doesn't use HTTPS")
				return r, resp
			}
			return r, nil
		})

	// TODO: Внести проверку на urlscan.io

	// Check Security Headers
	proxy.OnResponse().DoFunc(
		func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if secheaders.CheckCSP(resp, ctx) &&
				secheaders.CheckCORS(resp, ctx) &&
				// secheaders.CheckXCT(resp, ctx) &&
				// secheaders.CheckXFO(resp, ctx) &&
				secheaders.CheckHSTS(resp, ctx) {
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
