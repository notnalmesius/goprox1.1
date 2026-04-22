package main

import (
	"log"
	"net/http"

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
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			
		}
	)

	log.Fatal(http.ListenAndServe("localhost:8080", proxy))

}
