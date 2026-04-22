package urlscan

import "time"

const (
	urlScanToken string = "019db650-e002-72ae-9a40-2e5e12bdc67a"
	submitURL           = "https://urlscan.io/api/v1/scan/"
	pollInterval        = 2 * time.Second
	pollTimeout         = 60 * time.Second
)

type ScanResult struct {
	Message string `json:"message"`
	UUID    string `json:"uuid"`
	API     string `json:"api"`
	Result  string `json:"result"`
}

// TODO: Реализовать методы обращения к API и структуры ответов
