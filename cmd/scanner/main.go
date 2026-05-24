package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	rep "prodjects/goprox/checks/report"
	siteinfo "prodjects/goprox/checks/siteInfo"
	publicfiles "prodjects/goprox/checks/publicFiles"
)

// ScanRequest — входящий запрос от интерфейса.
type ScanRequest struct {
	URL string `json:"url"`
}

// FindingJSON — одна аномалия для передачи в браузер.
type FindingJSON struct {
	Category  string `json:"category"`
	Severity  string `json:"severity"`
	Issue     string `json:"issue"`
	Detail    string `json:"detail"`
	Recommend string `json:"recommend"`
}

// ScanResponse — полный ответ сервера после сканирования.
type ScanResponse struct {
	URL           string        `json:"url"`
	Server        string        `json:"server"`
	PoweredBy     string        `json:"powered_by"`
	DetectedLang  string        `json:"detected_lang"`
	ContentType   string        `json:"content_type"`
	Findings      []FindingJSON `json:"findings"`
	CountCritical int           `json:"count_critical"`
	CountHigh     int           `json:"count_high"`
	CountMedium   int           `json:"count_medium"`
	CountLow      int           `json:"count_low"`
	SafeToVisit   string        `json:"safe_to_visit"` // "yes", "caution", "no"
	GeneralAdvice string        `json:"general_advice"`
}

func main() {
	// Отдаём HTML-интерфейс
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "ui/index.html")
	})

	// API-эндпоинт сканирования
	http.HandleFunc("/scan", handleScan)

	addr := "127.0.0.1:9090"
	fmt.Printf("goprox UI запущен: http://%s\n", addr)

	// Автоматически открываем браузер
	go openBrowser("http://" + addr)

	log.Fatal(http.ListenAndServe(addr, nil))
}

// handleScan принимает URL, запускает все проверки и возвращает JSON-отчёт.
func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Неверный запрос", http.StatusBadRequest)
		return
	}

	targetURL := strings.TrimSpace(req.URL)
	if targetURL == "" {
		http.Error(w, "URL не указан", http.StatusBadRequest)
		return
	}

	// Нормализуем URL
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}
	targetURL = strings.TrimRight(targetURL, "/")

	// Создаём отчёт для этого хоста
	siteReport := rep.GetOrCreate(targetURL)

	// 1. Сбор информации о сайте
	info, err := siteinfo.Collect(targetURL)
	if err == nil {
		siteReport.SetInfo(info)
	}

	// 2. Проверка HTTP-заголовков
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(targetURL)
	if err == nil {
		defer resp.Body.Close()
		// Создаём фиктивный контекст для совместимости с secHeaders
		checkHeaders(resp, targetURL, siteReport)
	}

	// 3. Поиск публичных файлов
	publicfiles.CheckPublicFilesInto(targetURL, siteReport)

	// Формируем JSON-ответ
	result := buildResponse(targetURL, info, siteReport)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(result)
}

// checkHeaders проверяет заголовки безопасности напрямую (без прокси-контекста).
func checkHeaders(resp *http.Response, host string, r *rep.SiteReport) {
	checks := []struct {
		header  string
		risk    string
		comment string
	}{
		{"Content-Security-Policy", "high",
			"Добавьте Content-Security-Policy: default-src 'self'. Защита от XSS-атак."},
		{"Strict-Transport-Security", "high",
			"Добавьте Strict-Transport-Security: max-age=31536000; includeSubDomains. Защита от MITM-атак."},
		{"X-Frame-Options", "medium",
			"Добавьте X-Frame-Options: DENY или SAMEORIGIN. Защита от кликджекинга."},
		{"X-Content-Type-Options", "medium",
			"Добавьте X-Content-Type-Options: nosniff. Защита от подмены MIME-типа."},
		{"Referrer-Policy", "low",
			"Добавьте Referrer-Policy: strict-origin-when-cross-origin. Ограничение утечки URL."},
		{"Permissions-Policy", "low",
			"Добавьте Permissions-Policy: camera=(), microphone=(), geolocation=(). Ограничение API браузера."},
	}

	for _, c := range checks {
		val := resp.Header.Get(c.header)
		if val == "" {
			r.AddHeaderFinding(c.header, c.risk, c.comment)
		}
		// Дополнительная проверка опасных значений
		if c.header == "Content-Security-Policy" && val != "" {
			if strings.Contains(val, "unsafe-inline") || strings.Contains(val, "unsafe-eval") {
				r.AddHeaderFinding(c.header+" (небезопасное значение)", "high",
					"Уберите 'unsafe-inline' и 'unsafe-eval' из CSP.")
			}
		}
		if c.header == "Access-Control-Allow-Origin" && val == "*" {
			r.AddHeaderFinding("Access-Control-Allow-Origin (*)", "critical",
				"Замените '*' на список доверенных доменов.")
		}
	}
}

// buildResponse собирает итоговую структуру ответа.
func buildResponse(url string, info *siteinfo.SiteInfo, r *rep.SiteReport) ScanResponse {
	result := ScanResponse{URL: url}

	if info != nil {
		result.Server = info.Server
		result.PoweredBy = info.PoweredBy
		result.DetectedLang = info.DetectedLang
		result.ContentType = info.ContentType
	}

	findings := r.GetFindings()
	for _, f := range findings {
		result.Findings = append(result.Findings, FindingJSON{
			Category:  f.Category,
			Severity:  string(f.Severity),
			Issue:     f.Issue,
			Detail:    f.Detail,
			Recommend: f.Recommend,
		})
		switch f.Severity {
		case rep.SeverityCritical:
			result.CountCritical++
		case rep.SeverityHigh:
			result.CountHigh++
		case rep.SeverityMedium:
			result.CountMedium++
		case rep.SeverityLow:
			result.CountLow++
		}
	}

	// Общая оценка безопасности
	if result.CountCritical > 0 || result.CountHigh > 3 {
		result.SafeToVisit = "no"
		result.GeneralAdvice = "На сайте обнаружены серьёзные уязвимости. Не вводите личные данные и пароли. По возможности воздержитесь от посещения."
	} else if result.CountHigh > 0 || result.CountMedium > 2 {
		result.SafeToVisit = "caution"
		result.GeneralAdvice = "Сайт имеет недостатки в конфигурации безопасности. Будьте осторожны при передаче личных данных."
	} else {
		result.SafeToVisit = "yes"
		result.GeneralAdvice = "Сайт не имеет критических проблем безопасности и безопасен для посещения."
	}

	return result
}

// openBrowser открывает браузер на указанном URL.
func openBrowser(url string) {
	time.Sleep(500 * time.Millisecond)
	switch runtime.GOOS {
	case "windows":
		exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		exec.Command("open", url).Start()
	default:
		exec.Command("xdg-open", url).Start()
	}
}
