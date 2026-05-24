package report

import (
	"fmt"
	"log"
	"strings"
	"sync"

	siteinfo "prodjects/goprox/checks/siteInfo"
)

type Severity string

const (
	SeverityCritical Severity = "КРИТИЧЕСКИЙ"
	SeverityHigh     Severity = "ВЫСОКИЙ"
	SeverityMedium   Severity = "СРЕДНИЙ"
	SeverityLow      Severity = "НИЗКИЙ"
	SeverityInfo     Severity = "ИНФО"
)

type Finding struct {
	Category  string
	Severity  Severity
	Issue     string
	Detail    string
	Recommend string
}

type SiteReport struct {
	URL      string
	Info     *siteinfo.SiteInfo
	Findings []Finding
	mu       sync.Mutex
}

var (
	reports   = make(map[string]*SiteReport)
	reportsMu sync.Mutex
)

func GetOrCreate(host string) *SiteReport {
	reportsMu.Lock()
	defer reportsMu.Unlock()
	if r, ok := reports[host]; ok {
		return r
	}
	r := &SiteReport{URL: host, Findings: []Finding{}}
	reports[host] = r
	return r
}

// GetFindings возвращает копию списка аномалий (для использования в UI-сервере).
func (r *SiteReport) GetFindings() []Finding {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]Finding, len(r.Findings))
	copy(result, r.Findings)
	return result
}

func (r *SiteReport) AddFinding(f Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.Findings {
		if existing.Detail == f.Detail && existing.Category == f.Category {
			return
		}
	}
	r.Findings = append(r.Findings, f)
}

func (r *SiteReport) SetInfo(info *siteinfo.SiteInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Info = info
}

func (r *SiteReport) AddHeaderFinding(header, severity, comment string) {
	s := mapSeverity(severity)
	r.AddFinding(Finding{
		Category:  "Заголовки безопасности",
		Severity:  s,
		Issue:     fmt.Sprintf("Заголовок %s отсутствует или настроен небезопасно", header),
		Detail:    header,
		Recommend: comment,
	})
}

func (r *SiteReport) AddPublicFileFinding(path, risk, comment string) {
	r.AddFinding(Finding{
		Category:  "Публичные файлы",
		Severity:  mapSeverity(strings.ToLower(risk)),
		Issue:     fmt.Sprintf("Файл %s доступен без авторизации", path),
		Detail:    path,
		Recommend: comment,
	})
}

func mapSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "critical", "критический":
		return SeverityCritical
	case "high", "высокий":
		return SeverityHigh
	case "medium", "средний":
		return SeverityMedium
	case "low", "низкий":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func (r *SiteReport) PrintFinalReport() {
	r.mu.Lock()
	defer r.mu.Unlock()

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString(fmt.Sprintf("║  ОТЧЁТ О БЕЗОПАСНОСТИ: %-37s║\n", truncate(r.URL, 37)))
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n")

	sb.WriteString("\n[ 1. ОБЩАЯ ИНФОРМАЦИЯ О САЙТЕ ]\n")
	if r.Info != nil {
		sb.WriteString(fmt.Sprintf("  Веб-сервер     : %s\n", r.Info.Server))
		if r.Info.DetectedEngine != "" {
			sb.WriteString(fmt.Sprintf("  Платформа      : %s\n", r.Info.DetectedEngine))
		}
		if r.Info.PoweredBy != "" {
			sb.WriteString(fmt.Sprintf("  X-Powered-By   : %s\n", r.Info.PoweredBy))
		}
		sb.WriteString(fmt.Sprintf("  Язык/фреймворк : %s\n", r.Info.DetectedLang))
		sb.WriteString(fmt.Sprintf("  Тип содержимого: %s\n", r.Info.ContentType))
	} else {
		sb.WriteString("  Данные не собраны (сайт недоступен или заблокирован)\n")
	}

	sb.WriteString("\n[ 2. НАЙДЕННЫЕ АНОМАЛИИ ]\n")
	if len(r.Findings) == 0 {
		sb.WriteString("  Аномалий не обнаружено.\n")
	} else {
		categories := make(map[string][]Finding)
		catOrder := []string{}
		for _, f := range r.Findings {
			if _, exists := categories[f.Category]; !exists {
				catOrder = append(catOrder, f.Category)
			}
			categories[f.Category] = append(categories[f.Category], f)
		}
		for _, cat := range catOrder {
			sb.WriteString(fmt.Sprintf("\n  ▶ %s:\n", cat))
			for _, f := range categories[cat] {
				icon := severityIcon(f.Severity)
				sb.WriteString(fmt.Sprintf("    %s [%s] %s\n", icon, f.Severity, f.Issue))
				if f.Detail != "" {
					sb.WriteString(fmt.Sprintf("       Деталь: %s\n", f.Detail))
				}
			}
		}
	}

	critical, high, medium, low := countBySeverity(r.Findings)
	sb.WriteString("\n[ ИТОГ ]\n")
	sb.WriteString(fmt.Sprintf("  Всего аномалий : %d\n", len(r.Findings)))
	sb.WriteString(fmt.Sprintf("  🔴 Критических : %d\n", critical))
	sb.WriteString(fmt.Sprintf("  🟠 Высоких     : %d\n", high))
	sb.WriteString(fmt.Sprintf("  🟡 Средних     : %d\n", medium))
	sb.WriteString(fmt.Sprintf("  🟢 Низких      : %d\n", low))

	sb.WriteString("\n[ 3. РЕКОМЕНДАЦИИ ПО БЕЗОПАСНОМУ ПОСЕЩЕНИЮ ]\n")
	if len(r.Findings) == 0 {
		sb.WriteString("  ✓ Посещение данного ресурса не представляет очевидных рисков.\n")
	} else {
		printed := make(map[string]bool)
		for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
			for _, f := range r.Findings {
				if f.Severity == sev && !printed[f.Recommend] {
					printed[f.Recommend] = true
					icon := severityIcon(f.Severity)
					sb.WriteString(fmt.Sprintf("  %s %s\n", icon, f.Recommend))
				}
			}
		}
		sb.WriteString("\n  [ Общие меры предосторожности ]\n")
		if critical > 0 || high > 0 {
			sb.WriteString("  ⛔ На сайте обнаружены критические уязвимости.\n")
			sb.WriteString("     Не вводите личные данные, пароли и платёжную информацию.\n")
		} else if medium > 0 {
			sb.WriteString("  ⚠️  Сайт имеет недостатки конфигурации. Будьте осторожны.\n")
		} else {
			sb.WriteString("  ℹ️  Незначительные недостатки. Сайт безопасен для посещения.\n")
		}
	}
	sb.WriteString("\n══════════════════════════════════════════════════════════════════\n")
	log.Print(sb.String())
}

func severityIcon(s Severity) string {
	switch s {
	case SeverityCritical:
		return "🔴"
	case SeverityHigh:
		return "🟠"
	case SeverityMedium:
		return "🟡"
	case SeverityLow:
		return "🟢"
	default:
		return "⚪"
	}
}

func countBySeverity(findings []Finding) (critical, high, medium, low int) {
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			critical++
		case SeverityHigh:
			high++
		case SeverityMedium:
			medium++
		case SeverityLow:
			low++
		}
	}
	return
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
