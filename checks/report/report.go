// Пакет report реализует сбор результатов всех проверок безопасности,
// формирование структурированного отчёта об аномалиях (Задача 2)
// и рекомендаций по безопасному посещению веб-ресурса (Задача 3).
package report

import (
	"fmt"
	"log"
	"strings"
	"sync"

	siteinfo "prodjects/goprox/checks/siteInfo"
)

// Severity — уровень серьёзности найденной аномалии.
type Severity string

const (
	SeverityCritical Severity = "КРИТИЧЕСКИЙ"
	SeverityHigh     Severity = "ВЫСОКИЙ"
	SeverityMedium   Severity = "СРЕДНИЙ"
	SeverityLow      Severity = "НИЗКИЙ"
	SeverityInfo     Severity = "ИНФО"
)

// Finding описывает одну найденную аномалию.
type Finding struct {
	Category   string   // Категория: "Заголовки", "Публичные файлы", "Информация о сайте"
	Severity   Severity // Уровень серьёзности
	Issue      string   // Описание проблемы
	Detail     string   // Дополнительная деталь (например, конкретный заголовок или путь)
	Recommend  string   // Рекомендация по устранению
}

// SiteReport — полный отчёт по одному сайту, собирающий данные от всех модулей.
type SiteReport struct {
	URL      string       // Проверяемый URL
	Info     *siteinfo.SiteInfo // Результат модуля siteInfo (Задача 1)
	Findings []Finding    // Список всех найденных аномалий
	mu       sync.Mutex   // Защита от гонок при параллельной записи
}

// reports хранит отчёты по каждому хосту.
var (
	reports   = make(map[string]*SiteReport)
	reportsMu sync.Mutex
)

// GetOrCreate возвращает существующий отчёт для хоста или создаёт новый.
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

// AddFinding добавляет аномалию в отчёт (потокобезопасно).
func (r *SiteReport) AddFinding(f Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Findings = append(r.Findings, f)
}

// SetInfo сохраняет результат модуля siteInfo в отчёт.
func (r *SiteReport) SetInfo(info *siteinfo.SiteInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Info = info
}

// --- Вспомогательные функции для добавления результатов от других модулей ---

// AddHeaderFinding добавляет аномалию от модуля проверки заголовков (Задача итерации 5).
// severity: "high", "medium", "low"
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

// AddPublicFileFinding добавляет аномалию от модуля поиска публичных файлов (Задача итерации 5).
func (r *SiteReport) AddPublicFileFinding(path, risk, comment string) {
	r.AddFinding(Finding{
		Category:  "Публичные файлы",
		Severity:  mapSeverity(strings.ToLower(risk)),
		Issue:     fmt.Sprintf("Файл %s доступен без авторизации", path),
		Detail:    path,
		Recommend: comment,
	})
}

// mapSeverity переводит строковый уровень риска в тип Severity.
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

// --- Формирование отчёта (Задача 2) и рекомендаций (Задача 3) ---

// PrintFinalReport выводит полный структурированный отчёт в лог.
// Вызывается после завершения всех проверок для данного хоста.
//
// Алгоритм работы:
//  1. Вывести блок «Информация о сайте» (из модуля siteInfo).
//  2. Сгруппировать все аномалии по категориям.
//  3. Для каждой аномалии вывести уровень риска, описание и деталь.
//  4. Вывести итоговую статистику: количество аномалий по уровням.
//  5. Вывести блок рекомендаций (Задача 3): для каждой аномалии — конкретный совет.
func (r *SiteReport) PrintFinalReport() {
	r.mu.Lock()
	defer r.mu.Unlock()

	var sb strings.Builder

	// ─── Шапка отчёта ────────────────────────────────────────────────────────
	sb.WriteString("\n")
	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString(fmt.Sprintf("║  ОТЧЁТ О БЕЗОПАСНОСТИ: %-37s║\n", truncate(r.URL, 37)))
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n")

	// ─── Блок 1: Информация о сайте (Задача 1) ───────────────────────────────
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

	// ─── Блок 2: Найденные аномалии (Задача 2) ───────────────────────────────
	sb.WriteString("\n[ 2. НАЙДЕННЫЕ АНОМАЛИИ ]\n")

	if len(r.Findings) == 0 {
		sb.WriteString("  Аномалий не обнаружено.\n")
	} else {
		// Группируем по категориям
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

	// ─── Итоговая статистика ──────────────────────────────────────────────────
	critical, high, medium, low := countBySeverity(r.Findings)
	sb.WriteString("\n[ ИТОГ ]\n")
	sb.WriteString(fmt.Sprintf("  Всего аномалий : %d\n", len(r.Findings)))
	sb.WriteString(fmt.Sprintf("  🔴 Критических : %d\n", critical))
	sb.WriteString(fmt.Sprintf("  🟠 Высоких     : %d\n", high))
	sb.WriteString(fmt.Sprintf("  🟡 Средних     : %d\n", medium))
	sb.WriteString(fmt.Sprintf("  🟢 Низких      : %d\n", low))

	// ─── Блок 3: Рекомендации (Задача 3) ─────────────────────────────────────
	sb.WriteString("\n[ 3. РЕКОМЕНДАЦИИ ПО БЕЗОПАСНОМУ ПОСЕЩЕНИЮ ]\n")

	if len(r.Findings) == 0 {
		sb.WriteString("  Сайт не имеет выявленных проблем безопасности.\n")
		sb.WriteString("  ✓ Посещение данного ресурса не представляет очевидных рисков.\n")
	} else {
		// Выводим рекомендации, начиная с наиболее критичных
		printed := make(map[string]bool) // избегаем дублей одинаковых рекомендаций
		for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
			for _, f := range r.Findings {
				if f.Severity == sev && !printed[f.Recommend] {
					printed[f.Recommend] = true
					icon := severityIcon(f.Severity)
					sb.WriteString(fmt.Sprintf("  %s %s\n", icon, f.Recommend))
				}
			}
		}

		// Общие рекомендации для пользователя
		sb.WriteString("\n  [ Общие меры предосторожности ]\n")
		if critical > 0 || high > 0 {
			sb.WriteString("  ⛔ На сайте обнаружены критические уязвимости.\n")
			sb.WriteString("     Не вводите личные данные, пароли и платёжную информацию.\n")
			sb.WriteString("     По возможности воздержитесь от посещения данного ресурса.\n")
		} else if medium > 0 {
			sb.WriteString("  ⚠️  Сайт имеет недостатки в конфигурации безопасности.\n")
			sb.WriteString("     Будьте осторожны при передаче личных данных.\n")
			sb.WriteString("     Убедитесь что соединение защищено (значок замка в браузере).\n")
		} else {
			sb.WriteString("  ℹ️  Обнаружены незначительные недостатки.\n")
			sb.WriteString("     Сайт в целом безопасен для посещения.\n")
		}
	}

	sb.WriteString("\n══════════════════════════════════════════════════════════════════\n")

	log.Print(sb.String())
}

// severityIcon возвращает текстовый символ для уровня серьёзности.
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

// countBySeverity подсчитывает количество аномалий по уровням.
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

// truncate обрезает строку до maxLen символов.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
