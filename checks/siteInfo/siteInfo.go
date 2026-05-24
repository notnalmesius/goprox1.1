// Пакет siteinfo реализует сбор общей информации о веб-сайте:
// типе веб-сервера и языке программирования серверной части.
package siteinfo

import (
	"fmt"
	"net/http"
	"strings"
)

// SiteInfo содержит собранную информацию о сайте.
type SiteInfo struct {
	URL             string // Проверяемый URL
	Server          string // Веб-сервер (например, nginx, Apache)
	PoweredBy       string // Язык/фреймворк (например, PHP/8.1, ASP.NET)
	ContentType     string // Тип содержимого страницы
	DetectedLang    string // Язык программирования, определённый по косвенным признакам
	DetectedEngine  string // CMS или фреймворк (WordPress, Django и т.д.)
}

// serverSignatures — словарь ключевых слов для определения веб-сервера
// по значению заголовка Server.
var serverSignatures = map[string]string{
	"nginx":              "Nginx",
	"apache":             "Apache",
	"microsoft-iis":      "Microsoft IIS",
	"lighttpd":           "Lighttpd",
	"openresty":          "OpenResty (Nginx + Lua)",
	"cloudflare":         "Cloudflare",
	"gunicorn":           "Gunicorn (Python)",
	"uvicorn":            "Uvicorn (Python/ASGI)",
	"caddy":              "Caddy",
	"jetty":              "Jetty (Java)",
	"tomcat":             "Apache Tomcat (Java)",
	"kestrel":            "Kestrel (.NET)",
	"node":               "Node.js",
	"express":            "Express.js (Node.js)",
}

// languageSignatures — словарь ключевых слов для определения языка программирования
// по заголовкам X-Powered-By, Set-Cookie, X-Generator и другим.
var languageSignatures = map[string]string{
	"php":        "PHP",
	"asp.net":    "ASP.NET (C#)",
	"java":       "Java",
	"python":     "Python",
	"ruby":       "Ruby",
	"perl":       "Perl",
	"node":       "Node.js (JavaScript)",
	"express":    "Node.js (Express)",
	"django":     "Python (Django)",
	"flask":      "Python (Flask)",
	"laravel":    "PHP (Laravel)",
	"symfony":    "PHP (Symfony)",
	"rails":      "Ruby on Rails",
	"spring":     "Java (Spring)",
	"wordpress":  "PHP (WordPress)",
	"joomla":     "PHP (Joomla)",
	"drupal":     "PHP (Drupal)",
}

// Collect выполняет GET-запрос к указанному URL и собирает
// общую информацию о веб-сервере и языке программирования.
//
// Алгоритм работы:
//  1. Выполнить GET-запрос к целевому URL.
//  2. Извлечь заголовок Server — определить тип веб-сервера.
//  3. Извлечь заголовок X-Powered-By — определить язык/фреймворк напрямую.
//  4. Если X-Powered-By отсутствует — определить язык косвенно:
//     по заголовкам Set-Cookie, X-Generator, Via, X-AspNet-Version и другим.
//  5. Извлечь Content-Type — тип содержимого страницы.
//  6. Вернуть структуру SiteInfo с собранными данными.
func Collect(targetURL string) (*SiteInfo, error) {
	client := &http.Client{}

	resp, err := client.Get(targetURL)
	if err != nil {
		return nil, fmt.Errorf("не удалось выполнить запрос к %s: %w", targetURL, err)
	}
	defer resp.Body.Close()

	info := &SiteInfo{
		URL: targetURL,
	}

	// Шаг 2: определяем веб-сервер по заголовку Server
	serverHeader := resp.Header.Get("Server")
	if serverHeader != "" {
		info.Server = serverHeader
		info.DetectedEngine = detectBySignatures(serverHeader, serverSignatures)
	} else {
		info.Server = "не определён (заголовок Server отсутствует)"
	}

	// Шаг 3: определяем язык напрямую по X-Powered-By
	poweredBy := resp.Header.Get("X-Powered-By")
	if poweredBy != "" {
		info.PoweredBy = poweredBy
		info.DetectedLang = detectBySignatures(poweredBy, languageSignatures)
	}

	// Шаг 4: косвенное определение языка по другим заголовкам
	if info.DetectedLang == "" {
		info.DetectedLang = detectLangIndirect(resp)
	}

	// Шаг 5: тип содержимого
	ct := resp.Header.Get("Content-Type")
	if ct != "" {
		info.ContentType = ct
	} else {
		info.ContentType = "не указан"
	}

	return info, nil
}

// detectBySignatures ищет совпадение ключевых слов из словаря в строке value.
func detectBySignatures(value string, signatures map[string]string) string {
	lower := strings.ToLower(value)
	for key, name := range signatures {
		if strings.Contains(lower, key) {
			return name
		}
	}
	return ""
}

// detectLangIndirect пытается определить язык программирования
// по косвенным признакам в других заголовках ответа.
func detectLangIndirect(resp *http.Response) string {
	// Проверяем заголовок X-AspNet-Version — однозначно указывает на ASP.NET
	if v := resp.Header.Get("X-AspNet-Version"); v != "" {
		return fmt.Sprintf("ASP.NET (версия %s)", v)
	}

	// Проверяем X-AspNetMvc-Version
	if v := resp.Header.Get("X-AspNetMvc-Version"); v != "" {
		return fmt.Sprintf("ASP.NET MVC (версия %s)", v)
	}

	// Проверяем X-Generator (часто используют CMS)
	if gen := resp.Header.Get("X-Generator"); gen != "" {
		detected := detectBySignatures(gen, languageSignatures)
		if detected != "" {
			return detected
		}
		return gen
	}

	// Анализируем Set-Cookie: PHPSESSID → PHP, JSESSIONID → Java
	cookies := resp.Header.Get("Set-Cookie")
	if cookies != "" {
		lower := strings.ToLower(cookies)
		if strings.Contains(lower, "phpsessid") {
			return "PHP"
		}
		if strings.Contains(lower, "jsessionid") {
			return "Java"
		}
		if strings.Contains(lower, "asp.net_sessionid") {
			return "ASP.NET (C#)"
		}
		if strings.Contains(lower, "rack.session") {
			return "Ruby (Rack/Rails)"
		}
		if strings.Contains(lower, "django") || strings.Contains(lower, "csrftoken") {
			return "Python (Django)"
		}
	}

	// Анализируем Via — может указывать на технологию
	via := resp.Header.Get("Via")
	if via != "" {
		detected := detectBySignatures(via, languageSignatures)
		if detected != "" {
			return detected
		}
	}

	return "не определён"
}

// FormatSiteInfo форматирует собранную информацию для вывода в лог.
func FormatSiteInfo(info *SiteInfo) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\n========== Информация о сайте: %s ==========\n", info.URL))
	sb.WriteString(fmt.Sprintf("  Веб-сервер     : %s\n", info.Server))

	if info.DetectedEngine != "" {
		sb.WriteString(fmt.Sprintf("  Платформа      : %s\n", info.DetectedEngine))
	}

	if info.PoweredBy != "" {
		sb.WriteString(fmt.Sprintf("  X-Powered-By   : %s\n", info.PoweredBy))
	}

	sb.WriteString(fmt.Sprintf("  Язык/фреймворк : %s\n", info.DetectedLang))
	sb.WriteString(fmt.Sprintf("  Тип содержимого: %s\n", info.ContentType))
	sb.WriteString("=====================================================\n")

	return sb.String()
}
