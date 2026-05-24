package publicfiles

import (
	"log"
	"net/http"
	"strings"
	"time"

	rep "prodjects/goprox/checks/report"
)

type target struct {
	path    string
	risk    string
	comment string
}

var publicFileTargets = []target{
	{"/.env", "critical", "Закройте публичный доступ к файлу .env — он содержит пароли БД и API-ключи. Добавьте правило запрета в конфигурацию веб-сервера."},
	{"/.env.local", "critical", "Закройте доступ к .env.local — локальный файл конфигурации не должен быть доступен извне."},
	{"/config.php", "critical", "Закройте доступ к config.php — файл содержит параметры подключения к базе данных."},
	{"/wp-config.php", "critical", "Закройте доступ к wp-config.php через конфигурацию Nginx/Apache. Это критически важный файл WordPress."},
	{"/configuration.php", "critical", "Закройте доступ к configuration.php — конфигурационный файл Joomla с секретными данными."},
	{"/settings.py", "critical", "Закройте доступ к settings.py — файл настроек Django содержит SECRET_KEY и параметры БД."},
	{"/.git/config", "critical", "Закройте директорию .git через конфигурацию сервера — доступ к ней позволяет скачать весь исходный код."},
	{"/.git/HEAD", "critical", "Директория .git открыта публично. Добавьте запрет доступа к /.git/ в настройках веб-сервера."},
	{"/.svn/entries", "critical", "Закройте директорию .svn — через неё можно восстановить исходный код из SVN-репозитория."},
	{"/backup.zip", "critical", "Удалите архив резервной копии с веб-сервера или переместите его за пределы публичной директории."},
	{"/backup.sql", "critical", "Удалите дамп базы данных с веб-сервера — он содержит все данные пользователей."},
	{"/db.sql", "critical", "Удалите файл дампа БД с веб-сервера или ограничьте доступ к нему."},
	{"/backup.tar.gz", "critical", "Удалите архив резервной копии из публичной директории веб-сервера."},
	{"/phpmyadmin", "high", "Ограничьте доступ к phpMyAdmin по IP-адресу или перенесите его на нестандартный URL."},
	{"/phpmyadmin/index.php", "high", "phpMyAdmin доступен без ограничений. Настройте доступ только с доверенных IP-адресов."},
	{"/admin", "medium", "Убедитесь что административная панель защищена надёжным паролем и двухфакторной аутентификацией."},
	{"/wp-admin", "medium", "Ограничьте доступ к /wp-admin по IP или установите плагин защиты входа с поддержкой 2FA."},
	{"/.htaccess", "medium", "Настройте сервер так чтобы файл .htaccess не отдавался клиентам (deny from all)."},
	{"/server-status", "medium", "Отключите mod_status Apache или ограничьте доступ к /server-status по IP."},
	{"/server-info", "medium", "Отключите mod_info Apache или ограничьте доступ к /server-info по IP."},
	{"/error.log", "medium", "Закройте публичный доступ к журналу ошибок — он раскрывает внутреннюю структуру сайта."},
	{"/access.log", "medium", "Закройте публичный доступ к журналу доступа — он содержит IP-адреса посетителей."},
	{"/package.json", "low", "Рассмотрите ограничение доступа к package.json — он раскрывает версии зависимостей с возможными уязвимостями."},
	{"/composer.json", "low", "Рассмотрите ограничение доступа к composer.json — он раскрывает версии PHP-пакетов."},
	{"/requirements.txt", "low", "Рассмотрите ограничение доступа к requirements.txt — он раскрывает Python-зависимости."},
	{"/robots.txt", "low", "Проверьте robots.txt: директивы Disallow не должны указывать на чувствительные разделы сайта."},
	{"/sitemap.xml", "low", "Sitemap.xml раскрывает полную структуру сайта — убедитесь что все перечисленные URL предназначены для публичного доступа."},
}

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// CheckPublicFiles проверяет наличие опасных общедоступных файлов
// и передаёт найденные аномалии в модуль report.
func CheckPublicFiles(baseURL string) {
	baseURL = strings.TrimRight(baseURL, "/")
	r := rep.GetOrCreate(baseURL)

	log.Printf("[PublicFiles] Starting scan: %s (%d paths)", baseURL, len(publicFileTargets))

	found := 0
	for _, t := range publicFileTargets {
		fullURL := baseURL + t.path
		status, err := probeURL(fullURL)
		if err != nil {
			continue
		}
		if status == http.StatusOK {
			found++
			log.Printf("[PublicFiles] [%s] %s (HTTP 200)", strings.ToUpper(t.risk), t.path)
			r.AddPublicFileFinding(t.path, t.risk, t.comment)
		}
	}

	if found == 0 {
		log.Printf("[PublicFiles] Scan complete: no exposed files found on %s", baseURL)
	} else {
		log.Printf("[PublicFiles] Scan complete: %d exposed file(s) found on %s", found, baseURL)
	}

	// После завершения всех проверок публичных файлов — выводим итоговый отчёт
	r.PrintFinalReport()
}

func probeURL(url string) (int, error) {
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusMethodNotAllowed {
		getReq, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return 0, err
		}
		getReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		getResp, err := httpClient.Do(getReq)
		if err != nil {
			return 0, err
		}
		getResp.Body.Close()
		return getResp.StatusCode, nil
	}

	return resp.StatusCode, nil
}
