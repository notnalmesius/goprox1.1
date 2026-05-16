package publicfiles

import (
	"log"
	"net/http"
	"strings"
	"time"
)

// target описывает один проверяемый путь.
type target struct {
	path    string
	risk    string // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	comment string
}

// publicFileTargets — список путей, наличие которых в открытом доступе
// представляет угрозу безопасности.
var publicFileTargets = []target{
	// Конфигурационные файлы
	{"/.env", "CRITICAL", "Файл переменных окружения: пароли БД, API-ключи, секретные токены"},
	{"/.env.local", "CRITICAL", "Локальный файл конфигурации с секретными данными окружения"},
	{"/config.php", "CRITICAL", "Файл конфигурации PHP: параметры подключения к БД"},
	{"/wp-config.php", "CRITICAL", "Конфигурация WordPress: данные доступа к БД"},
	{"/configuration.php", "CRITICAL", "Конфигурация Joomla: параметры БД и секретные ключи"},
	{"/settings.py", "CRITICAL", "Настройки Django: SECRET_KEY, параметры БД"},
	// Системы контроля версий
	{"/.git/config", "CRITICAL", "Git-репозиторий доступен: возможна утечка исходного кода"},
	{"/.git/HEAD", "CRITICAL", "Директория .git открыта: весь исходный код может быть скачан"},
	{"/.svn/entries", "CRITICAL", "SVN-репозиторий доступен: возможна утечка исходного кода"},
	// Резервные копии
	{"/backup.zip", "CRITICAL", "Архив резервной копии сайта доступен без авторизации"},
	{"/backup.sql", "CRITICAL", "Дамп базы данных доступен без авторизации"},
	{"/db.sql", "CRITICAL", "Файл дампа БД доступен без ограничений"},
	{"/backup.tar.gz", "CRITICAL", "Архив резервной копии доступен без авторизации"},
	// Административные панели
	{"/phpmyadmin", "HIGH", "phpMyAdmin доступен публично: прямой интерфейс управления БД"},
	{"/phpmyadmin/index.php", "HIGH", "phpMyAdmin доступен без ограничений"},
	{"/admin", "MEDIUM", "Административная панель обнаружена и доступна"},
	{"/wp-admin", "MEDIUM", "Панель администратора WordPress доступна"},
	// Служебные файлы
	{"/.htaccess", "MEDIUM", "Файл .htaccess раскрывает правила маршрутизации и конфигурацию Apache"},
	{"/server-status", "MEDIUM", "Apache mod_status раскрывает IP-адреса и текущие запросы к серверу"},
	{"/server-info", "MEDIUM", "Страница server-info раскрывает подробную конфигурацию веб-сервера"},
	{"/error.log", "MEDIUM", "Журнал ошибок раскрывает трассировки стека и пути к файлам"},
	{"/access.log", "MEDIUM", "Журнал доступа раскрывает все HTTP-запросы и IP-адреса посетителей"},
	// Зависимости
	{"/package.json", "LOW", "Раскрывает зависимости Node.js: злоумышленник найдёт уязвимые версии"},
	{"/composer.json", "LOW", "Раскрывает зависимости PHP-пакетов и их версии"},
	{"/requirements.txt", "LOW", "Раскрывает зависимости Python и их версии"},
	// Служебные
	{"/robots.txt", "LOW", "Может раскрывать скрытые разделы через директивы Disallow"},
	{"/sitemap.xml", "LOW", "Раскрывает полную структуру и все URL сайта"},
}

// httpClient — общий клиент с таймаутом для всех проверок.
// Не следует редиректам: сервер, перенаправляющий 404 на главную,
// вернёт 301/302, а не 200 — это исключает ложные срабатывания.
var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// CheckPublicFiles выполняет проверку общедоступных файлов для указанного хоста.
// Вызывается один раз при первом обращении браузера к новому хосту.
// baseURL — схема + хост, например "https://example.com".
func CheckPublicFiles(baseURL string) {
	baseURL = strings.TrimRight(baseURL, "/")
	log.Printf("[PublicFiles] Starting scan: %s (%d paths)", baseURL, len(publicFileTargets))

	found := 0
	for _, t := range publicFileTargets {
		fullURL := baseURL + t.path
		status, err := probeURL(fullURL)
		if err != nil {
			// Таймаут или сетевая ошибка — пропускаем
			continue
		}
		if status == http.StatusOK {
			found++
			log.Printf("[PublicFiles] [%s] %s — %s (HTTP 200)", t.risk, t.path, t.comment)
		}
	}

	if found == 0 {
		log.Printf("[PublicFiles] Scan complete: no exposed files found on %s", baseURL)
	} else {
		log.Printf("[PublicFiles] Scan complete: %d exposed file(s) found on %s", found, baseURL)
	}
}

// probeURL отправляет HEAD-запрос. Если сервер возвращает 405 — повторяет через GET.
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