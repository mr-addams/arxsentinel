// ========================== Модуль config ==============================================
//   Единая точка определения всех поведенческих параметров проекта.
//   LoadConfig() — парсит config.yaml с дефолтами, возвращает заполненный Config.
//
//   ЧТО ЗДЕСЬ:
//     - Структура Config с вложенными секциями по модулям
//     - LoadConfig(path string) (Config, error) — единственная публичная функция
//     - Duration — тип-обёртка для парсинга строк вида "300s", "24h" из YAML
//     - defaultConfig() + defaultProbePaths() + defaultBots() — внутренние дефолты
//
//   ЧТО НЕ ЗДЕСЬ:
//     - Бизнес-логика (core/)
//     - Логирование (sys/utils)
//
//   ОГРАНИЧЕНИЕ yaml-парсинга:
//     yaml.v3 накладывает значения поверх дефолтов на уровне секций целиком.
//     Если в config.yaml указана секция scoring:, она должна содержать ВСЕ поля —
//     иначе неуказанные поля обнулятся (yaml.v3 не поддерживает partial merge).
//     Отсутствующие секции целиком сохраняют Go-дефолты.

package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ========================== Вспомогательный тип Duration ===============================

// Duration — обёртка над time.Duration для корректного парсинга строк из YAML.
// yaml.v3 не умеет из коробки превращать "300s", "24h" → time.Duration.
// Приведение к time.Duration: time.Duration(cfg.Scoring.ObservationWindow).
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("некорректная длительность %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// ========================== Корневой Config ============================================

type Config struct {
	General   GeneralConfig   `yaml:"general"`
	Logging   LoggingConfig   `yaml:"logging"`
	Parser    ParserConfig    `yaml:"parser"`
	Scoring   ScoringConfig   `yaml:"scoring"`
	State     StateConfig     `yaml:"state"`
	Detectors DetectorsConfig `yaml:"detectors"`
	Whitelist WhitelistConfig `yaml:"whitelist"`
	Output    OutputConfig    `yaml:"output"`
}

// ++++++++++++++++++++++++++ Секция: general +++++++++++++++++++++++++++++++++++++++++++

type GeneralConfig struct {
	LogFile           string   `yaml:"log_file"`            // YAML: general.log_file, default "/var/log/nginx/access.log" — путь к access.log nginx. Потребитель: utils.TailReader
	PIDFile           string   `yaml:"pid_file"`            // YAML: general.pid_file, default "/var/run/nginx-sentinel.pid" — PID-файл демона. Потребитель: main.go
	LinesBufSize      int      `yaml:"lines_buf_size"`      // YAML: general.lines_buf_size, default 1000 — буфер канала между TailReader и обработчиком строк; поднять при burst >1000 строк/сек. Потребитель: main.go
	TailRetryInterval Duration `yaml:"tail_retry_interval"` // YAML: general.tail_retry_interval, default "5s" — интервал повтора при недоступном log_file. Потребитель: utils.TailReader
	// Пути к лог-файлам демона — в секции output: (полные пути, не директория)
}

// ++++++++++++++++++++++++++ Секция: logging ++++++++++++++++++++++++++++++++++++++++++++

type LoggingConfig struct {
	Debug        bool `yaml:"debug"`         // YAML: logging.debug, default false — показывать debugOnlyTags в консоль. Потребитель: utils.DebugEnabled
	ConsoleColor bool `yaml:"console_color"` // YAML: logging.console_color, default true — цветной вывод в консоль. Потребитель: utils.ColorEnabled
}

// ++++++++++++++++++++++++++ Секция: parser +++++++++++++++++++++++++++++++++++++++++++++

type ParserConfig struct {
	LogFormat string `yaml:"log_format"` // YAML: parser.log_format, default "combined" — зарезервировано, поддерживается только "combined". Потребитель: не подключён
	Timezone  string `yaml:"timezone"`   // YAML: parser.timezone, default "UTC" — зарезервировано; парсер берёт timezone из offset в строке лога (+0000). Потребитель: не подключён
}

// ++++++++++++++++++++++++++ Секция: scoring +++++++++++++++++++++++++++++++++++++++++++

type ScoringConfig struct {
	AlertThreshold    int      `yaml:"alert_threshold"`    // YAML: scoring.alert_threshold, default 50 — порог уровня WARN, запись в threat-лог. Потребитель: scorer.Evaluate
	BanThreshold      int      `yaml:"ban_threshold"`      // YAML: scoring.ban_threshold, default 80 — порог уровня THREAT, Fail2Ban банит IP. Потребитель: scorer.Evaluate
	ObservationWindow Duration `yaml:"observation_window"` // YAML: scoring.observation_window, default "300s" — окно накопления очков. Потребитель: scorer.Decay, state.Tracker
	Decay             string   `yaml:"decay"`              // YAML: scoring.decay, default "linear" — алгоритм затухания ("linear"). Потребитель: scorer.Decay
}

// ++++++++++++++++++++++++++ Секция: state ++++++++++++++++++++++++++++++++++++++++++++++

type StateConfig struct {
	GCInterval    Duration `yaml:"gc_interval"`     // YAML: state.gc_interval, default "60s" — интервал запуска сборки мусора. Потребитель: state.GC.Run
	MaxTrackedIPs int      `yaml:"max_tracked_ips"` // YAML: state.max_tracked_ips, default 100000 — лимит IP в памяти (LRU eviction при превышении). Потребитель: state.Tracker
}

// ++++++++++++++++++++++++++ Секция: detectors ++++++++++++++++++++++++++++++++++++++++

type DetectorsConfig struct {
	Probe      ProbeConfig      `yaml:"probe"`
	Bruteforce BruteforceConfig `yaml:"bruteforce"`
	Crawler    CrawlerConfig    `yaml:"crawler"`
	NoAsset    NoAssetConfig    `yaml:"noasset"`
	Rate       RateConfig       `yaml:"rate"`
	UserAgent  UserAgentConfig  `yaml:"useragent"`
	Overflow   OverflowConfig   `yaml:"overflow"`
}

// -------------------------- Probe scanner --------------------------------------------

type ProbeConfig struct {
	Enabled bool     `yaml:"enabled"` // YAML: detectors.probe.enabled, default true — рубильник. Потребитель: detector.Probe
	Score   int      `yaml:"score"`   // YAML: detectors.probe.score, default 25 — очки за каждый probe-запрос. Потребитель: detector.Probe
	Paths   []string `yaml:"paths"`   // YAML: detectors.probe.paths — список чувствительных путей. Потребитель: detector.Probe
}

// -------------------------- Path Bruteforce (404 ratio) ------------------------------

type BruteforceConfig struct {
	Enabled        bool    `yaml:"enabled"`         // YAML: detectors.bruteforce.enabled, default true. Потребитель: detector.Bruteforce
	MinRequests    int     `yaml:"min_requests"`    // YAML: detectors.bruteforce.min_requests, default 10 — минимум запросов для срабатывания. Потребитель: detector.Bruteforce
	RatioThreshold float64 `yaml:"ratio_threshold"` // YAML: detectors.bruteforce.ratio_threshold, default 0.6 — порог доли 404. Потребитель: detector.Bruteforce
	Score          int     `yaml:"score"`           // YAML: detectors.bruteforce.score, default 30. Потребитель: detector.Bruteforce
}

// -------------------------- Sequential Crawler ---------------------------------------

type CrawlerConfig struct {
	Enabled       bool `yaml:"enabled"`        // YAML: detectors.crawler.enabled, default true. Потребитель: detector.Crawler
	MinSequential int  `yaml:"min_sequential"` // YAML: detectors.crawler.min_sequential, default 5 — минимум последовательных URL. Потребитель: detector.Crawler
	Score         int  `yaml:"score"`          // YAML: detectors.crawler.score, default 20. Потребитель: detector.Crawler
}

// -------------------------- No-Asset Bot --------------------------------------------

type NoAssetConfig struct {
	Enabled             bool     `yaml:"enabled"`               // YAML: detectors.noasset.enabled, default true. Потребитель: detector.NoAsset
	MinPageRequests     int      `yaml:"min_page_requests"`     // YAML: detectors.noasset.min_page_requests, default 3. Потребитель: detector.NoAsset
	AssetRatioThreshold float64  `yaml:"asset_ratio_threshold"` // YAML: detectors.noasset.asset_ratio_threshold, default 0.1 — менее 10% ассетов. Потребитель: detector.NoAsset
	AssetExtensions     []string `yaml:"asset_extensions"`      // YAML: detectors.noasset.asset_extensions — расширения статических файлов. Потребитель: detector.NoAsset
	Score               int      `yaml:"score"`                 // YAML: detectors.noasset.score, default 20. Потребитель: detector.NoAsset
}

// -------------------------- Rate Anomaly --------------------------------------------

type RateConfig struct {
	Enabled   bool     `yaml:"enabled"`   // YAML: detectors.rate.enabled, default true. Потребитель: detector.Rate
	Window    Duration `yaml:"window"`    // YAML: detectors.rate.window, default "60s" — окно подсчёта запросов. Потребитель: detector.Rate
	Threshold int      `yaml:"threshold"` // YAML: detectors.rate.threshold, default 100 — запросов за окно для срабатывания. Потребитель: detector.Rate
	Score     int      `yaml:"score"`     // YAML: detectors.rate.score, default 25. Потребитель: detector.Rate
}

// -------------------------- User-Agent Anomaly --------------------------------------

type UserAgentConfig struct {
	Enabled         bool `yaml:"enabled"`          // YAML: detectors.useragent.enabled, default true. Потребитель: detector.UserAgent
	ScannerScore    int  `yaml:"scanner_score"`    // YAML: detectors.useragent.scanner_score, default 40 — сканеры (Nuclei, sqlmap). Потребитель: detector.UserAgent
	GrabberScore    int  `yaml:"grabber_score"`    // YAML: detectors.useragent.grabber_score, default 20 — грабберы/краулеры. Потребитель: detector.UserAgent
	AutomationScore int  `yaml:"automation_score"` // YAML: detectors.useragent.automation_score, default 15 — автоматизация (requests, aiohttp). Потребитель: detector.UserAgent
	EmptyUAScore    int  `yaml:"empty_ua_score"`   // YAML: detectors.useragent.empty_ua_score, default 30 — пустой UA. Потребитель: detector.UserAgent
}

// -------------------------- Overflow / WAF Bypass -----------------------------------

type OverflowConfig struct {
	Enabled          bool     `yaml:"enabled"`           // YAML: detectors.overflow.enabled, default true. Потребитель: detector.Overflow
	MaxURLLength     int      `yaml:"max_url_length"`    // YAML: detectors.overflow.max_url_length, default 2048 — порог длины URL. Потребитель: detector.Overflow
	SuspiciousParams []string `yaml:"suspicious_params"` // YAML: detectors.overflow.suspicious_params — подозрительные query-параметры. Потребитель: detector.Overflow
	Score            int      `yaml:"score"`             // YAML: detectors.overflow.score, default 30. Потребитель: detector.Overflow
}

// ++++++++++++++++++++++++++ Секция: whitelist ++++++++++++++++++++++++++++++++++++++++

type WhitelistConfig struct {
	Bots         []BotConfig          `yaml:"bots"`
	Custom       CustomWhitelistConfig `yaml:"custom"`
	DNSCache     DNSCacheConfig        `yaml:"dns_cache"`
	FakeBotScore int                  `yaml:"fake_bot_score"` // YAML: whitelist.fake_bot_score, default 35 — штраф за UA легитимного бота без подтверждения DNS. Потребитель: whitelist.Verifier
}

// BotConfig — один легитимный бот с UA-паттернами и rDNS-доменами для верификации.
type BotConfig struct {
	Name         string   `yaml:"name"`          // YAML: whitelist.bots[].name — идентификатор (google, bing...). Потребитель: whitelist.Matcher
	UAPatterns   []string `yaml:"ua_patterns"`   // YAML: whitelist.bots[].ua_patterns — подстроки User-Agent. Потребитель: whitelist.Matcher
	RDNSDomains  []string `yaml:"rdns_domains"`  // YAML: whitelist.bots[].rdns_domains — допустимые rDNS-суффиксы. Потребитель: whitelist.Verifier
	VerifyMethod string   `yaml:"verify_method"` // YAML: whitelist.bots[].verify_method — "rdns" | "rdns_ipjson" | "ip_ranges". Потребитель: whitelist.Verifier
}

type CustomWhitelistConfig struct {
	IPs          []string `yaml:"ips"`           // YAML: whitelist.custom.ips — доверенные IP. Потребитель: whitelist.Matcher
	CIDRs        []string `yaml:"cidrs"`         // YAML: whitelist.custom.cidrs — доверенные подсети. Потребитель: whitelist.Matcher
	UASubstrings []string `yaml:"ua_substrings"` // YAML: whitelist.custom.ua_substrings — UA-подстроки для пропуска. Потребитель: whitelist.Matcher
}

type DNSCacheConfig struct {
	PositiveTTL   Duration `yaml:"positive_ttl"`    // YAML: whitelist.dns_cache.positive_ttl, default "24h" — TTL успешной верификации. Потребитель: whitelist.IPCache
	NegativeTTL   Duration `yaml:"negative_ttl"`    // YAML: whitelist.dns_cache.negative_ttl, default "1h" — TTL неуспешной верификации. Потребитель: whitelist.IPCache
	IPListRefresh Duration `yaml:"ip_list_refresh"` // YAML: whitelist.dns_cache.ip_list_refresh, default "24h" — интервал обновления IP-диапазонов ботов. Потребитель: не подключён (v0.2+, ip_ranges refresh)
}

// ++++++++++++++++++++++++++ Секция: output ++++++++++++++++++++++++++++++++++++++++++++

type OutputConfig struct {
	ThreatLog      string `yaml:"threat_log"`      // YAML: output.threat_log, default "/var/log/nginx-sentinel/threats.log" — threat-лог для Fail2Ban. Потребитель: output.Logger
	OperationalLog string `yaml:"operational_log"` // YAML: output.operational_log, default "/var/log/nginx-sentinel/sentinel.log" — operational-лог демона. Потребитель: utils.Init
}

// ========================== Загрузка конфига ==========================================

// LoadConfig читает конфиг из path и накладывает его поверх Go-дефолтов.
//
// Поведение при отсутствии файла:
//   - Файл не найден (os.IsNotExist) → возвращает defaultConfig() без ошибки.
//     Демон работает "из коробки" с разумными дефолтами.
//
// Поведение при наличии файла:
//   - Невалидный YAML → возвращает ошибку.
//   - Частичная секция (например, scoring: без ban_threshold) → неуказанные поля
//     обнулятся (ограничение yaml.v3). config.yaml должен содержать все поля секций.
//
// Вызывается из main.go при старте; повторно при SIGHUP (Task 7.1).
func LoadConfig(path string) (Config, error) {
	cfg := defaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Файл не найден — дефолты достаточны для запуска
			return cfg, nil
		}
		return cfg, fmt.Errorf("чтение конфига %q: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("парсинг конфига %q: %w", path, err)
	}

	if err := validateConfig(&cfg); err != nil {
		return cfg, fmt.Errorf("невалидный конфиг %q: %w", path, err)
	}

	return cfg, nil
}

// validateConfig проверяет критичные поля после yaml.Unmarshal.
// Нулевые пороги могут возникнуть если в config.yaml указана секция scoring:
// с неполными полями (ограничение yaml.v3 partial merge) — защита от silent-misconfiguration.
func validateConfig(cfg *Config) error {
	if cfg.Scoring.AlertThreshold <= 0 {
		return fmt.Errorf("scoring.alert_threshold должен быть > 0, got %d", cfg.Scoring.AlertThreshold)
	}
	if cfg.Scoring.BanThreshold <= 0 {
		return fmt.Errorf("scoring.ban_threshold должен быть > 0, got %d", cfg.Scoring.BanThreshold)
	}
	if cfg.Scoring.BanThreshold <= cfg.Scoring.AlertThreshold {
		return fmt.Errorf("scoring.ban_threshold (%d) должен быть > alert_threshold (%d)",
			cfg.Scoring.BanThreshold, cfg.Scoring.AlertThreshold)
	}
	if time.Duration(cfg.Scoring.ObservationWindow) <= 0 {
		return fmt.Errorf("scoring.observation_window должен быть > 0")
	}
	if cfg.State.MaxTrackedIPs <= 0 {
		return fmt.Errorf("state.max_tracked_ips должен быть > 0, got %d", cfg.State.MaxTrackedIPs)
	}
	return nil
}

// ========================== Дефолты ==================================================

// defaultConfig возвращает Config со всеми дефолтами.
// Служит базой: yaml.Unmarshal накладывает только те секции, которые есть в файле.
// Отсутствующие секции (например, нет `state:`) сохраняют значения из этой функции.
func defaultConfig() Config {
	return Config{
		General: GeneralConfig{
			LogFile:           "/var/log/nginx/access.log",
			PIDFile:           "/var/run/nginx-sentinel.pid",
			LinesBufSize:      1000,
			TailRetryInterval: Duration(5 * time.Second),
		},
		Logging: LoggingConfig{
			Debug:        false,
			ConsoleColor: true,
		},
		Parser: ParserConfig{
			LogFormat: "combined",
			Timezone:  "UTC",
		},
		Scoring: ScoringConfig{
			AlertThreshold:    50,
			BanThreshold:      80,
			ObservationWindow: Duration(300 * time.Second),
			Decay:             "linear",
		},
		State: StateConfig{
			GCInterval:    Duration(60 * time.Second),
			MaxTrackedIPs: 100000,
		},
		Detectors: DetectorsConfig{
			Probe: ProbeConfig{
				Enabled: true,
				Score:   25,
				Paths:   defaultProbePaths(),
			},
			Bruteforce: BruteforceConfig{
				Enabled:        true,
				MinRequests:    10,
				RatioThreshold: 0.6,
				Score:          30,
			},
			Crawler: CrawlerConfig{
				Enabled:       true,
				MinSequential: 5,
				Score:         20,
			},
			NoAsset: NoAssetConfig{
				Enabled:             true,
				MinPageRequests:     3,
				AssetRatioThreshold: 0.1,
				AssetExtensions:     []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico", ".webp"},
				Score:               20,
			},
			Rate: RateConfig{
				Enabled:   true,
				Window:    Duration(60 * time.Second),
				Threshold: 100,
				Score:     25,
			},
			UserAgent: UserAgentConfig{
				Enabled:         true,
				ScannerScore:    40,
				GrabberScore:    20,
				AutomationScore: 15,
				EmptyUAScore:    30,
			},
			Overflow: OverflowConfig{
				Enabled:          true,
				MaxURLLength:     2048,
				SuspiciousParams: []string{"bypass", "shell", "cmd", "exec", "eval", "system", "passthru"},
				Score:            30,
			},
		},
		Whitelist: WhitelistConfig{
			Bots:         defaultBots(),
			Custom:       CustomWhitelistConfig{},
			FakeBotScore: 35,
			DNSCache: DNSCacheConfig{
				PositiveTTL:   Duration(24 * time.Hour),
				NegativeTTL:   Duration(time.Hour),
				IPListRefresh: Duration(24 * time.Hour),
			},
		},
		Output: OutputConfig{
			ThreatLog:      "/var/log/nginx-sentinel/threats.log",
			OperationalLog: "/var/log/nginx-sentinel/sentinel.log",
		},
	}
}

// defaultProbePaths — список чувствительных путей для детектора probe.
// Охватывает: конфиги, VCS, облачные credentials, CMS, бэкапы, инфраструктуру, debug.
// Вынесен отдельно чтобы не загромождать defaultConfig().
func defaultProbePaths() []string {
	return []string{
		// Конфигурационные файлы приложений
		"/.env", "/.env.backup", "/.env.local", "/.env.production", "/.env.staging",
		"/config.yml", "/config.yaml", "/config.json", "/application.properties",
		"/settings.py", "/local_settings.py", "/database.yml", "/database.yaml",
		"/web.config", "/app.config",

		// Git / VCS
		"/.git/config", "/.git/HEAD", "/.gitignore",
		"/.svn/entries", "/.hg/", "/.bzr/",

		// Облачные credentials
		"/.aws/credentials", "/.docker/config.json",
		"/aws-exports.json", "/.gcloud/credentials",

		// CMS: WordPress
		"/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
		"/wp-login.php", "/xmlrpc.php", "/wp-admin/",

		// CMS: общие
		"/administrator/", "/admin/", "/phpmyadmin/", "/pma/",
		"/joomla/", "/drupal/", "/typo3/",

		// Backup файлы
		"/backup.zip", "/backup.tar.gz", "/backup.sql", "/backup.sql.gz",
		"/db.dump", "/database.sql", "/dump.sql", "/site.sql",

		// Инфраструктура и мониторинг
		"/server-status", "/server-info",
		"/phpinfo.php", "/info.php", "/php.php",
		"/actuator/", "/actuator/env", "/actuator/health", "/actuator/mappings",
		"/metrics", "/health", "/.well-known/",

		// Debug / API endpoints
		"/.debug", "/trace", "/console",
		"/graphql", "/graphiql", "/api/graphql",
	}
}

// defaultBots — список легитимных поисковых ботов из spec раздел 4.2.
// Каждый бот верифицируется по UA-паттерну + rDNS + (опционально) fDNS или IP-ranges.
func defaultBots() []BotConfig {
	return []BotConfig{
		{
			Name:         "google",
			UAPatterns:   []string{"Googlebot", "Google-InspectionTool", "GoogleOther", "AdsBot-Google"},
			RDNSDomains:  []string{".googlebot.com", ".google.com"},
			VerifyMethod: "rdns_ipjson",
		},
		{
			Name:         "bing",
			UAPatterns:   []string{"bingbot", "BingPreview", "msnbot", "adidxbot"},
			RDNSDomains:  []string{".search.msn.com"},
			VerifyMethod: "rdns",
		},
		{
			Name:         "yandex",
			UAPatterns:   []string{"YandexBot", "YandexImages", "YandexMetrika", "YandexDirect"},
			RDNSDomains:  []string{".yandex.ru", ".yandex.net", ".yandex.com"},
			VerifyMethod: "rdns",
		},
		{
			Name:         "duckduckgo",
			UAPatterns:   []string{"DuckDuckBot"},
			RDNSDomains:  []string{".duckduckgo.com"},
			VerifyMethod: "rdns",
		},
		{
			Name:         "baidu",
			UAPatterns:   []string{"Baiduspider", "BaiduMobaider"},
			RDNSDomains:  []string{".baidu.com", ".baidu.jp"},
			VerifyMethod: "rdns",
		},
		{
			Name:         "apple",
			UAPatterns:   []string{"Applebot"},
			RDNSDomains:  []string{".applebot.apple.com"},
			VerifyMethod: "rdns",
		},
		{
			Name:         "facebook",
			UAPatterns:   []string{"facebookexternalhit", "Facebot"},
			RDNSDomains:  []string{},
			VerifyMethod: "ip_ranges",
		},
		{
			Name:         "twitter",
			UAPatterns:   []string{"Twitterbot"},
			RDNSDomains:  []string{},
			VerifyMethod: "ip_ranges",
		},
		{
			Name:         "telegram",
			UAPatterns:   []string{"TelegramBot"},
			RDNSDomains:  []string{},
			VerifyMethod: "ip_ranges",
		},
		{
			Name:         "gptbot",
			UAPatterns:   []string{"GPTBot"},
			RDNSDomains:  []string{".openai.com"},
			VerifyMethod: "rdns",
		},
		{
			Name:         "claudebot",
			UAPatterns:   []string{"ClaudeBot", "Claude-Web", "anthropic-ai"},
			RDNSDomains:  []string{".anthropic.com"},
			VerifyMethod: "rdns",
		},
	}
}
