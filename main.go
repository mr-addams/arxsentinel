// ========================== Точка входа — nginx-sentinel ================================
//   Инициализация компонентов, сборка pipeline, запуск демона.
//
//   ЧТО ЗДЕСЬ:
//     - main() — загрузка конфига, инициализация логгера, [STARTUP] в консоль
//     - Будущее (Task 1.4): запуск tail reader и pipeline
//
//   ЧТО НЕ ЗДЕСЬ:
//     - Бизнес-логика (core/)
//     - Конфигурационные структуры (sys/config)
//     - Логирование (sys/utils)

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
	"github.com/mr-addams/nginx-sentinel/internal/sys/utils"
)

// configPath — путь к конфигу по умолчанию.
// Переопределяется через переменную окружения NGINX_SENTINEL_CONFIG.
// hardcoded: путь привязан к структуре проекта и install-скрипту (Task 7.4).
const configPath = "./config.yaml"

func main() {
	// ── Загрузка конфига ──────────────────────────────────────────────────────────────

	path := configPath
	if env := os.Getenv("NGINX_SENTINEL_CONFIG"); env != "" {
		path = env
	}

	cfg, err := config.LoadConfig(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nginx-sentinel: ошибка конфига: %v\n", err)
		os.Exit(1)
	}

	// ── Инициализация логгера ─────────────────────────────────────────────────────────

	if err := utils.Init(cfg.Logging.Debug, cfg.Logging.ConsoleColor,
		cfg.Output.OperationalLog, cfg.Output.ThreatLog); err != nil {
		// Threat log недоступен — без него Fail2Ban не работает, стартовать нельзя
		fmt.Fprintf(os.Stderr, "nginx-sentinel: ошибка инициализации логгера: %v\n", err)
		os.Exit(1)
	}
	defer utils.Close()

	// ── Стартовые сообщения ───────────────────────────────────────────────────────────

	utils.Log("STARTUP", "nginx-sentinel v0.1 запуск", "info")
	utils.Log("CONFIG", fmt.Sprintf("alert=%d ban=%d window=%v debug=%v",
		cfg.Scoring.AlertThreshold,
		cfg.Scoring.BanThreshold,
		time.Duration(cfg.Scoring.ObservationWindow),
		cfg.Logging.Debug,
	), "info")
	utils.Log("CONFIG", fmt.Sprintf("лог: %s", cfg.General.LogFile), "info")
	utils.Log("STARTUP", "компоненты готовы (tail reader — Task 1.4)", "info")

	// Заглушка Flow #1 — pipeline (tail → parser → detector → scorer) собирается в Task 1.4.
	// После Task 1.4 здесь будут: запуск TailReader, горутин обработки, ожидание SIGTERM.
}
