// ========================== Точка входа — nginx-sentinel ================================
//   Инициализация компонентов, сборка pipeline, запуск демона.
//
//   ЧТО ЗДЕСЬ:
//     - main() — загрузка конфига, инициализация логгера, запуск pipeline
//     - Pipeline Task 1.4: TailReader → parser.Parse → [PARSER] лог в консоль
//     - Базовый shutdown по SIGTERM/SIGINT (полный graceful shutdown — Task 7.2)
//
//   ЧТО НЕ ЗДЕСЬ:
//     - Бизнес-логика (core/)
//     - Конфигурационные структуры (sys/config)
//     - Логирование (sys/utils)

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
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

	// ── Context + shutdown ────────────────────────────────────────────────────────────

	// Полный graceful shutdown (flush буферов, drain канала) — Task 7.2.
	// Сейчас: останавливаем горутины по сигналу через ctx.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// ── Pipeline: TailReader → parser ─────────────────────────────────────────────────

	lines := make(chan string, cfg.General.LinesBufSize)
	tail := utils.NewTailReader(cfg.General.LogFile, lines, time.Duration(cfg.General.TailRetryInterval))
	go tail.Run(ctx)

	utils.Log("STARTUP", fmt.Sprintf("pipeline запущен (tail → parser) | файл: %s", cfg.General.LogFile), "info")

	// ── Основной цикл обработки ───────────────────────────────────────────────────────

	// Обрабатываем строки из TailReader.
	// Task 1.4: парсим и логируем в консоль — демонстрация работы pipeline.
	// Следующие задачи (Flow #2–4): добавят detector, scorer, threat-лог.
	for {
		select {
		case <-ctx.Done():
			utils.Log("SHUTDOWN", "сигнал получен, завершение", "info")
			return
		case line, ok := <-lines:
			if !ok {
				utils.Log("SHUTDOWN", "канал закрыт, завершение", "info")
				return
			}
			entry, ok := parser.Parse(line)
			if !ok {
				// Битые строки (бинарный мусор, нестандартный формат) — пропускаем без паники.
				// Логируем только в debug-режиме — в продакшне таких строк мало, но они есть.
				utils.Log("PARSER", fmt.Sprintf("пропуск битой строки: %.80s", line), "debug")
				continue
			}
			utils.Log("PARSER", fmt.Sprintf("%s %s %s %d",
				entry.RealIP, entry.Method, entry.Path, entry.Status,
			), "debug")
		}
	}
}
