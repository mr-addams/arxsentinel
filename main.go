// ========================== Точка входа — nginx-sentinel ================================
//   Инициализация компонентов, сборка pipeline, запуск демона.
//
//   ЧТО ЗДЕСЬ:
//     - main() — загрузка конфига, инициализация логгера, запуск pipeline
//     - Pipeline Flow #4: TailReader → whitelist check → tracker → scorer(detectors) → logger
//     - buildDetectors() — сборка активных детекторов из конфига
//     - processLine() — обработка одной строки лога
//     - writePID() / removePID() — управление PID-файлом демона
//     - GC горутина: периодическая очистка неактивных IP
//     - Graceful shutdown: drain буфера + Sync перед Close (Task 7.2)
//
//   ЧТО НЕ ЗДЕСЬ:
//     - Бизнес-логика (core/)
//     - Конфигурационные структуры (sys/config)
//     - Логирование (sys/utils)
//
//   АРХИТЕКТУРА PIPELINE (Flow #4–6):
//     TailReader → lines chan → whitelist.Matcher (custom IP/UA → early return)
//              ↓
//     whitelist.Verifier (bot UA → rDNS/fDNS → verified → return | isFakeBot → +score)
//              ↓
//     tracker.Update(*IPState)
//              ↓
//     scorer.Evaluate(state, entry, detectors=[probe, rate, ua, bruteforce, crawler, noasset, overflow])
//              ↓ [level≠""]
//     threatLogger.Log
//
//   Изменение (Flow #4, Tasks 4.0–4.3):
//     Добавлена whitelist-интеграция (Matcher, IPCache, Verifier).
//     Подключены три детектора: probe, rate, ua.
//     processLine расширен: early-exit по whitelist, fake bot penalty перед scorer.
//   Изменение (Flow #6, Tasks 6.1–6.4):
//     Подключены четыре детектора: bruteforce, crawler, noasset, overflow.
//   Изменение (Flow #5, Task 5.3):
//     Добавлено управление PID-файлом: writePID после utils.Init, defer removePID.

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mr-addams/nginx-sentinel/internal/core/detector"
	"github.com/mr-addams/nginx-sentinel/internal/core/output"
	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/core/scorer"
	"github.com/mr-addams/nginx-sentinel/internal/core/state"
	"github.com/mr-addams/nginx-sentinel/internal/core/whitelist"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
	"github.com/mr-addams/nginx-sentinel/internal/sys/utils"
)

// processedCount / threatCount — атомарные счётчики для горутины статистики (Task 7.3).
// Package-level: processLine и ThreatLogger writeFn находятся в том же пакете.
var (
	processedCount atomic.Int64
	threatCount    atomic.Int64
)

// configPath — путь к конфигу по умолчанию.
// Абсолютный путь: при запуске через systemd WorkingDirectory=/ относительный "./config.yaml"
// не найдётся. Совпадает с путём из install.sh.
// Переопределяется через переменную окружения NGINX_SENTINEL_CONFIG.
const configPath = "/etc/nginx-sentinel/config.yaml"

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

	// PID-файл нужен для: kill -HUP $(cat pid) и logrotate postrotate (Task 7.1).
	// Ошибка записи — warn, не fatal: демон работает без PID-файла, просто теряем удобство управления.
	if err := writePID(cfg.General.PIDFile); err != nil {
		utils.Log("STARTUP", fmt.Sprintf("не удалось записать PID-файл %s: %v", cfg.General.PIDFile, err), "warn")
	} else {
		defer removePID(cfg.General.PIDFile)
	}

	// ── Стартовые сообщения ───────────────────────────────────────────────────────────

	utils.Log("STARTUP", "nginx-sentinel v0.1 запуск", "info")
	utils.Log("CONFIG", fmt.Sprintf("alert=%d ban=%d window=%v debug=%v",
		cfg.Scoring.AlertThreshold,
		cfg.Scoring.BanThreshold,
		time.Duration(cfg.Scoring.ObservationWindow),
		cfg.Logging.Debug,
	), "info")
	utils.Log("CONFIG", fmt.Sprintf("лог: %s", cfg.General.LogFile), "info")

	// ── Инициализация компонентов pipeline ────────────────────────────────────────────

	// tracker — in-memory состояние по IP (Tasks 2.1 + 2.2)
	tracker := state.NewTracker(cfg, utils.Log)

	// whitelist: Matcher (UA/IP lookup), IPCache (DNS-результаты), Verifier (rDNS+fDNS)
	// IPCache создаётся отдельно — при SIGHUP (Task 7.1) кэш переживает reload конфига.
	ipCache := whitelist.NewIPCache(cfg.Whitelist.DNSCache)
	matcher, err := whitelist.NewMatcher(cfg.Whitelist)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nginx-sentinel: ошибка инициализации whitelist: %v\n", err)
		os.Exit(1)
	}
	resolver := &net.Resolver{PreferGo: true}
	verifier := whitelist.NewVerifier(ipCache, resolver, utils.Log)

	// scorer — агрегатор очков от детекторов (Task 2.3 + Flow #4)
	sc := scorer.NewScorer(cfg.Scoring, buildDetectors(cfg), utils.Log)

	// threatLogger — запись WARN/THREAT в threats.log (Task 2.4).
	// Closure вокруг utils.LogThreat: инкрементирует threatCount для горутины статистики.
	threatLogger := output.NewThreatLogger(func(ip string, score int, level string, modules []string, reason string) {
		if level == "THREAT" {
			threatCount.Add(1)
		}
		utils.LogThreat(ip, score, level, modules, reason)
	})

	// ── Context + shutdown ────────────────────────────────────────────────────────────

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// ── SIGHUP reload ─────────────────────────────────────────────────────────────────
	// Горутина конвертирует os.Signal → struct{} в небуферизованный канал размером 1.
	// Если предыдущий reload ещё не обработан — пропускаем (select default).
	// Главный loop читает reloadCh между строками — нет concurrent access в processLine.
	sigHUP := make(chan os.Signal, 1)
	signal.Notify(sigHUP, syscall.SIGHUP)
	defer signal.Stop(sigHUP)
	reloadCh := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigHUP:
				select {
				case reloadCh <- struct{}{}:
				default:
				}
			}
		}
	}()

	// ── GC горутина ───────────────────────────────────────────────────────────────────
	go tracker.RunGC(ctx, time.Duration(cfg.State.GCInterval))

	// ── Горутина статистики (Task 7.3) ────────────────────────────────────────────────
	// Период = general.stats_interval (дефолт 300s) — независим от scoring.observation_window.
	// Горутина стартует один раз; изменение stats_interval через SIGHUP требует перезапуска.
	// processedCount/threatCount — атомики, нет гонок с pipeline горутиной.
	// tracker.GetStats() итерирует под RLock — не вызывать из hot path.
	go func() {
		ticker := time.NewTicker(time.Duration(cfg.General.StatsInterval))
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				st := tracker.GetStats()
				utils.Log("STATS", fmt.Sprintf(
					"processed=%d tracked=%d threats=%d suspicious=%d",
					processedCount.Load(), st.TrackedIPs,
					threatCount.Load(), st.Suspicious,
				), "info")
			}
		}
	}()

	// ── Pipeline: TailReader → parser ─────────────────────────────────────────────────

	lines := make(chan string, cfg.General.LinesBufSize)
	tail := utils.NewTailReader(cfg.General.LogFile, lines, time.Duration(cfg.General.TailRetryInterval))
	go tail.Run(ctx)

	utils.Log("STARTUP", fmt.Sprintf(
		"pipeline запущен (tail → whitelist → tracker → scorer[probe,rate,ua,bruteforce,crawler,noasset,overflow]) | файл: %s",
		cfg.General.LogFile,
	), "info")

	// ── Основной цикл обработки ───────────────────────────────────────────────────────

	for {
		select {
		case <-ctx.Done():
			utils.Log("SHUTDOWN", "сигнал получен, обработка буфера...", "info")
			// TailReader завершает работу по тому же ctx и закрывает канал через defer.
			// Ждём !ok — это гарантирует что TailReader дозаписал все строки перед выходом.
			// TailReader использует неблокирующий select при отправке — дедлок невозможен.
			// context.Background() вместо ctx: ctx уже отменён, поэтому verifyCtx
			// (context.WithTimeout(ctx,...)) был бы немедленно отменён → все боты
			// получали бы isFakeBot=true → ложные бан-записи в threats.log при shutdown.
		drainLoop:
			for {
				line, ok := <-lines
				if !ok {
					break drainLoop
				}
				processLine(context.Background(), line, tracker, sc, threatLogger, matcher, verifier, cfg.Whitelist.FakeBotScore, time.Duration(cfg.Whitelist.DNSVerifyTimeout))
			}
			utils.Log("SHUTDOWN", "завершение", "info")
			return

		case <-reloadCh:
			newCfg, err := config.LoadConfig(path)
			if err != nil {
				utils.Log("CONFIG", "SIGHUP: ошибка перезагрузки конфига: "+err.Error(), "warn")
				continue
			}
			// Подготавливаем все компоненты до применения — если один не готов, остальные не меняем.
			// Partial apply (cfg обновлён, matcher нет) создаёт молчаливое расхождение:
			// scorer использует пороги нового конфига, matcher — старый whitelist.
			newMatcher, err := whitelist.NewMatcher(newCfg.Whitelist)
			if err != nil {
				utils.Log("CONFIG", "SIGHUP: ошибка перезагрузки whitelist, reload отменён: "+err.Error(), "warn")
				continue
			}
			// Атомарное применение: все компоненты готовы.
			// ОГРАНИЧЕНИЕ: ipCache (TTL настройки) не обновляется при SIGHUP — кэш
			// переживает reload намеренно (сброс кэша → DNS-нагрузка на весь трафик ботов).
			// Изменение dns_cache.positive_ttl/negative_ttl вступает в силу только при перезапуске.
			cfg = newCfg
			tracker.Reconfigure(cfg)
			sc = scorer.NewScorer(cfg.Scoring, buildDetectors(cfg), utils.Log)
			matcher = newMatcher
			if err := utils.Reload(cfg.Logging.Debug, cfg.Logging.ConsoleColor,
				cfg.Output.OperationalLog, cfg.Output.ThreatLog); err != nil {
				utils.Log("CONFIG", "SIGHUP: ошибка перезагрузки логгера: "+err.Error(), "warn")
			}
			utils.Log("CONFIG", "SIGHUP: конфиг перезагружен", "info")

		case line, ok := <-lines:
			if !ok {
				utils.Log("SHUTDOWN", "канал закрыт, завершение", "info")
				return
			}
			processLine(ctx, line, tracker, sc, threatLogger, matcher, verifier, cfg.Whitelist.FakeBotScore, time.Duration(cfg.Whitelist.DNSVerifyTimeout))
		}
	}
}

// buildDetectors собирает список активных детекторов из конфига.
//
// Только включённые детекторы (Enabled=true) добавляются в список.
// Flow #4 MVP: probe, rate, ua.
// Flow #6: bruteforce, crawler, noasset, overflow.
func buildDetectors(cfg config.Config) []detector.Detector {
	var detectors []detector.Detector

	// Probe: запросы к .env, .git, wp-config и т.д. — Task 4.1
	if cfg.Detectors.Probe.Enabled {
		detectors = append(detectors, detector.NewProbeDetector(cfg.Detectors.Probe))
	}

	// Rate: всплеск запросов за окно — Task 4.2
	if cfg.Detectors.Rate.Enabled {
		detectors = append(detectors, detector.NewRateDetector(cfg.Detectors.Rate))
	}

	// UserAgent: сканеры, грабберы, автоматизация, пустой UA — Task 4.3
	if cfg.Detectors.UserAgent.Enabled {
		detectors = append(detectors, detector.NewUADetector(cfg.Detectors.UserAgent))
	}

	// Bruteforce: аномальный % 404 — Task 6.1
	if cfg.Detectors.Bruteforce.Enabled {
		detectors = append(detectors, detector.NewBruteforceDetector(cfg.Detectors.Bruteforce))
	}

	// Crawler: последовательный числовой обход URL — Task 6.2
	if cfg.Detectors.Crawler.Enabled {
		detectors = append(detectors, detector.NewCrawlerDetector(cfg.Detectors.Crawler))
	}

	// NoAsset: страницы без статики — Task 6.3
	if cfg.Detectors.NoAsset.Enabled {
		detectors = append(detectors, detector.NewNoAssetDetector(cfg.Detectors.NoAsset))
	}

	// Overflow: аномальная длина URL / WAF bypass — Task 6.4
	if cfg.Detectors.Overflow.Enabled {
		detectors = append(detectors, detector.NewOverflowDetector(cfg.Detectors.Overflow))
	}

	utils.Log("CONFIG", fmt.Sprintf(
		"детекторы: %d активных (probe=%v rate=%v ua=%v bruteforce=%v crawler=%v noasset=%v overflow=%v)",
		len(detectors),
		cfg.Detectors.Probe.Enabled,
		cfg.Detectors.Rate.Enabled,
		cfg.Detectors.UserAgent.Enabled,
		cfg.Detectors.Bruteforce.Enabled,
		cfg.Detectors.Crawler.Enabled,
		cfg.Detectors.NoAsset.Enabled,
		cfg.Detectors.Overflow.Enabled,
	), "info")

	return detectors
}

// ========================== PID file ====================================================

// writePID записывает PID текущего процесса в файл.
// Используется для: kill -HUP $(cat pid) и logrotate postrotate (Task 7.1).
// При ошибке — вызывающий логирует warn и продолжает работу: PID не критичен.
func writePID(path string) error {
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644)
}

// removePID удаляет PID-файл при завершении демона.
// Вызывается через defer — срабатывает при любом return из main, включая SIGTERM.
// Ошибка при удалении намеренно игнорируется: файл мог быть удалён вручную оператором.
func removePID(path string) {
	_ = os.Remove(path)
}

// processLine обрабатывает одну строку лога:
//   парсинг → whitelist early-exit → трекинг → fake bot penalty → скоринг → лог угрозы.
//
// АРХИТЕКТУРА WHITELIST EARLY-EXIT:
//   Шаг 1 — custom whitelist (IP/CIDR/UA)? → return (не трекать внутренний трафик)
//   Шаг 2 — UA совпал с паттерном бота? → rDNS/fDNS верификация (кэшируется в IPCache)
//   Шаг 3 — verified бот → return (легитимный, не трекать)
//   Шаг 4 — fake bot → tracker.Update + добавить FakeBotScore ДО scorer.Evaluate
//
// KNOWN LIMITATION (Task 7.x): Verify делает DNS-запрос синхронно в pipeline-горутине.
// При cache miss один запрос блокирует обработку канала lines на DNS round-trip (~200ms).
// Смягчение: IPCache кэширует результат — DNS делается только при первом обращении IP.
// При целенаправленной атаке с ботовым UA и множеством уникальных IP возможна задержка.
// Максимальное ожидание ограничено dnsVerifyTimeout (конфиг whitelist.dns_verify_timeout, дефолт 2s). При timeout → isFakeBot=true.
//
// Изменение (Flow #4, Task 4.0): добавлена whitelist-интеграция и fake bot penalty.
func processLine(
	ctx context.Context,
	line string,
	tracker *state.Tracker,
	sc *scorer.Scorer,
	threatLogger *output.ThreatLogger,
	matcher *whitelist.Matcher,
	verifier *whitelist.Verifier,
	fakeBotScore int,
	dnsVerifyTimeout time.Duration,
) {
	entry, ok := parser.Parse(line)
	if !ok {
		utils.Log("PARSER", fmt.Sprintf("пропуск битой строки: %.80s", line), "debug")
		return
	}
	// Считаем только успешно распарсенные строки — bitые записи не учитываются.
	processedCount.Add(1)

	utils.Log("PARSER", fmt.Sprintf("%s %s %s %d",
		entry.RealIP, entry.Method, entry.Path, entry.Status,
	), "debug")

	// ── Шаг 1: custom whitelist early-exit ───────────────────────────────────────────
	// Custom whitelist проверяется до tracker.Update — whitelisted трафик не попадает
	// в state, что снижает нагрузку на GC и не искажает статистику детекторов.
	if matcher.IsWhitelistedIP(entry.RealIP) || matcher.IsWhitelistedUA(entry.UserAgent) {
		utils.Log("WHITELIST", "пропуск по custom whitelist: "+entry.RealIP, "debug")
		return
	}

	// ── Шаг 2–3: детекция и верификация ботов ────────────────────────────────────────
	// MatchBot быстрый (strings.Contains по slice). Verify кэширует результат —
	// DNS-запрос делается только при первом обращении нового IP с bot-UA.
	// verifyCtx с timeout: ограничиваем блокировку pipeline (см. KNOWN LIMITATION выше).
	isFakeBot := false
	if _, botCfg, matched := matcher.MatchBot(entry.UserAgent); matched {
		verifyCtx, cancelVerify := context.WithTimeout(ctx, dnsVerifyTimeout)
		verified, fake := verifier.Verify(verifyCtx, entry.RealIP, botCfg)
		cancelVerify()
		if verified {
			// Легитимный бот подтверждён по rDNS/fDNS — не трекать, не скорить
			utils.Log("WHITELIST", "пропуск: верифицированный бот "+entry.RealIP, "debug")
			return
		}
		isFakeBot = fake
	}

	// ── Шаг 4: трекинг состояния IP ───────────────────────────────────────────────────
	// Вызывается после whitelist-проверок — в state попадают только подозрительные IP.
	ipState := tracker.Update(entry)

	// ── Шаг 4b: штраф за фейкового бота ─────────────────────────────────────────────
	// FakeBotScore добавляется к накопленному score ДО Evaluate.
	//
	// Timestamp = time.Now(): scorer.Evaluate получит elapsed≈0 → decay≈0% → штраф
	// передаётся полностью. Погрешность: prev не decayed в этом цикле Evaluate,
	// но elapsed между строками одного активного IP — секунды при window=300s (<1% ошибка).
	// Следующий Evaluate корректно decays весь score от этого timestamp.
	//
	// Альтернатива — ручной decay prev до SetScore — дублирует логику scorer.applyDecay
	// и требует передачи window в processLine. Отложено до Task 7.x (scorer refactor).
	if isFakeBot {
		ipState.SetScore(ipState.GetScore()+fakeBotScore, time.Now())
		utils.Log("WHITELIST", fmt.Sprintf("фейковый бот %s +%d (fake bot score)", entry.RealIP, fakeBotScore), "warn")
	}

	// ── Скоринг → лог угрозы ─────────────────────────────────────────────────────────
	// Evaluate: decay накопленного score + запуск детекторов + вынесение вердикта.
	// Возвращённый *IPState реализует detector.ScoreAccess.
	level, score, modules, reason := sc.Evaluate(ipState, entry)

	// Пишем в threat-лог только при WARN или THREAT
	threatLogger.Log(entry.RealIP, score, level, modules, reason)
}
