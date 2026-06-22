// ========================== Runtime adapter — config → StreamSpec ========================
//   Этот файл — мост между Product-конфигом (config.Config) и runtime-контрактом
//   (StreamSpec / PipelineSpec). Здесь НЕТ security-логики — только построение
//   аргументов runtime.Run из YAML-конфига.
//
//   ЧТО ЗДЕСЬ:
//     - adaptConfigToStreams() — построить []runtime.StreamSpec (по одному на стрим)
//       + []chan struct{} (reload-каналы для SIGHUP-fanout, индексы = cfg.Streams).
//
//   СВЯЗЬ С DECISIONS.md:
//     - Sources/Sinks строятся здесь через buildSources/buildSinks и кладутся
//       в PipelineSpec.Sources/Sinks — engine их не строит (DECISION Q2).
//     - Detectors НЕ кладутся в PipelineSpec — они передаются через замыкание
//       factory.Build (Q1: scorer→Product).
//     - ShutdownTimeout = 5s по умолчанию; конфиг-поля пока нет (Phase 4+).

package main

import (
	"context"
	"fmt"
	"time"

	coreruntime "github.com/mr-addams/arx-core/pkg/runtime"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// ++++++++++++++++++++++++++ adaptConfigToStreams ++++++++++++++++++++++++++++++++++++++++++

// adaptConfigToStreams строит один runtime.StreamSpec на каждый cfg.Streams[i].
// Возвращает:
//
//	streams    — слайс готовых к runtime.Run спецификаций;
//	reloadChs  — слайс SIGHUP-каналов, индексы соответствуют cfg.Streams (main.go
//	             подменяет существующие reloadChs на возвращённые — SIGHUP-fanout
//	             пробрасывается в engine через factory.Reload).
//
// На ошибке построения sources/sinks — возвращается частичный результат + ошибка;
// engine ещё не стартовал, ошибка fatal в main.go.
//
// ctx — app context для buildSinks (sink.Reload открывает файлы).
func adaptConfigToStreams(ctx context.Context, cfg config.Config) ([]coreruntime.StreamSpec, []chan struct{}, error) {
	streams := make([]coreruntime.StreamSpec, 0, len(cfg.Streams))
	reloadChs := make([]chan struct{}, 0, len(cfg.Streams))

	for _, streamCfg := range cfg.Streams {
		// PipelineSpec'ы для одного стрима.
		pipelines := make([]coreruntime.PipelineSpec, 0, len(streamCfg.Pipelines))
		for j, pipeCfg := range streamCfg.Pipelines {
			// Sources/Sinks строятся здесь (а не в factory) — engine не знает
			// о config-домене Product'а.
			sources, err := buildSources(cfg, pipeCfg.Inputs)
			if err != nil {
				return nil, nil, fmt.Errorf("stream %q pipeline %d sources: %w", streamCfg.Name, j, err)
			}
			sinks, err := buildSinks(ctx, pipeCfg.Outputs)
			if err != nil {
				return nil, nil, fmt.Errorf("stream %q pipeline %d sinks: %w", streamCfg.Name, j, err)
			}

			pipelines = append(pipelines, coreruntime.PipelineSpec{
				Name:    pipeCfg.Name,
				Idx:     j,
				Sources: sources,
				Sinks:   sinks,
			})
		}

		// BufferSize: per-pipeline override → дефолт stream'а → engine fallback (1000).
		// Адаптер берёт первый pipeline override; если 0 — engine применит defaultBufferSize.
		bufSize := int(cfg.Pipeline.BufferSize)
		if len(streamCfg.Pipelines) > 0 && streamCfg.Pipelines[0].Pipeline.BufferSize > 0 {
			bufSize = int(streamCfg.Pipelines[0].Pipeline.BufferSize)
		}

		// TrackerGroup: берём resolver из первой pipeline (для логов engine).
		// Сам runtime не использует это поле — оставлено для совместимости с
		// оригинальной конфигурацией pool'а; engine игнорирует (DECISIONS.md).
		tg := ""
		if len(streamCfg.Pipelines) > 0 {
			tg = resolveTrackerGroup(streamCfg.Pipelines[0])
		}

		streams = append(streams, coreruntime.StreamSpec{
			Name:            streamCfg.Name,
			TrackerGroup:    tg,
			BufferSize:      bufSize,
			ShutdownTimeout: 5 * time.Second, // no cfg field yet; engine honors non-zero
			StatsInterval:   time.Duration(cfg.General.StatsInterval),
			Pipelines:       pipelines,
		})

		reloadChs = append(reloadChs, make(chan struct{}, 1))
	}

	return streams, reloadChs, nil
}
