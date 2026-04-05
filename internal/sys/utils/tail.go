// ========================== Модуль utils/tail ==========================================
//   Tail-reader для чтения access.log в режиме tail -f с поддержкой logrotate.
//   Использует fsnotify (inotify) для отслеживания ротации файла.
//
//   ЧТО ЗДЕСЬ:
//     - TailReader — чтение с позиции EOF, выдача новых строк через канал
//     - Обработка logrotate mv-метода: RENAME → ожидание CREATE → переоткрытие
//     - Обработка copytruncate: детекция pos > size → seek(0)
//
//   ЧТО НЕ ЗДЕСЬ:
//     - Парсинг строк (core/parser)
//     - Бизнес-логика (core/)
//
//   АРХИТЕКТУРА (Run):
//     Старт      → waitForFile (seek EOF) → watcher(dir + file)
//     WRITE      → [copytruncate?] → readAvailableLines
//     RENAME/RM  → дочитать хвост → close → f = nil
//     CREATE     → open new file → read from start
//     ctx.Done() → close fd → return

package utils

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ========================== TailReader ================================================

// TailReader читает файл в режиме tail -f, отправляет новые строки в канал lines.
// Поддерживает два метода logrotate:
//   - mv + postrotate (RENAME): файл переименовывается, nginx создаёт новый
//   - copytruncate: файл усекается на месте, позиция уходит за новый EOF
//
// Жизненный цикл переменной f внутри Run:
//   открыт на EOF  → читает WRITE-события  → закрыт при RENAME
//   nil            → ожидание нового файла после ротации (f == nil — нормально)
//   переоткрыт     → после CREATE нового файла
type TailReader struct {
	filePath      string
	lines         chan<- string
	retryInterval time.Duration // интервал повтора при недоступном файле; из cfg.General.TailRetryInterval
}

// NewTailReader создаёт TailReader.
// lines — буферизованный канал для прочитанных строк (размер: cfg.General.LinesBufSize).
// retryInterval — интервал ожидания при недоступном файле (cfg.General.TailRetryInterval).
// Запуск: go t.Run(ctx).
func NewTailReader(filePath string, lines chan<- string, retryInterval time.Duration) *TailReader {
	return &TailReader{
		filePath:      filePath,
		lines:         lines,
		retryInterval: retryInterval,
	}
}

// Run — блокирующий цикл чтения. Вызывать: go t.Run(ctx).
// Останавливается по ctx.Done().
//
// При старте открывает файл и переходит в EOF — читаем только новые строки,
// не весь исторический лог (может быть гигантским и уже обработанным).
func (t *TailReader) Run(ctx context.Context) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		Log("TAIL", fmt.Sprintf("ошибка создания watcher: %v", err), "error")
		return
	}
	defer watcher.Close()

	// Следим за директорией для детекции CREATE (новый файл после mv-ротации).
	// Только директория гарантирует получение CREATE после того как старый inode исчез.
	dir := filepath.Dir(t.filePath)
	if err := watcher.Add(dir); err != nil {
		Log("TAIL", fmt.Sprintf("ошибка наблюдения директории %s: %v", dir, err), "error")
		return
	}

	// Открываем файл; если ещё не существует — ждём появления
	f := t.waitForFile(ctx)
	if f == nil {
		// ctx отменён пока ждали файл
		return
	}

	// Следим за самим файлом для WRITE/RENAME/REMOVE событий.
	// Не фатально если Add провалится — WRITE события всё равно придут через директорный watch.
	if err := watcher.Add(t.filePath); err != nil {
		Log("TAIL", fmt.Sprintf("ошибка наблюдения файла %s: %v", t.filePath, err), "error")
	}

	reader := bufio.NewReader(f)

	Log("TAIL", fmt.Sprintf("слежение запущено: %s", t.filePath), "info")

	for {
		select {
		case <-ctx.Done():
			Log("TAIL", "слежение остановлено", "info")
			if f != nil {
				f.Close()
			}
			return

		case event, ok := <-watcher.Events:
			if !ok {
				if f != nil {
					f.Close()
				}
				return
			}
			Log("TAIL", fmt.Sprintf("fsnotify: %s %s", event.Op, event.Name), "debug")

			switch {
			case t.isTargetFile(event) && event.Has(fsnotify.Write):
				// Новые данные — сначала проверяем усечение (copytruncate logrotate),
				// потом читаем строки.
				if f != nil && t.handleTruncation(f, reader) {
					Log("TAIL", "copytruncate: файл усечён, читаю с начала", "info")
				}
				if f != nil {
					t.readAvailableLines(reader)
				}

			case t.isTargetFile(event) && (event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove)):
				// Файл переименован/удалён (mv-метод logrotate).
				// Дочитываем хвост из старого fd — nginx мог записать строки между
				// последним WRITE-событием и переименованием.
				if f != nil {
					t.readAvailableLines(reader)
					f.Close()
					f = nil
				}
				_ = watcher.Remove(t.filePath) // inode исчез — снимаем watch
				Log("TAIL", "файл ротирован (mv), ожидаю новый", "info")

			case t.isTargetFile(event) && event.Has(fsnotify.Create):
				// Новый файл создан (после mv-ротации или пересоздания nginx).
				// f == nil при нормальной mv-ротации (RENAME закрыл его выше) — это ожидаемо.
				// Открываем с начала файла — это первые записи нового лога.
				if f != nil {
					f.Close()
				}
				newF, err := os.Open(t.filePath)
				if err != nil {
					Log("TAIL", fmt.Sprintf("ошибка открытия нового файла: %v", err), "error")
					f = nil
					continue
				}
				f = newF
				reader.Reset(f)
				_ = watcher.Add(t.filePath)
				Log("TAIL", "новый файл открыт после ротации", "info")
				t.readAvailableLines(reader)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				if f != nil {
					f.Close()
				}
				return
			}
			Log("TAIL", fmt.Sprintf("ошибка watcher: %v", err), "error")
		}
	}
}

// ========================== Вспомогательные методы ====================================

// waitForFile ждёт появления файла и открывает его с позиции EOF.
// Возвращает nil если ctx отменён до появления файла.
// Seek(EOF) при старте — исторический лог может быть гигантским, не читаем его.
func (t *TailReader) waitForFile(ctx context.Context) *os.File {
	for {
		f, err := os.Open(t.filePath)
		if err == nil {
			if _, seekErr := f.Seek(0, io.SeekEnd); seekErr != nil {
				f.Close()
				Log("TAIL", fmt.Sprintf("ошибка seek(EOF) в %s: %v", t.filePath, seekErr), "error")
			} else {
				return f
			}
		} else {
			Log("TAIL", fmt.Sprintf("файл недоступен (%v), повтор через %v", err, t.retryInterval), "warning")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(t.retryInterval):
		}
	}
}

// handleTruncation обнаруживает усечение файла (logrotate copytruncate) и
// сбрасывает позицию чтения в начало файла.
// Возвращает true если усечение обнаружено и seek(0) выполнен.
func (t *TailReader) handleTruncation(f *os.File, reader *bufio.Reader) bool {
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	if pos > info.Size() {
		// Текущая позиция за пределами нового размера — файл был усечён на месте
		_, _ = f.Seek(0, io.SeekStart)
		reader.Reset(f)
		return true
	}
	return false
}

// readAvailableLines читает все доступные строки до io.EOF и отправляет в канал.
// Не блокирует — останавливается при io.EOF (данных больше нет в данный момент).
// При переполнении канала строка пропускается — лучше потерять строку чем
// заблокировать watcher-цикл и пропустить события ротации.
func (t *TailReader) readAvailableLines(reader *bufio.Reader) {
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimRight(line, "\r\n")
			if line != "" {
				select {
				case t.lines <- line:
				default:
					// Downstream (parser/processor) не успевает — строка потеряна
					Log("TAIL", "канал переполнен, строка пропущена", "warning")
				}
			}
		}
		if err != nil {
			// io.EOF — нормально, ждём следующего WRITE-события
			return
		}
	}
}

// isTargetFile проверяет что fsnotify-событие касается отслеживаемого файла.
// fsnotify может вернуть абсолютный путь даже если Add получил относительный —
// filepath.Clean нормализует оба пути перед сравнением.
func (t *TailReader) isTargetFile(event fsnotify.Event) bool {
	return filepath.Clean(event.Name) == filepath.Clean(t.filePath)
}
