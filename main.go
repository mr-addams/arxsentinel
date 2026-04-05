// ========================== Точка входа — nginx-sentinel ================================
//   Инициализация компонентов, сборка pipeline, запуск демона.
//
//   ЧТО ЗДЕСЬ:
//     - main() — точка входа: загрузка конфига, инициализация логгера, запуск tail reader
//     - Будущее: сборка детекторов, scorer, whitelist → pipeline
//
//   ЧТО НЕ ЗДЕСЬ:
//     - Бизнес-логика (core/)
//     - Конфигурационные структуры (sys/config)
//     - Логирование (sys/utils)

package main

import "fmt"

func main() {
	// Заглушка Flow #1 — будет заменена в Task 1.2 (config+logging) и Task 1.4 (tail reader).
	// Сейчас достаточно для прохождения `go build`.
	fmt.Println("nginx-sentinel starting...")
}
