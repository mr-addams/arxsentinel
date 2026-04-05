// ========================== Модуль output/logger ========================================
//   Запись THREAT-событий в threat-лог в формате для Fail2Ban.
//
//   ЧТО ЗДЕСЬ:
//     - ThreatLogger — запись строк формата:
//       `timestamp THREAT IP score=N modules=... reason="..."`
//     - Поток threats.log (третий поток из sys/utils/logging.go)
//
//   Реализуется в Task 2.4.

package output
