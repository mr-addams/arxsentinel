// ========================== Модуль parser/nginx =========================================
//   Парсер combined log format + поле real_ip.
//   Извлекает структурированный LogEntry из строки лога Nginx.
//
//   ЧТО ЗДЕСЬ:
//     - Структура LogEntry — все поля строки лога
//     - Parse() — парсинг одной строки, graceful skip при битой строке
//     - Извлечение последнего IP из цепочки X-Forwarded-For в поле real_ip
//
//   Формат лога:
//     $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
//     "$http_referer" "$http_user_agent" "$real_ip"
//
//   Реализуется в Task 1.3.

package parser
