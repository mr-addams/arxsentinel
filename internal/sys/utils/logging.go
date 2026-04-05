// ========================== Модуль utils/logging ========================================
//   Три потока логирования: console (цветной stdout), operational (sentinel.log),
//   threat (threats.log). Тегированный вывод с поддержкой debugOnlyTags/quietTags.
//
//   ЧТО ЗДЕСЬ:
//     - Инициализация трёх логгеров
//     - Тегированный вывод: outer + inner теги
//     - debugOnlyTags, quietTags, quietInnerTags — фильтрация по уровню
//
//   Реализуется в Task 1.2.

package utils
