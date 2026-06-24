#!/usr/bin/env bash
# Общая библиотека хелперов для интеграционных тестов.
# Подгружается run.sh и scenarios.sh (последний выполняется в отдельном bash-процессе
# и поэтому не наследует функции, определённые в run.sh).

# docker_pull_retry IMAGE
#   Тянет docker-образ с до 3 попытками и экспоненциальным backoff (2/4/8 секунды).
#   Логирует каждую попытку. Возвращает ненулевой код, если все попытки провалились.
#   Нужен, чтобы переживать транзиентные TLS-handshake/network-таймауты Docker Hub,
#   которые раньше абортили весь интеграционный прогон целиком.
docker_pull_retry() {
    local image=$1
    local max_attempts=3
    local delay=2
    local attempt=1
    while [ "$attempt" -le "$max_attempts" ]; do
        if docker pull -q "$image"; then
            return 0
        fi
        echo "[pull] attempt ${attempt}/${max_attempts} failed for ${image}; retrying in ${delay}s..." >&2
        sleep "$delay"
        delay=$((delay * 2))
        attempt=$((attempt + 1))
    done
    echo "[pull] ERROR: failed to pull ${image} after ${max_attempts} attempts" >&2
    return 1
}