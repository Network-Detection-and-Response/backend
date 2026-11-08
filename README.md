# NDR Backend

Backend учебной системы **Network Detection and Response** на Go.

Система пассивно анализирует метаданные сетевых сессий: сенсор (C#) отправляет потоки, backend сохраняет их в PostgreSQL, при наличии ML вызывает `/predict` и формирует инциденты, затем отдаёт данные веб-панели. При необходимости — уведомления в Telegram.

**Интеграция с реальным Python ML API команды пока не подтверждена** (исходников/доступного сервиса нет): клиент совместим с контрактом в `API_CONTRACTS.md` и проверяется через mock. Подробности — `docs/ML_CONTRACT.md`.

Автоматическая блокировка адресов **не** выполняется: рекомендации только для оператора.

## Что уже готово

- Запуск API на Go (Gin) с конфигурацией через переменные окружения
- Проверки живости и готовности: `GET /healthz`, `GET /readyz`
- PostgreSQL в Docker Compose
- Схема БД и миграции (goose): потоки, узлы, связи, инциденты, whitelist-расписания
- `POST /api/v1/flows` — приём батчей от сенсора (валидация, API-ключ, очередь, сохранение flows/nodes/edges)
- ML-клиент (mock-compatible) `POST ${ML_SERVICE_URL}/predict` с таймаутом и валидацией ответа; при сбое ML телеметрия сохраняется, предсказания не выдумываются
- Decision Agent: детерминированные правила (`Normal`/`PortScan`/`DDoS`/`BruteForce`), whitelist UTC, русские шаблоны; LLM опционален и не меняет class/confidence/severity; повторный скоринг того же flow не создаёт дубликат инцидента
- Репозитории для работы с этими таблицами
- Базовые автотесты и команды сборки/проверки

## Что планируется дальше

1. API инцидентов, топологии и статистики для панели
2. Уведомления в Telegram (опционально)
3. Realtime-события по WebSocket

## Стек

- Go 1.22+
- Gin, pgx, PostgreSQL 16
- Docker Compose
- goose (миграции)

## Быстрый старт

Нужны: Go, Docker Desktop, [goose](https://github.com/pressly/goose).

```bash
cp .env.example .env
docker compose up -d postgres
make migrate-up
go run ./cmd/api
```

Проверка:

```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz
```

### Приём батча потоков

Требуется заголовок `X-Sensor-API-Key` (значение из `SENSOR_API_KEY`). Успешный ответ — `202 Accepted` только если батч попал во внутреннюю очередь обработки.

```bash
curl -s -X POST http://localhost:8080/api/v1/flows \
  -H "Content-Type: application/json" \
  -H "X-Sensor-API-Key: change-me-sensor-key" \
  -d '{
    "sensor_id": "core_switch_mirror",
    "timestamp": "2026-10-09T14:30:00Z",
    "flows": [{
      "src_ip": "192.168.1.50",
      "src_mac": "00:1A:2B:3C:4D:5E",
      "dst_ip": "10.0.0.5",
      "dst_mac": null,
      "src_port": 54321,
      "dst_port": 443,
      "protocol": "TCP",
      "duration_ms": 1500,
      "total_packets": 45,
      "total_bytes": 35000,
      "tcp_flags": { "syn": 1, "ack": 40, "rst": 0 }
    }]
  }'
```

Ожидаемый ответ:

```json
{
  "data": {
    "batch_id": "<uuid>",
    "accepted_flows": 1,
    "status": "accepted"
  }
}
```

Коды ошибок: `400` (валидация), `401` (ключ), `413` (слишком большой body/батч), `503` (очередь заполнена).

**Ограничения очереди:** in-memory канал не переживает аварийный перезапуск/kill и не даёт гарантированной доставки. При штатной остановке (SIGINT/SIGTERM) HTTP сначала перестаёт принимать запросы; затем очередь дренирует уже принятые батчи в пределах `SHUTDOWN_TIMEOUT` (отдельный бюджет после остановки HTTP). По истечении бюджета in-flight `ProcessBatch` отменяется, оставшиеся задания помечаются abandoned, и `Shutdown` **всегда** дожидается выхода workers перед возвратом — пул БД закрывается только после этого. Если БД игнорирует отмену контекста, процесс может зависнуть на shutdown (это намеренно безопаснее, чем закрыть pool под активными workers). Ошибки сохранения ретраятся ограниченно (`PERSIST_MAX_ATTEMPTS`, exponential backoff от `PERSIST_RETRY_BASE_DELAY`) внутри worker'а; после исчерпания попыток батч учитывается в `persist_failures` и отбрасывается. Повтор после `202` создаёт новый `batch_id` и дублирует строки — не ретраить успешный accept.

Обязательные переменные в `.env`: `DATABASE_URL`, `SENSOR_API_KEY`.  
Опционально: `ML_SERVICE_URL` (без него flows сохраняются, скоринг пропускается), `ATTACK_THRESHOLD` (по умолчанию `0.60`), `DDOS_CRITICAL_THRESHOLD` (`0.85`), `LLM_API_KEY`/`LLM_BASE_URL` (только текст объяснения).  
Контракт ML и статус сверки с Python-сервисом: `docs/ML_CONTRACT.md`.  
Whitelist-расписания интерпретируются в **UTC**; совпадение exact-match может снизить severity и выставить `FALSE_POSITIVE`. Рекомендации advisory only — IP не блокируется.  
Файл `.env` в git не коммитится. Dashboard API на этом этапе без пользовательской авторизации (учебный стенд, не production-ready).

## Полезные команды

| Команда | Назначение |
|---------|------------|
| `make run` | запуск API |
| `make test` | тесты |
| `make check` | форматирование + vet + тесты |
| `make migrate-up` | применить миграции |
| `make docker-up` | поднять Compose |

Миграции нужно запускать отдельно — при старте API схема сама не создаётся.
