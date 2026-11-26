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
- API инцидентов: `GET/PATCH /api/v1/incidents` (пагинация, фильтры, переходы статусов)
- Telegram: опциональная очередь с retry; только HIGH/CRITICAL; сбой Telegram не блокирует ingestion
- `GET /api/v1/topology` — наблюдаемый граф связей (не физическая схема); `is_compromised` / `is_under_attack` из активных инцидентов за `ATTACK_WINDOW`
- `GET /api/v1/stats/overview?period=24h` — агрегаты flows/bytes/packets, инцидентов, `tcp_flags`, `sensors`
- `GET /api/v1/stats/timeseries?period=1h` — поминутная телеметрия за последний час (UTC, zero-fill)
- `GET /ws/stream` — realtime WebSocket (`FLOW_STATS`, `INCIDENT_ALERT`, `TOPOLOGY_UPDATED`); REST остаётся источником начальной загрузки
- Репозитории для работы с этими таблицами
- Базовые автотесты и команды сборки/проверки
- Интеграционный audit (фаза 08): матрица требований, ограничения стенда, открытые вопросы к команде (ниже)

## Что планируется дальше

1. Согласовать открытые контрактные вопросы с владельцами Sensor / ML / Frontend (раздел ниже)
2. Опционально: пользовательская авторизация dashboard/WS (только после решения команды)

## Стек

- Go 1.22+
- Gin, gorilla/websocket, pgx, PostgreSQL 16
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

**JSON policy:** неизвестные поля в теле `POST /api/v1/flows` **отклоняются** (`DisallowUnknownFields` → `400 VALIDATION_ERROR`). Лишние ключи в `tcp_flags` тоже запрещены.

**Ограничения очереди:** in-memory канал не переживает аварийный перезапуск/kill и не даёт гарантированной доставки. При штатной остановке (SIGINT/SIGTERM) HTTP сначала перестаёт принимать запросы; затем очередь дренирует уже принятые батчи в пределах `SHUTDOWN_TIMEOUT` (отдельный бюджет после остановки HTTP). По истечении бюджета in-flight `ProcessBatch` отменяется, оставшиеся задания помечаются abandoned, и `Shutdown` **всегда** дожидается выхода workers перед возвратом — пул БД закрывается только после этого. Если БД игнорирует отмену контекста, процесс может зависнуть на shutdown (это намеренно безопаснее, чем закрыть pool под активными workers). Ошибки сохранения ретраятся ограниченно (`PERSIST_MAX_ATTEMPTS`, exponential backoff от `PERSIST_RETRY_BASE_DELAY`) внутри worker'а; после исчерпания попыток батч учитывается в `persist_failures` и отбрасывается. Повтор после `202` создаёт новый `batch_id` и дублирует строки — не ретраить успешный accept.

### Инциденты (dashboard)

```bash
curl -s "http://localhost:8080/api/v1/incidents?page=1&page_size=20&severity=CRITICAL&status=OPEN"
curl -s "http://localhost:8080/api/v1/incidents/<uuid>"
curl -s -X PATCH "http://localhost:8080/api/v1/incidents/<uuid>" \
  -H "Content-Type: application/json" \
  -d '{"status":"ACKNOWLEDGED"}'
```

Допустимые PATCH-статусы: `ACKNOWLEDGED`, `RESOLVED`, `FALSE_POSITIVE`.  
Переходы: `OPEN → ACKNOWLEDGED|RESOLVED|FALSE_POSITIVE`; `ACKNOWLEDGED → RESOLVED|FALSE_POSITIVE`; `RESOLVED`/`FALSE_POSITIVE` терминальны.

### Порты в `POST /api/v1/flows` (Sensor contract)

PostgreSQL уже допускает `0..65535`. HTTP-валидация protocol-aware:

| Протокол | Правило |
|----------|---------|
| `ICMP` | `src_port`/`dst_port` ∈ `0..65535` (Sensor шлёт `0/0`) |
| `TCP`/`UDP` обычный поток | оба порта ∈ `1..65535` |
| `TCP`/`UDP` flood summary | `src_port = 0` (маркер `DroppedFloodAggregator`); `dst_port` ∈ `0..65535` |
| прочие | оба порта ∈ `1..65535` (port 0 **не** разрешён безусловно) |

### Топология и статистика

```bash
curl -s http://localhost:8080/api/v1/topology
curl -s "http://localhost:8080/api/v1/stats/overview?period=24h"
curl -s "http://localhost:8080/api/v1/stats/timeseries?period=1h"
```

Топология — **наблюдаемые** коммуникации sensor→backend (IP/MAC), не гарантированная L2/L3 схема сети.  
Флаги атаки считаются на чтении: инциденты со статусом `OPEN`/`ACKNOWLEDGED` за окно `ATTACK_WINDOW` (по умолчанию 15m).  
`period` для overview: `1h`, `24h`, `7d` или положительный Go duration (не больше 30d).  
`protocols`: `[{ "protocol", "flows", "bytes", "packets" }, ...]`.

**Additive overview fields (обратная совместимость):**

```json
"tcp_flags": { "syn": 0, "ack": 0, "rst": 0 },
"sensors": [{
  "sensor_id": "core_switch_mirror",
  "last_batch_at": "2026-11-25T14:30:00Z",
  "flows_last_5m": 12,
  "activity": "active"
}]
```

`tcp_flags` — `SUM(tcp_syn/ack/rst)` по `network_flows` за выбранный `period`.  
`sensors` — **не heartbeat**: `last_batch_at = MAX(observed_at)` за последние 24h (это timestamp батча Sensor).  
Правило `activity`: `active` ≤2m, `idle` ≤15m, иначе `stale`. Статус `online` **не** используется.

**Timeseries contract** (`GET /api/v1/stats/timeseries?period=1h` — только `1h`):

```json
{
  "period": "1h",
  "bucket": "1m",
  "timezone": "UTC",
  "from": "2026-11-25T13:31:00Z",
  "to": "2026-11-25T14:30:00Z",
  "points": [{ "t": "2026-11-25T13:31:00Z", "flows": 0, "packets": 0, "bytes": 0 }]
}
```

Ровно 60 минут UTC; пустые минуты — нули (не синтетический трафик). Сортировка по `t` ASC. Индекс `network_flows_observed_at_idx` достаточен; новых индексов не добавлялось.

### WebSocket realtime

`GET /ws/stream` — одно соединение для dashboard. События — JSON envelope:

```json
{ "type": "INCIDENT_ALERT", "timestamp": "2026-10-09T14:30:00Z", "data": { "incident_id": "<uuid>", "severity": "HIGH" } }
```

Типы: `FLOW_STATS` (после успешного persist батча), `TOPOLOGY_UPDATED` (после upsert nodes/edges), `INCIDENT_ALERT` (после создания инцидента).  
`data` для `INCIDENT_ALERT`: `{ "incident_id", "severity" }` (+ опционально `attack_class`, `status`).  
`FLOW_STATS`: `{ "batch_id", "accepted_flows", "bytes_total", "packets_total" }`.  
`TOPOLOGY_UPDATED`: `{ "batch_id", "nodes_upserted", "edges_upserted" }`.

**Безопасность (учебный стенд):** проверка `Origin` по `CORS_ALLOWED_ORIGINS` — это не авторизация пользователя. Пустой Origin (non-browser) допускается. Как и остальные dashboard REST (`/incidents`, `/topology`, `/stats`), `GET /ws/stream` **не требует** session/token: любой клиент, дошедший до endpoint, может получать realtime-события о сети и инцидентах. Это осознанное ограничение учебного стенда, не production-ready IAM.

На клиента — ограниченный буфер (`WS_CLIENT_BUFFER`); медленный клиент не блокирует ingestion. **При полном буфере исходящие события для этого клиента могут теряться** (дропаются без retry/replay). Ping/pong и write deadlines — `WS_*`. При shutdown соединения закрываются, hub ждёт завершения read/write pumps. Горизонтальное масштабирование WS без внешнего брокера не обещается. Frontend после reconnect загружает состояние через REST.

### Telegram

Включается только при обоих `TELEGRAM_BOT_TOKEN` и `TELEGRAM_CHAT_ID`. Отправляются только новые инциденты severity `HIGH`/`CRITICAL` (не `FALSE_POSITIVE`). Очередь in-memory: **не переживает перезапуск**, доставка не гарантирована; при переполнении сообщение дропается (счётчик/лог), pipeline не блокируется. Токены в логи не пишутся. Тесты используют mock HTTP, не реальный чат.

Обязательные переменные в `.env`: `DATABASE_URL`, `SENSOR_API_KEY`.  
Опционально: `ML_SERVICE_URL`, `ATTACK_THRESHOLD` (`0.60`), `DDOS_CRITICAL_THRESHOLD` (`0.85`), `WS_*`, Telegram/LLM.  
Контракт ML: `docs/ML_CONTRACT.md` (реальный Python API пока не подтверждён).  
Whitelist — **UTC**. Рекомендации advisory only — IP не блокируется.  
Файл `.env` в git не коммитится. Dashboard API без пользовательской авторизации (учебный стенд).

## Полезные команды

| Команда | Назначение |
|---------|------------|
| `make run` | запуск API |
| `make test` | тесты |
| `make check` | форматирование + vet + тесты |
| `make migrate-up` | применить миграции |
| `make docker-up` | поднять Compose |

Миграции нужно запускать отдельно — при старте API и в Docker Compose схема сама **не** создаётся (`make migrate-up` после `docker compose up -d postgres`).

## Демо-сценарий (acceptance)

1. `cp .env.example .env` → задать `SENSOR_API_KEY`, при необходимости `ML_SERVICE_URL`.
2. Поднять БД: `docker compose up -d postgres` (нужен запущенный Docker Desktop).
3. `make migrate-up` → `make run` (или `docker compose up --build -d` после миграций).
4. `curl` `/healthz` и `/readyz` → `200`.
5. Отправить нормальный батч на `POST /api/v1/flows` → `202`; проверить `GET /api/v1/topology` (nodes/edges) и `GET /api/v1/stats/overview?period=24h`.
6. С mock ML (высокий `PortScan`/`DDoS`): убедиться, что появляется инцидент, при желании событие на `GET /ws/stream`, при настроенном Telegram — сообщение только для HIGH/CRITICAL.
7. Остановить ML / указать неверный URL: ingestion продолжает сохранять flows, инциденты из «пустого» ML не создаются.
8. Сбой Telegram (неверный token/chat или mock 500): API и очередь ingestion остаются доступны.

## Запуск для одногруппника

```bash
git clone <repo> && cd backend
cp .env.example .env   # SENSOR_API_KEY, DATABASE_URL
# Docker Desktop должен быть запущен
docker compose up -d postgres
make migrate-up
make test
make run
```

Compose `backend` собирает API, но **не** накатывает goose. Локально API обычно удобнее через `make run` к `localhost:5432`.

## Открытые вопросы к команде (контракты)

**Sensor**
- Timestamp относится к батчу целиком или к каждому flow?
- Гарантирует ли сенсор unique flow IDs, или ID всегда выдаёт backend?
- Port 0: закрыто на Backend (ICMP `0/0`, flood `src_port=0`); отдельный heartbeat от Sensor **не** реализован — activity выводится из `observed_at`.
- Точное имя заголовка ключа и переменной конфигурации на стороне сенсора?

**ML**
- Совпадает ли live `POST /predict` с `API_CONTRACTS.md` / `docs/ML_CONTRACT.md` (batch + `flow_id` + 4 класса)?
- Какой базовый URL и таймауты на стенде команды?

**Frontend**
- Устраивает ли открытый dashboard/WS без user auth на учебном стенде?
- Ожидаемые `data` для `FLOW_STATS` / `TOPOLOGY_UPDATED` (сейчас зафиксированы в README)?
- `incident_id` как UUID (как в REST), а не display-id вида `INC-883`?

## Известные ограничения стенда

- Dashboard REST и `/ws/stream` без пользовательской авторизации; Origin ≠ auth.
- In-memory очереди ingestion/Telegram/WS не переживают restart; при полном WS-буфере события клиенту могут теряться.
- Одна инстанция backend; горизонтальный fan-out WS без брокера не поддерживается.
- Реальная блокировка IP не выполняется; `recommended_action` advisory only.
- `go test -race` требует cgo + gcc (на Windows без MinGW может быть недоступен).
- Интеграционные тесты с PostgreSQL пропускаются (`Skip`), если БД/goose недоступны.
