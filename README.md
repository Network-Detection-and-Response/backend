# NDR Backend (Go)

Центральный API учебной системы Network Detection and Response. Принимает flow-метаданные от C#-сенсора, сохраняет их в PostgreSQL, вызывает ML-сервис, формирует инциденты и отдаёт данные dashboard.

Спецификации команды лежат в `ndr-cursor-backend-kit/` (`BACKEND_SPEC.md`, `API_CONTRACTS.md`, `DATABASE.md`, `TEST_PLAN.md`).

## Текущий статус (этап 02 — database)

Работает каркас приложения:
- конфигурация из env / `.env`
- `GET /healthz` / `GET /readyz`
- Docker Compose (PostgreSQL + backend)
- схема PostgreSQL через **goose**: `network_flows`, `network_nodes`, `network_edges`, `incidents`, `whitelist_schedules`
- репозитории pgx (`internal/repository/postgres`)

Ещё не реализовано: HTTP-приём flows, ML, инциденты API, топология, Telegram, WebSocket.

### Миграции

Нужен CLI [goose](https://github.com/pressly/goose). Схема **не** применяется при старте API — только явно:

```bash
docker compose up -d postgres
make migrate-up
make migrate-status
```

Timezone для `whitelist_schedules`: backend интерпретирует `start_time` / `end_time` / `days_of_week` в **UTC**.

Идентификатор узла: `mac:<AA:BB:…>` если MAC есть, иначе `ip:<address>`. MAC не является универсальным PK.

**Безопасность учебного стенда:** dashboard API на следующих этапах без пользовательской авторизации. Это не production-ready.

## Требования

- Go 1.22+
- Docker Desktop (для Compose / интеграционных проверок)
- (позже) [goose](https://github.com/pressly/goose) для миграций

## Быстрый старт

```bash
cp .env.example .env
# отредактируйте SENSOR_API_KEY и при необходимости DATABASE_URL

# Локально (нужен запущенный PostgreSQL, например через Compose)
docker compose up -d postgres
go run ./cmd/api
```

Проверки:

```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz
```

Полный стек:

```bash
docker compose up --build
```

## Переменные окружения

См. `.env.example`. Обязательные:
- `DATABASE_URL`
- `SENSOR_API_KEY`

Опциональные (приложение стартует без них): Telegram, LLM, URL ML-сервиса.

Секреты в репозиторий не коммитить. В `.env` только локальные/учебные значения.

## Makefile

| Цель | Назначение |
|------|------------|
| `make run` | запуск API |
| `make test` | `go test ./...` |
| `make vet` | `go vet ./...` |
| `make fmt` | `gofmt -w .` |
| `make check` | fmt + vet + test |
| `make migrate-up` | миграции (этап 02) |
| `make docker-up` | Compose up --build |

## Ограничения

- In-memory очереди (появятся позже) не переживают перезапуск.
- Автоматическая блокировка IP не выполняется; `recommended_action` — только рекомендация оператору.
- Производительность 500–5000 сессий/с не заявляется без измерений.
