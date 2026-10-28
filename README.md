# NDR Backend

Backend учебной системы **Network Detection and Response** на Go.

Система пассивно анализирует метаданные сетевых сессий: сенсор (C#) отправляет потоки, backend сохраняет их в PostgreSQL, ML-сервис оценивает класс трафика, backend формирует инциденты и отдаёт данные веб-панели. При необходимости — уведомления в Telegram.

Автоматическая блокировка адресов **не** выполняется: рекомендации только для оператора.

## Что уже готово

- Запуск API на Go (Gin) с конфигурацией через переменные окружения
- Проверки живости и готовности: `GET /healthz`, `GET /readyz`
- PostgreSQL в Docker Compose
- Схема БД и миграции (goose): потоки, узлы, связи, инциденты, whitelist-расписания
- Репозитории для работы с этими таблицами
- Базовые автотесты и команды сборки/проверки

## Что планируется дальше

1. Приём батчей потоков от сенсора (`POST /api/v1/flows`)
2. Интеграция с ML-сервисом и правила формирования инцидентов
3. API инцидентов, топологии и статистики для панели
4. Уведомления в Telegram (опционально)
5. Realtime-события по WebSocket

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

Обязательные переменные в `.env`: `DATABASE_URL`, `SENSOR_API_KEY`.  
Файл `.env` в git не коммитится.

## Полезные команды

| Команда | Назначение |
|---------|------------|
| `make run` | запуск API |
| `make test` | тесты |
| `make check` | форматирование + vet + тесты |
| `make migrate-up` | применить миграции |
| `make docker-up` | поднять Compose |

Миграции нужно запускать отдельно — при старте API схема сама не создаётся.
