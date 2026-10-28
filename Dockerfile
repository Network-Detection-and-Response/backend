# Build stage
FROM golang:1.25-alpine AS builder
WORKDIR /src

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/api ./cmd/api

# Runtime stage
FROM alpine:3.20
WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata \
	&& adduser -D -H -u 10001 appuser

COPY --from=builder /out/api /app/api

USER appuser
EXPOSE 8080

ENTRYPOINT ["/app/api"]
