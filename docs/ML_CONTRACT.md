# ML contract status (phase 04)

## Source of truth

Backend implements a **mock-compatible** client for
`POST ${ML_SERVICE_URL}/predict` as documented in
`ndr-cursor-backend-kit/API_CONTRACTS.md` §2:

- Request: `{ "flows": [ { "flow_id", addresses, ports, protocol, counters, tcp_flags } ] }`
- Response: `{ "predictions": [ { "flow_id", "probabilities": { Normal, PortScan, DDoS, BruteForce } } ] }`
- Probabilities: finite, each in `[0,1]`, sum within `±0.02` of `1`
- Each `flow_id` in the response must belong to the request set (no unexpected IDs)

Local/unit tests use an `httptest` mock with this contract.

## Team confirmation — not done

**Реальный Python ML API ещё не проверен.**

Исходников ML-сервиса нет в этом репозитории и в соседнем дереве `тп`.
Живой FastAPI endpoint не был доступен для сверки. Поэтому:

- **нет подтверждённой интеграции** с продовым/учебным ML-сервисом команды;
- backend готов к работе с mock и с сервисом, если он совпадает с `API_CONTRACTS.md`;
- при расхождении live API с документом стороны **нельзя** менять молча — зафиксировать
  mismatch и согласовать один контракт.

## Degradation

- Empty `ML_SERVICE_URL`: backend starts; scoring is skipped; flows still persist.
- ML timeout / HTTP 503 / invalid JSON / invalid probabilities: logged
  (`ml_predict_failed`); saved flows are kept; predictions are **not** fabricated;
  no incident is created from a missing ML answer.
