-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE network_flows (
    id              UUID PRIMARY KEY,
    batch_id        UUID NOT NULL,
    sensor_id       TEXT NOT NULL,
    observed_at     TIMESTAMPTZ NOT NULL,
    src_ip          INET NOT NULL,
    src_mac         MACADDR NULL,
    dst_ip          INET NOT NULL,
    dst_mac         MACADDR NULL,
    src_port        INTEGER NOT NULL CHECK (src_port >= 0 AND src_port <= 65535),
    dst_port        INTEGER NOT NULL CHECK (dst_port >= 0 AND dst_port <= 65535),
    protocol        TEXT NOT NULL,
    duration_ms     BIGINT NOT NULL CHECK (duration_ms >= 0),
    total_packets   BIGINT NOT NULL CHECK (total_packets >= 0),
    total_bytes     BIGINT NOT NULL CHECK (total_bytes >= 0),
    tcp_syn         BIGINT NOT NULL DEFAULT 0,
    tcp_ack         BIGINT NOT NULL DEFAULT 0,
    tcp_rst         BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX network_flows_observed_at_idx
    ON network_flows (observed_at DESC);
CREATE INDEX network_flows_src_ip_observed_at_idx
    ON network_flows (src_ip, observed_at DESC);
CREATE INDEX network_flows_dst_ip_observed_at_idx
    ON network_flows (dst_ip, observed_at DESC);
CREATE INDEX network_flows_src_mac_observed_at_idx
    ON network_flows (src_mac, observed_at DESC)
    WHERE src_mac IS NOT NULL;
CREATE INDEX network_flows_batch_id_idx
    ON network_flows (batch_id);

CREATE TABLE network_nodes (
    id              TEXT PRIMARY KEY,
    mac_address     MACADDR NULL,
    ip_address      INET NOT NULL,
    device_type     TEXT NOT NULL DEFAULT 'unknown',
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    is_compromised  BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT network_nodes_seen_order CHECK (last_seen >= first_seen)
);

-- MAC is unique when present; null MACs (IP-only nodes) are allowed multiple times.
CREATE UNIQUE INDEX network_nodes_mac_address_uidx
    ON network_nodes (mac_address)
    WHERE mac_address IS NOT NULL;

CREATE INDEX network_nodes_ip_address_idx
    ON network_nodes (ip_address);
CREATE INDEX network_nodes_last_seen_idx
    ON network_nodes (last_seen DESC);

CREATE TABLE network_edges (
    id               UUID PRIMARY KEY,
    source_node_id   TEXT NOT NULL REFERENCES network_nodes(id),
    target_node_id   TEXT NOT NULL REFERENCES network_nodes(id),
    protocol         TEXT NOT NULL,
    total_bytes      BIGINT NOT NULL DEFAULT 0 CHECK (total_bytes >= 0),
    total_packets    BIGINT NOT NULL DEFAULT 0 CHECK (total_packets >= 0),
    last_seen        TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT network_edges_unique_pair UNIQUE (source_node_id, target_node_id, protocol)
);

CREATE INDEX network_edges_source_idx ON network_edges (source_node_id);
CREATE INDEX network_edges_target_idx ON network_edges (target_node_id);
CREATE INDEX network_edges_last_seen_idx ON network_edges (last_seen DESC);

CREATE TABLE incidents (
    id                   UUID PRIMARY KEY,
    flow_id              UUID NULL REFERENCES network_flows(id),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    src_ip               INET NOT NULL,
    src_mac              MACADDR NULL,
    dst_ip               INET NOT NULL,
    dst_mac              MACADDR NULL,
    attack_class         TEXT NOT NULL,
    severity             TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status               TEXT NOT NULL DEFAULT 'OPEN'
                             CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE')),
    ml_confidence        DOUBLE PRECISION NOT NULL
                             CHECK (ml_confidence >= 0 AND ml_confidence <= 1),
    agent_verdict        TEXT NOT NULL,
    recommended_action   TEXT NOT NULL,
    context_summary      JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX incidents_created_at_idx
    ON incidents (created_at DESC);
CREATE INDEX incidents_severity_status_created_at_idx
    ON incidents (severity, status, created_at DESC);
CREATE INDEX incidents_src_ip_idx
    ON incidents (src_ip);
CREATE INDEX incidents_flow_id_idx
    ON incidents (flow_id)
    WHERE flow_id IS NOT NULL;

CREATE TABLE whitelist_schedules (
    id              UUID PRIMARY KEY,
    name            TEXT NOT NULL,
    src_ip          INET NULL,
    src_mac         MACADDR NULL,
    dst_ip          INET NULL,
    protocol        TEXT NULL,
    start_time      TIME NOT NULL,
    end_time        TIME NOT NULL,
    days_of_week    SMALLINT[] NOT NULL DEFAULT '{0,1,2,3,4,5,6}',
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT whitelist_schedules_days_nonempty CHECK (cardinality(days_of_week) > 0)
);

CREATE INDEX whitelist_schedules_enabled_idx
    ON whitelist_schedules (enabled)
    WHERE enabled = TRUE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS whitelist_schedules;
DROP TABLE IF EXISTS incidents;
DROP TABLE IF EXISTS network_edges;
DROP TABLE IF EXISTS network_nodes;
DROP TABLE IF EXISTS network_flows;
-- +goose StatementEnd
