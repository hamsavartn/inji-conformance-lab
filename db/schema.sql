CREATE TABLE IF NOT EXISTS test_runs (
    id TEXT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    issuer_type TEXT NOT NULL,
    verifier_type TEXT NOT NULL,
    format TEXT NOT NULL,
    status TEXT NOT NULL,
    latency_ms INTEGER,
    tamper_applied TEXT,
    trace_blob TEXT
);
