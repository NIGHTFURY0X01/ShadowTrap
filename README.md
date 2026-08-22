# ShadowTrap

ShadowTrap is a modular, low-interaction honeypot and attack-intelligence platform. It records HTTP and SSH interaction, correlates behaviour by source IP, calculates deterministic risk, exposes a protected FastAPI interface, and presents the results in a live dashboard.

> Use only on systems and networks you own or are explicitly authorized to monitor. Place honeypots in an isolated segment; they are intentionally exposed services and must never hold production secrets.

## What is included

- HTTP and SSH low-interaction honeypots that never execute attacker input.
- SQLite persistence by default, with optional PostgreSQL via `SHADOWTRAP_DATABASE_URL`.
- Behaviour, credential, HTTP scanner, brute-force, suspicious-path, and cross-service campaign intelligence.
- Risk score, severity, classification, IP investigation, and chronological event timeline.
- FastAPI API, optional API-key protection, Prometheus-style metrics, critical-alert webhook support, and a responsive dashboard.
- Docker Compose deployment, persistent storage, retention tooling, CI, and unit/API/end-to-end tests.

## Quick start

Requires Python 3.12+.

```bash
cd "/Users/ShadowTrap"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py init
```

Start each process in a separate terminal:

```bash
python main.py api
python main.py http
python main.py ssh
```

Open [the dashboard](http://127.0.0.1:8000/dashboard/) or the interactive API documentation at `http://127.0.0.1:8000/docs`.

For a harmless local end-to-end check, make one request to the HTTP service:

```bash
curl -i http://127.0.0.1:8080/wp-login.php
curl -i -X POST http://127.0.0.1:8080/login -d 'username=demo&password=demo'
python main.py investigate --ip 127.0.0.1
```

## CLI

```text
python main.py init
python main.py api [--host 127.0.0.1] [--port 8000]
python main.py http [--host 127.0.0.1] [--port 8080]
python main.py ssh [--host 127.0.0.1] [--port 2222]
python main.py investigate --ip 198.51.100.23 --json
python main.py timeline --ip 198.51.100.23
python main.py http-analyze --ip 198.51.100.23
python main.py credentials --ip 198.51.100.23
python main.py purge --confirm
```

Captured passwords are masked in CLI and API output by default. `--show-sensitive` is deliberately required for local CLI display. API sensitive output additionally requires a configured `SHADOWTRAP_API_KEY` and `X-API-Key` request header.

## Configuration and security

`config.yaml` supplies safe loopback defaults. Environment variables prefixed with `SHADOWTRAP_` override it; see `.env.example`.

- Set `SHADOWTRAP_API_KEY` to protect `/api/*`. The dashboard has a session-only key field.
- Use `SHADOWTRAP_DATABASE_URL=postgresql://…` to select PostgreSQL. The default is durable SQLite with WAL mode.
- Alerts are disabled by default. Set `SHADOWTRAP_ALERTING_ENABLED=true` and, optionally, `SHADOWTRAP_ALERT_WEBHOOK_URL` for critical-event notifications. Alerts are deduplicated per IP and classification.
- Bind services to loopback during development. In a deployment, use a firewall, a dedicated host/VLAN, a reverse proxy for the dashboard/API, monitoring, and restricted database access.
- `python main.py purge --confirm` removes data older than the configured retention period; it is the only automatic-retention action and requires explicit confirmation.

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /` | API status and dashboard location |
| `GET /api/health` | Database-aware health check |
| `GET /api/stats` | Collection metrics |
| `GET /api/attacks` | Recent events; filter by `service`, `source_ip`, or `event` |
| `GET /api/investigate/{ip}` | Combined risk and evidence |
| `GET /api/timeline/{ip}` | Ordered activity timeline |
| `GET /api/http/{ip}` | HTTP scanner/brute-force intelligence |
| `GET /api/campaign/{ip}` | Cross-service campaign analysis |
| `GET /api/credentials/{ip}` | Credential-pattern intelligence |
| `GET /api/alerts` | Generated critical alerts |
| `GET /api/metrics` | Prometheus-style plaintext metrics |

Example:

```bash
curl http://127.0.0.1:8000/api/investigate/127.0.0.1
curl -H "X-API-Key: $SHADOWTRAP_API_KEY" http://127.0.0.1:8000/api/stats
```

## Docker

```bash
docker compose up --build
```

This starts the API/dashboard, HTTP honeypot, and SSH honeypot with one persistent `shadowtrap-data` volume. To use PostgreSQL, start the profile and set the identical database URL on all three ShadowTrap services:

```bash
docker compose --profile postgres up -d postgres
# Set SHADOWTRAP_DATABASE_URL=postgresql://shadowtrap:change-me@postgres:5432/shadowtrap
# for api, http-honeypot, and ssh-honeypot in a deployment override file.
```

## Verification

```bash
python -m pytest -q
```

The suite covers storage, logger behaviour, risk/detection logic, API contracts, the HTTP honeypot, and an end-to-end HTTP request → database → API investigation path.
