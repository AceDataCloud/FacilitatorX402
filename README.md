# Ace Data Cloud Facilitator X402

Official verification and settlement implementation for the x402 v2 protocol,
built on the Python SDK (`x402==2.16.0`). The canonical production endpoint is
<https://facilitator.acedata.cloud>. The temporary validation candidate was
retired after the official-v2 production cutover completed in July 2026.

## Production rails

| Scheme | Network | CAIP-2 identifier | Asset |
| --- | --- | --- | --- |
| exact | Base mainnet | `eip155:8453` | Circle USDC |
| upto | Base mainnet | `eip155:8453` | Circle USDC through Permit2 |
| exact | SKALE Base | `eip155:1187947933` | Bridged USDC |
| exact | Solana mainnet | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` | SPL USDC |

Solana devnet support exists behind configuration and is disabled by default.
It is a testnet compatibility option, not a production rail.

## API

- `GET /healthz`: liveness and readiness probe.
- `GET /supported`: official facilitator kinds, extensions, and signer
  addresses.
- `POST /verify`: validate and reserve a v2 payment authorization.
- `POST /settle`: settle a verified authorization. This endpoint requires
  `X-Settlement-Token`.
- `GET /.well-known/x402`: facilitator metadata.
- `GET /discovery/resources`: paginated CAIP-2 resource catalog.
- `GET /list`: compatibility redirect to discovery.

The official SDK handles protocol parsing, signature verification, simulation,
and transaction construction. This service adds:

- PostgreSQL-backed authorization and settlement state;
- per-network PostgreSQL advisory locks across two replicas;
- prepared transaction persistence before broadcast;
- deterministic recovery and reconciliation;
- asset and recipient allowlists;
- authenticated settlement and replay protection.

## Configuration

Database settings:

- `PGSQL_HOST`, `PGSQL_PORT`, `PGSQL_USER`, `PGSQL_PASSWORD`
- `PGSQL_DATABASE_FACILITATOR`

Core settings:

- `APP_ENV`, `APP_SECRET_KEY`, `ALLOWED_HOSTS`
- `X402_SETTLE_TOKEN`
- `X402_FACILITATOR_PUBLIC_URL`
- `X402_SETTLEMENT_LEASE_SECONDS`
- `X402_PREPARED_MAX_AGE_SECONDS`
- `X402_TX_TIMEOUT_SECONDS`

Each enabled rail requires its RPC URL, signer key/address, approved asset, and
approved recipient. See [docs/migration.md](docs/migration.md) for the complete
Base, SKALE, Solana, discovery, migration, cutover, and rollback configuration.

## Development

```bash
poetry install
poetry run python manage.py migrate
poetry run python manage.py runserver 0.0.0.0:8008
```

Run validation:

```bash
poetry run pytest -q
poetry run ruff check .
poetry run ruff format --check .
```

Local container:

```bash
docker compose build
docker compose up
```

Compose loads the gitignored `.env` when present. It can still build without the
file in CI, but payment rails require their configured RPC, signer, asset, and
recipient values before runtime use.

The shared image runs as non-root UID/GID `10001` and serves ASGI with Uvicorn
on port 8000.

## Delivery

- `.github/workflows/ci.yaml`: PR test, lint, and Docker build.
- `.github/workflows/deploy.yaml`: manual production build and deployment from
  `main` through `deploy/run.sh`.

Production deployment uses a Recreate strategy to prevent old and official
settlement semantics from overlapping. The runbook quiesces traffic, checks
legacy records, applies migrations, deploys two replicas, starts reconciliation,
and rolls back the Deployment and CronJob if validation fails.

See [docs/migration.md](docs/migration.md) for the completed official-v2
migration record and rollback constraints.
