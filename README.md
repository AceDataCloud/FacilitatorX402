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

Additional native-USDC networks are available behind per-chain opt-in settings.
See [EVM network setup](docs/x402-evm-networks.md); their presence in source is not a production enablement.

## API

- `GET /healthz`: liveness and readiness probe.
- `GET /supported`: official facilitator kinds, extensions, and signer
  addresses.
- `POST /verify`: validate and reserve a v2 payment authorization.
- `POST /settle`: settle a verified authorization. This endpoint requires
  `X-Settlement-Token`.
- `GET /.well-known/x402`: facilitator metadata.

The official SDK handles protocol parsing, signature verification, simulation,
and transaction construction. This service adds:

- PostgreSQL-backed authorization and settlement state;
- per-network PostgreSQL advisory locks across two replicas;
- prepared transaction persistence before broadcast;
- deterministic recovery and reconciliation;
- asset and recipient allowlists;
- authenticated settlement and replay protection.

Solana verification reports `insufficient_token_balance` when the USDC transfer
simulation returns SPL Token's insufficient-funds error. This response is
retryable and reports `charged: false`; the wallet must hold the quoted USDC
amount before signing a fresh payment. Errors from wallet-added instructions
and the facilitator's fee balance are not classified as a payer USDC shortfall.
Internal simulation logs retain the instruction index and typed error code,
without logging signed transactions, RPC response bodies, or RPC URLs.

## Configuration

Database settings:

- `PGSQL_HOST`, `PGSQL_PORT`, `PGSQL_USER`, `PGSQL_PASSWORD`
- `PGSQL_DATABASE_FACILITATOR`

Runtime, reconciliation, preflight and migration manifests read these fields
from `pgsql-facilitator`. Before a future authorized release, the
`acedatacloud_facilitator` role needs login enabled, ownership of its existing
application objects and permission to create objects in its application schema.
This shared runtime and migration role has DDL authority within its own database;
table grants alone do not permit `ALTER TABLE`. Changing Secret references does
not authorize resuming a stopped facilitator or its suspended reconciliation task.

Core settings:

- `APP_ENV`, `APPLICATION_SECRET_KEY`, `ALLOWED_HOSTS`
- `X402_SETTLE_TOKEN`
- `X402_FACILITATOR_PUBLIC_URL`
- `X402_SETTLEMENT_LEASE_SECONDS`
- `X402_PREPARED_MAX_AGE_SECONDS`
- `X402_TX_TIMEOUT_SECONDS`

Each enabled rail requires its RPC URL, signer key/address, approved asset, and
approved recipient. See [docs/migration.md](docs/migration.md) for the complete
Base, SKALE, Solana, migration, cutover, and rollback configuration.

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
  `main` through `deploy/run.sh` on the Hong Kong cluster.

Production templates default to **paused**: zero web replicas, suspended
reconciliation, all payment rails disabled and no signer private-key references.
Pushes and manual runs of the deployment workflow stage the new image in those
paused templates. They do not connect to the database or run preflight,
migration, reconciliation or live payment checks. Existing reconciliation Pods
must be stopped before staging; suspending a CronJob does not stop an existing Job.

Payment restoration is a separate, explicitly authorized operator action. See
[paused releases and restoration](docs/paused-releases.md) for required checks,
rail selection and failure behavior. Ordinary application deployment does not
restore payments. A failed release rolls back the image while preserving zero
replicas, disabled rails, absent signer key references and suspended reconciliation.

See [docs/migration.md](docs/migration.md) for the historical official-v2
migration record and schema rollback constraints.

## Application secret configuration

Use `APPLICATION_SECRET_KEY` from this service's independent application Secret.
See [configuration migration](plans/application-secrets/README.md) for names and deployment prerequisites.


## Payment configuration

Keep RPC URLs, approved assets, receiving addresses and the settlement caller
token in `x402`. Keep only signer private keys in `x402-private`: each enabled
network reads its own `<NETWORK>_SIGNER_PRIVATE_KEY` field. The Facilitator never
mounts sweep or buyback configuration. Database and application credentials
remain in `pgsql-facilitator` and `facilitator-application`.

The Hong Kong deployment uses its repository-scoped `KUBE_CONFIG_HK`. Ordinary
Backend and worker processes do not receive signer private fields. Production
release templates contain no private keys while payments are paused. Keep
reconciliation suspended during migration and validate database access and chain
RPCs before enabling the selected payment networks.
