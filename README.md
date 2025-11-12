# Ace Data Cloud Facilitator X402

Ace Data Cloud runs Facilitator X402 as the production settlement engine behind the X402 payment protocol. The service is publicly available at [https://facilitator.acedata.cloud](https://facilitator.acedata.cloud) and ties into the wider Ace Data Cloud platform at [https://platform.acedata.cloud](https://platform.acedata.cloud).

## X402 at a glance

[x402](https://x402.org) is an open protocol that brings stablecoin payments to plain HTTP by reviving status code **402 Payment Required**:

- Clients obtain payment instructions through a standard HTTP response, then respond with a typed authorization.
- Signatures use EIP-712 typed data so destination, amount, validity window, and nonce are all cryptographically bound.
- Nonces eliminate replay; facilitators store each authorization before allowing settlement.
- Usage-based pricing, micropayments, and machine-to-machine scenarios become first-class—with no accounts, API keys, or session management.

### Why it matters

Web-scale applications and AI agents need instant, programmable settlement. Legacy payment flows are slow and require pre-established credentials. x402 embeds payment in the request–response cycle, enabling trust-minimized pay-per-request experiences with the reach of the public internet.

### Protocol flow

1. The client requests a protected resource.
2. The server returns HTTP 402 with x402 `paymentRequirements`.
3. The client signs a `TransferWithAuthorization` payload and sends it back.
4. Facilitator X402 verifies, settles on-chain, and the resource is released.

![x402 sequence](https://cdn.acedata.cloud/30qdwn.jpg)

## Facilitator capabilities

- **Authorization verification** – `POST /x402/verify` checks payload integrity and signature, enforces caps/validity, and persists the nonce for replay protection.
- **Settlement execution** – `POST /x402/settle` re-validates the stored authorization, invokes `transferWithAuthorization`, waits for the receipt, and marks the record as settled.
- **Operational endpoints** – `/` and `/healthz` provide JSON probes for L7 load balancers.
- **Web3 integration** – Configurable RPC endpoint, gas limits, and optional EIP-1559 fees. Supports any stablecoin contract address supplied in the request.
- **Automated delivery** – `.github/workflows/deploy.yaml` builds & deploys to Kubernetes using `deploy/run.sh` and the manifests under `deploy/production/`.

## Configuration

Environment variables govern runtime behaviour (see the supplied `.env`).

| Variable                                                                                 | Description                                   | Required | Default                    |
| ---------------------------------------------------------------------------------------- | --------------------------------------------- | -------- | -------------------------- |
| `APP_ENV`                                                                                | Environment (local, production, …)            | No       | `local`                    |
| `APP_SECRET_KEY`                                                                         | Django secret key                             | Yes      | —                          |
| `PGSQL_HOST`, `PGSQL_PORT`, `PGSQL_USER`, `PGSQL_PASSWORD`, `PGSQL_DATABASE_FACILITATOR` | PostgreSQL connection info                    | Yes      | —                          |
| `X402_RPC_URL`                                                                           | RPC endpoint used for settlement transactions | Yes      | —                          |
| `X402_SIGNER_PRIVATE_KEY`                                                                | Private key used to sign settlements          | Yes      | —                          |
| `X402_SIGNER_ADDRESS`                                                                    | Optional explicit signer address              | No       | derived from key           |
| `X402_GAS_LIMIT`                                                                         | Gas limit applied to settlements              | No       | `250000`                   |
| `X402_TX_TIMEOUT_SECONDS`                                                                | Timeout (seconds) waiting for receipts        | No       | `120`                      |
| `X402_MAX_FEE_PER_GAS_WEI`                                                               | Max fee per gas (EIP-1559)                    | No       | `0` (use legacy gas price) |
| `X402_MAX_PRIORITY_FEE_PER_GAS_WEI`                                                      | Priority fee per gas (EIP-1559)               | No       | `0`                        |

Callers are responsible for restricting `pay_to`, `asset`, and `network` values in payloads to approved destinations.

## Development workflow

```bash
# install dependencies
pip install -r <(poetry export -f requirements.txt --without-hashes)
# or
poetry install

# apply migrations
python manage.py migrate

# start locally
python manage.py runserver 0.0.0.0:8008
```

## Containers and deployment

- `docker-compose build && docker-compose up` runs the service with `uvicorn core.asgi:application --host 0.0.0.0 --port 8000`.
- Kubernetes manifests live under `deploy/production`. Use `deploy/run.sh` during CI/CD to substitute the build number and apply.
- The GitHub Actions workflow `.github/workflows/deploy.yaml` handles build → push → rollout to the Ace Data Cloud cluster.

## API quick reference

```http
POST /x402/verify
Content-Type: application/json

{
  "paymentPayload": { ... },
  "paymentRequirements": { ... }
}
```

Response:

```json
{ "isValid": true, "invalidReason": null, "payer": "0x..." }
```

```http
POST /x402/settle
```

Response on success:

```json
{
  "success": true,
  "transaction": "0xabc123...",
  "network": "base",
  "payer": "0x..."
}
```

Failures return `success: false` with `errorReason` explaining validation failures, replay detection, RPC timeouts, or on-chain reverts.

## Repository layout

```
FacilitatorBackend/
├── core/
├── x402f/
├── deploy/
├── Dockerfile
├── docker-compose.yaml
├── pyproject.toml
└── README.md
```

## Production footprint and contact

- Facilitator endpoint: [https://facilitator.acedata.cloud](https://facilitator.acedata.cloud)
- Ace Data Cloud platform: [https://platform.acedata.cloud](https://platform.acedata.cloud)
- Updates and coordination: [https://x.com/acedatacloud](https://x.com/acedatacloud)
