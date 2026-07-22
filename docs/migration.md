# Official x402 v2 Facilitator Migration

This document describes the migration completed by
[PR 66](https://github.com/AceDataCloud/FacilitatorX402/pull/66), merged as
`6ad53e34b6eed20ca5b81f88b84469ab5d34ec71` on 2026-07-21. It covers the code
and data migration from the self-written multi-chain facilitator to the official
`x402==2.16.0` schemes.

The merged change touched 42 files with 2,549 additions and 5,952 deletions.
The official implementation was subsequently promoted to
`https://facilitator.acedata.cloud`; the temporary validation endpoint was
retired after the July 2026 production cutover.

The follow-up migration PR also aligns the production manifests with the
validated candidate: all four production rails are mapped from the `x402`
Secret, readiness/liveness probes use the production Host header, and a durable
reconciliation CronJob is deployed and smoke-tested as part of cutover.

## Migration outcome

The official implementation supports all four production rails previously
served by the legacy facilitator:

| Scheme | Network | CAIP-2 identifier | Asset |
| --- | --- | --- | --- |
| exact | Base mainnet | `eip155:8453` | Circle USDC |
| upto | Base mainnet | `eip155:8453` | Circle USDC through Permit2 |
| exact | SKALE Base | `eip155:1187947933` | Bridged USDC |
| exact | Solana mainnet | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` | SPL USDC |

Solana devnet exact is implemented behind configuration but is disabled. It is
a testnet compatibility option, not a production cutover requirement.

## Architecture change

### Before

- `x402f/views_multichain.py` selected a self-written chain handler.
- `x402f/chain_handlers/` implemented EVM exact, EVM upto, SKALE, and Solana
  verification and settlement directly.
- Public network identifiers used short names such as `base`, `skale`, and
  `solana`.
- Recovery depended on handler-specific transaction logic.

### After

- `x402f/urls.py` routes `/supported`, `/verify`, and `/settle` only to
  `x402f/views_official.py`.
- `x402f/official.py` registers official `ExactEvmFacilitatorScheme`,
  `UptoEvmFacilitatorScheme`, and `ExactSvmFacilitatorScheme` implementations.
- `x402f/official_signer.py` adapts official SDK signers to durable transaction
  preparation, broadcast, status lookup, and replay.
- PostgreSQL remains the source of truth for verification reservations,
  settlement ownership, prepared transactions, and recovery across replicas.
- Public network identifiers use CAIP-2.

The official SDK owns protocol parsing, signature verification, simulation, and
transaction construction. Ace Data Cloud still owns persistence, distributed
locking, recovery, authorization policy, deployment, and observability.

## What was added

### Official protocol implementation

- `x402f/official.py`
  - Registers enabled schemes per network.
  - Uses isolated signers for Base, SKALE, Solana mainnet, and optional Solana
    devnet.
  - Generates the official `/supported` response without contacting RPC nodes.
- `x402f/views_official.py`
  - Parses official v2 `VerifyRequest` and `SettleRequest` models.
  - Enforces configured asset and recipient allowlists.
  - Reserves verified authorizations before settlement.
  - Supports Base upto verification at a signed ceiling and settlement at an
    actual amount no greater than that ceiling.
  - Requires `X-Settlement-Token` on `/settle`; callers can supply it through
    the official SDK `AuthProvider` interface.
  - Returns complete official response schemas, including on HTTP 403.
  - Returns the original successful transaction for EVM settlement retries.
  - Rejects repeated Solana settlement with the official
    `duplicate_settlement` error to prevent multiple resource fulfillments for
    one chain payment.
- `x402f/official_signer.py`
  - Persists EVM raw transactions, transaction hashes, and signer nonces before
    broadcast.
  - Persists serialized Solana transactions and signatures before submission.
  - Re-broadcasts the same prepared transaction rather than constructing a new
    payment after an ambiguous failure.

### Persistence and recovery

- PostgreSQL advisory locks serialize signer use by canonical network.
- Atomic status claims prevent two replicas from owning one settlement.
- `x402f/management/commands/reconcile_x402.py` repairs stale `settling` rows:
  - releases claims that never prepared a transaction;
  - marks confirmed transactions as settled;
  - clears failed transactions for safe retry;
  - re-broadcasts an identical prepared transaction;
  - expires Solana prepared transactions after their usable window;
  - preserves pending EVM nonce ownership instead of unsafe reallocation.
- Recovery-only aliases map historical `base`, `skale`, `solana`, and
  `solana-devnet` records to CAIP-2 without rewriting stored identity.
- A reconciliation CronJob runs every minute in production.

### Discovery and operations

- `/.well-known/x402` publishes v2 facilitator metadata and enabled kinds.
- `/discovery/resources` proxies a configured HTTPS discovery source with:
  - an exact host allowlist;
  - no credentials, query, fragment, or redirects;
  - a 5 MiB response limit;
  - response-shape validation.
- Production uses the independent PlatformBackend catalog at
  `https://platform.acedata.cloud/api/v1/x402/discovery/`. The facilitator
  validates every resource URL against `x402.acedata.cloud`, then converts the
  URL list into paginated v2 items with the four enabled CAIP-2 payment kinds.
  Full v2 catalog upstreams are subject to the same resource-host and
  accept-resource binding checks before pass-through.
  A source whose host equals the public facilitator host is rejected to prevent
  recursive discovery after domain cutover.
- `/list` permanently redirects to `/discovery/resources` for compatibility.
- The production deployment provides:
  - two replicas;
  - readiness and liveness probes;
  - PostgreSQL-backed state;
  - a migration Job before rollout;
  - a reconciliation CronJob;
  - resource snapshots and automatic rollback before rollout completion.

### Tests and delivery

- Official facilitator, view, SVM signer, reconciliation, discovery proxy, and
  migration tests replace legacy handler tests.
- `.github/workflows/ci.yaml` validates the shared non-root `Dockerfile`.
- `.github/workflows/deploy.yaml` deploys the canonical production resources
  from `deploy/production/`.

## What was removed

The following unreachable self-written implementation was deleted after the
official routes and recovery paths were validated:

- `x402f/views.py`
- `x402f/views_multichain.py`
- `x402f/chain_handlers/__init__.py`
- `x402f/chain_handlers/base.py`
- `x402f/chain_handlers/base_exact.py`
- `x402f/chain_handlers/base_upto.py`
- `x402f/chain_handlers/factory.py`
- `x402f/chain_handlers/skale_exact.py`
- `x402f/chain_handlers/skale_upto.py`
- `x402f/chain_handlers/solana_exact.py`
- `x402f/chain_handlers/upto_constants.py`

Legacy-only tests were also removed:

- `x402f/tests.py`
- `x402f/test_solana_chain_handler.py`
- `x402f/tests/test_base_upto.py`
- `x402f/tests/test_solana_fetch_diagnostics.py`
- `x402f/tests/test_solana_verification.py`

The cleanup commit removed 16 files and 5,750 lines. Database migrations,
historical network aliases, and reconciliation logic were retained because they
are required to recover existing records safely.

## Client-visible changes

### Network identifiers

Clients and resource servers must use the v2 CAIP-2 identifiers returned by
`/supported`:

| Legacy identifier | Official v2 identifier |
| --- | --- |
| `base` | `eip155:8453` |
| `skale` | `eip155:1187947933` |
| `solana` | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` |
| `solana-devnet` | `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` |

Do not hard-code the old short names when parsing `/supported` or constructing
v2 payment requirements. Solana devnet is not advertised unless explicitly
enabled and funded.

### Settlement authentication

`POST /settle` requires `X-Settlement-Token`. With the official Python client,
provide the header through `FacilitatorConfig.auth_provider`; do not patch the
SDK request implementation.

Missing or invalid authentication returns HTTP 403 with a complete
`SettleResponse` body:

```json
{
  "success": false,
  "errorReason": "Unauthorized settlement caller.",
  "transaction": "",
  "network": "eip155:8453"
}
```

### Replay behavior

- A settled EVM authorization returns success with the original transaction.
  This supports recovery after a lost HTTP response without another transfer.
- A repeated settled Solana payload returns `duplicate_settlement` and an empty
  transaction. Resource servers must not fulfill another resource for that
  response.
- A previously settled authorization cannot be submitted as a new verification.

### Upto semantics

For Base upto, verification stores the signed ceiling. Settlement may lower only
the `paymentRequirements.amount`; all other requirements and the payload must be
identical. An actual amount greater than the ceiling is rejected before
broadcast.

## Configuration migration

Existing per-network RPC, signer, fee-payer, asset, gas, and timeout variables
remain valid. The migration adds explicit recipients, enable flags, canonical
network identifiers, settlement authentication, and recovery settings.

### Core settings

| Variable | Purpose | Production requirement |
| --- | --- | --- |
| `X402_SETTLE_TOKEN` | Authenticates `/settle` callers | Required |
| `X402_FACILITATOR_PUBLIC_URL` | Canonical public metadata URL | Required for correct discovery metadata |
| `X402_SETTLEMENT_LEASE_SECONDS` | Stale settlement ownership threshold | Default `300` |
| `X402_PREPARED_MAX_AGE_SECONDS` | Maximum usable prepared Solana age | Default `1800` |
| `X402_TX_TIMEOUT_SECONDS` | Receipt/confirmation timeout | Default `120` |
| `X402_DISCOVERY_URL` | Upstream resource catalog | Optional |
| `X402_DISCOVERY_ALLOWED_HOSTS` | Exact allowlist for discovery proxy | Required when discovery is enabled |
| `X402_DISCOVERY_RESOURCE_HOSTS` | Exact allowlist for resource URLs emitted by the catalog | Defaults to `x402.acedata.cloud` |

### Base

| Variable | Purpose |
| --- | --- |
| `X402_BASE_NETWORK` | Canonical network; use `eip155:8453` |
| `X402_BASE_CHAIN_ID` | EVM chain ID; use `8453` |
| `X402_BASE_RPC_URL` | Base mainnet RPC |
| `X402_BASE_SIGNER_PRIVATE_KEY` | Facilitator gas signer |
| `X402_BASE_SIGNER_ADDRESS` | Expected signer address; validated against key |
| `X402_BASE_ASSET` | Approved Circle USDC contract |
| `X402_BASE_PAY_TO` | Approved recipient |
| `X402_BASE_EXACT_ENABLED` | Advertise/register exact |
| `X402_BASE_UPTO_ENABLED` | Advertise/register Permit2 upto |

### SKALE

| Variable | Purpose |
| --- | --- |
| `X402_SKALE_RPC_URL` | SKALE Base RPC |
| `X402_SKALE_SIGNER_PRIVATE_KEY` | Facilitator signer |
| `X402_SKALE_SIGNER_ADDRESS` | Expected signer address |
| `X402_SKALE_ASSET` | Approved Bridged USDC contract |
| `X402_SKALE_PAY_TO` | Approved recipient |
| `X402_SKALE_CHAIN_ID` | Use `1187947933` |
| `X402_SKALE_GAS_LIMIT` | SKALE transaction gas limit |
| `X402_SKALE_EXACT_ENABLED` | Advertise/register exact |

### Solana

| Variable | Purpose |
| --- | --- |
| `X402_SOLANA_RPC_URL` | Solana mainnet RPC |
| `X402_SOLANA_SIGNER_PRIVATE_KEY` | Facilitator fee-payer signer |
| `X402_SOLANA_SIGNER_ADDRESS` | Expected fee-payer address |
| `X402_SOLANA_ASSET` | Approved SPL USDC mint |
| `X402_SOLANA_PAY_TO` | Approved recipient owner |
| `X402_SOLANA_MAINNET_ENABLED` | Advertise/register mainnet exact |
| `X402_SOLANA_DEVNET_ENABLED` | Advertise/register optional devnet exact |
| `X402_SOLANA_DEVNET_RPC_URL` | Devnet RPC |
| `X402_SOLANA_DEVNET_SIGNER_PRIVATE_KEY` | Independent devnet fee-payer key |
| `X402_SOLANA_DEVNET_SIGNER_ADDRESS` | Expected devnet fee-payer address |
| `X402_SOLANA_DEVNET_ASSET` | Devnet USDC mint |
| `X402_SOLANA_DEVNET_PAY_TO` | Devnet recipient owner |

Keep devnet disabled unless the fee payer has devnet SOL and the rail passes a
real verify/settle test. Never advertise a rail that cannot settle.

The production Deployment and reconciliation CronJob explicitly map Base,
SKALE, and Solana mainnet settings from the `x402` Kubernetes Secret and enable
the four validated production rails. Solana devnet remains disabled. Always
inspect the deployed `/supported` response; code support and manifest flags do
not prove that every Secret value is valid or that a rail can settle.

## Database migration

Migrations are additive or widening:

| Migration | Change |
| --- | --- |
| `0006_expand_official_signature` | Changes `signature` to `TextField` for larger official payloads |
| `0007_add_prepared_transaction` | Adds nullable `prepared_transaction`, `signer_nonce`, and `transaction_broadcast_at` |
| `0008_add_verification_id` | Adds nullable `verification_id` for bound verify retries |

The model also uses existing `payment_payload`, `payment_requirements`, `scheme`,
`settled_amount`, `settling_started_at`, and expanded address/hash fields for
durable official-v2 state.

Do not reverse these migrations during an application rollback. The added fields
are nullable and the widened signature field is compatible with the previous
application. Rolling back schema first could make new rows unreadable or truncate
official signatures.

## Historical cutover runbook

The following sequence records the completed July 2026 cutover. It is retained
for rollback analysis and must not be rerun as a current deployment procedure.

The production runbook is implemented by `deploy/run.sh`.

1. Confirm the release image passed tests, Docker build, and candidate-chain
   validation.
2. Populate and verify all required Kubernetes Secret or SSM values. Compare the
  expected production kinds with the validated release artifact.
3. Disable the Gateway x402 feature that creates new legacy authorizations.
4. Snapshot the current `facilitator-backend` Deployment specification.
5. Scale the legacy Deployment to zero and wait for its pods to terminate.
6. Run `python manage.py check_official_v2_cutover` through
  `deploy/production/preflight-job.yaml`. The command fails while nonterminal
  non-Base legacy authorizations remain.
7. Run `python manage.py migrate --noinput` through
  `deploy/production/migration-job.yaml`.
8. Deploy the official image using the `Recreate` strategy. Incompatible legacy
   and official settlement logic must never overlap.
9. Wait for both replicas to become ready through the Host-aware readiness
   probe.
10. Apply `deploy/production/reconciliation-cronjob.yaml`, create a one-shot Job
  from it, and require that reconciliation smoke Job to complete.
11. Validate `/healthz`, `/supported`, `/.well-known/x402`, and discovery.
  Production discovery must return 43 independently sourced resources, and
  each item must advertise the four enabled CAIP-2 scheme/network pairs.
12. Run one controlled payment per enabled rail and verify the chain receipt,
    database state, and replay behavior.
13. Re-enable Gateway traffic gradually and monitor failures, pending
    reconciliation outcomes, signer balances, and duplicate-settlement errors.

Before advancing traffic, `/supported` had to advertise the intended production
kinds with CAIP-2 identifiers. The validated release advertised the four
production rails before traffic moved.

## Validation evidence

The candidate completed real mainnet settlement tests:

- Base exact:
  [`0x76f32f06...f316d9e`](https://basescan.org/tx/0x76f32f0695b7e2f6685108dad1c6b12ab5118badfd783c84e9f672468f316d9e)
- Base upto, signed ceiling 10 and actual amount 1:
  [`0x0d592968...6166849f`](https://basescan.org/tx/0x0d592968de45fb80cb23c53d76ff58c371f2c1dea3ca2ee026f893ad6166849f)
- Solana mainnet exact:
  [`22vAHU2J...V5CLN4FN`](https://solscan.io/tx/22vAHU2J2b97EYw99MvNHtCt3fvVsAEnLgFENZs2voWCDnp1qK5vvJuPQvnJfAHp4MQTsSwepoqACKE5V5CLN4FN)
- SKALE exact:
  [`0x09a7ff75...a2716c45`](https://skale-base-explorer.skalenodes.com/tx/0x09a7ff75d9f8c007f4e5e618b50f3d301186a38727bf2b8ed55995e8a2716c45)

Additional validation included:

- eight concurrent Base settlement requests producing one on-chain transfer;
- official `HTTPFacilitatorClientSync` interoperability through `AuthProvider`;
- upto-over-ceiling and settle-before-verify rejection;
- Solana finalized token balance deltas and duplicate-settlement rejection;
- two ready validation replicas with no restarts;
- clean CI test, lint, Docker build, image build, and SV deployment jobs.

The migration follow-up adds production-manifest and discovery-cutover checks:

- 46 retained tests pass with explicit Django configuration;
- Ruff, formatting, ShellCheck, Django system check, and migration drift checks
  pass;
- every rendered production Deployment, Job, CronJob, and Service passes
  Kubernetes client dry-run;
- the SV production Secret contains all 17 required four-rail keys;
- fake-kubectl success and failure runs prove one-shot Job cleanup plus
  Deployment/CronJob rollback;
- the real independent PlatformBackend source transforms into 43 discovery
  items with four CAIP-2 scheme/network pairs per item.

The SKALE evidence used the same payer and payee address. It proves on-chain
execution, authorization consumption, and replay handling, but not an independent
merchant balance increase.

## Rollback

### Before rollout completion

`deploy/run.sh` restores the captured Deployment specification automatically if
preflight, migration, apply, rollout, CronJob apply, or reconciliation smoke
fails. It also restores the previous `facilitator-reconcile` CronJob, or deletes
the newly created CronJob when no previous resource existed. The rollback
returns the previous replica count and waits for the old Deployment to become
ready. Preflight, migration, and reconciliation smoke Jobs are deleted on script
exit; their manifests retain a TTL as a secondary cleanup guard.

### After rollout completion

1. Disable Gateway x402 traffic.
2. Stop the official Deployment before restoring the previous image or
   Deployment specification; do not overlap settlement implementations.
3. Restore the previous Deployment specification or image and wait for health.
4. Leave migrations `0006` through `0008` applied.
5. Reconcile any official-v2 `settling` records before allowing the legacy
   service to process new payments.
6. Verify the legacy `/supported`, `/verify`, and `/settle` behavior.
7. Re-enable traffic gradually.

Do not treat a successful Kubernetes rollout as payment proof. A rollback or
cutover is complete only after enabled rails, database state, and chain receipts
have been checked.

## Remaining optional work

- Fund and enable Solana devnet only if testnet parity is still required.
- Add optional x402 extensions such as `payment-identifier`, signed receipts,
  builder attribution, approval gas sponsoring, or batch settlement when product
  requirements justify them.