# Envar upfront settlement

Envar uses the standard x402 v2 `/settle` request with exactly `x402Version`,
`paymentPayload`, and `paymentRequirements`. It does not call `/verify` or a
registration endpoint. Its requirements carry `extra.paymentFlow="upfront"`:
payment confirmation precedes Agent A work. The official SDK verifies and simulates
the authorization inside the authenticated settle handler before any reservation
can reach the durable broadcasting state machine.

The feature remains disabled by default. Envar must send both
`X-Envar-Delegation-Token` and a canonical UUID `X-Envar-Intent-Id`. Its service key
must differ from `X402_SETTLE_TOKEN`; requests with mixed rail headers fail closed.
Only Base mainnet, official USDC, exact EIP-3009, distinct nonzero payer/payee,
and 1–10,000 atomic USDC are accepted. Ordinary callers retain their configured
fixed recipient and cannot settle Envar authorizations.

The existing `X402Authorization` table stores the original payload, requirements,
signature, payer and `verification_id="envar:<intent UUID>"` before broadcasting.
Both nonce identity and the reserved Envar verification ID are unique. The ordinary
verify endpoint cannot reserve this namespace. A retry must match the original
intent, signature and complete terms; it can reconcile an expired authorization
only through its original persisted transaction.

A generic successful transaction receipt is insufficient. The HTTP path, replay
path and background reconciler require exactly one USDC Transfer matching the
original contract, payer, payee, amount and transaction hash. Missing proof leaves
the authorization pending without rebroadcasting a confirmed transaction. Reverted
Envar transactions retain their original hash and enter failed status, without
creating a replacement transfer.

## Migration and existing records

Migration 0014 removes the two unpublished registration models from active Django
state, retaining their historical tables and IDs for audit. It removes the archived
binding table's foreign key to active authorizations, so archived data does not
interfere with normal database maintenance. Legacy authorizations are quarantined
under `envar:legacy:<intent UUID>` and cannot be replayed through either rail. This
is a forward-only data migration; do not roll back by deleting audit tables or by
re-enabling the retired endpoints. Existing legacy payments need manual review.

## Validation and release boundaries

`python -m pytest x402f/tests core/tests -q` covers the standard endpoint and ordinary
rail regressions. Run it against PostgreSQL to include concurrent nonce/intent
reservation tests. CI has a PostgreSQL job for this purpose.

To exercise the merged Envar server against this service over loopback HTTP:

```sh
ENVAR_SOURCE_DIR=/path/to/EnvarAI \
DATABASE_ENGINE=django.db.backends.sqlite3 PGSQL_DATABASE_FACILITATOR=:memory: \
python -m pytest x402f/tests/test_envar_integration.py -q
```

This creates separate temporary databases and runs actual Envar and Facilitator
code, including SDK signature verification. Chain reads, broadcasting and receipts
are synthetic. It checks that Envar remains waiting without Transfer proof and
reconciles the original payment before queueing A work. It is not evidence of a
mainnet payment, real Agent execution, delivery or Credits accounting.

Production deployment, independent funds-safety review, secret provisioning and
payment enablement remain separate release gates. A's holder must prove receiving
wallet control. B's holder must personally review the Base chain, official USDC
contract, full A address and amount and confirm the signature. Acceptance requires
the real Transfer, a unique settlement, A's actual Hermes child Run and text output,
the parent terminal state and Credits accounting.
