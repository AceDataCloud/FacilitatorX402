# Payer-authorized payment recipients

The facilitator verifies and settles the `payTo` supplied in the payment
requirements. It has no merchant registry, primary recipient, additional-address
list or per-business receiving-wallet configuration. Adding another resource
server does not require editing facilitator code or registering its wallet.

The existing enabled-network, mechanism and asset checks still apply. Standard
EVM exact authorizations bind the recipient in EIP-3009; Permit2 upto binds it in
the signed witness; Solana exact binds the destination token account in the
payer-signed transaction. The mechanism must verify those bindings before an
authorization can settle. `/settle` still requires `X-Settlement-Token`.

## Resource-server responsibility

The resource server must build its expected payment requirements from its own
order, price, network, asset and receiving-wallet configuration. It must pass
those expected requirements to the facilitator. A facilitator success for
client-selected terms is not permission to credit an unrelated order or serve a
different resource.

For example, a payer's valid signature sending USDC to their own wallet does not
satisfy a business quote whose `payTo` is the business wallet. The business must
reject that mismatch, even though the signature may be valid for another payment.

Ace's order-payment helper matches the submitted accepted terms to its generated
requirements. Its Gateway passes the server-generated requirement for the chosen
network/scheme, including the business recipient and amount. Envar binds the
payload and chain receipt to the original top-up's frozen terms. Each business
keeps its own receiving-wallet configuration and ledger checks.

Verification persists the original requirements and payload. Settlement cannot
replace the recipient, including when another recipient would be valid for a
separate new payment. Existing transaction identity, amount ceilings, duplicate
protection and recovery are retained.

## Delegated recurring profile

The optional recurring profile is an on-chain spending delegation, not a standard
per-payment recipient signature. Trusted business callers must authorize the
request and bind the recipient; the existing delegatee, mint, allowance, period,
expiry and settlement-token checks remain required. Its transfer builder uses
the original verified record's recipient, never a global receiving wallet.
The production recurring profile remains disabled; this change does not enable it.

## Configuration migration

The facilitator no longer reads `X402_*_PAY_TO` or
`X402_ADDITIONAL_EXACT_RECIPIENTS`, and its manifests no longer contain recipient
addresses. Remove those environment references when deploying this version.
There is no replacement recipient allowlist to provision.

Business services still use their own receiving addresses to generate expected
payment requirements. Shared Secret keys such as `BASE_PAY_TO` and `SOLANA_PAY_TO`
may remain for those consumers; do not remove their business configuration.
Operational signer identities, RPCs, token assets and network enablement flags are
unchanged. Do not rewrite existing authorizations or replay historical payments.
