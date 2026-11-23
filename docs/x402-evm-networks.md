# Additional EVM USDC payments

The networks below support x402 v2 `exact` payments when explicitly enabled.
They are disabled by default; code support does not mean the production service
already accepts payments on the network. Use the request's live `accepts` list.
Only native Circle USDC is supported, with 6 decimals and the EIP-712 domain
`USD Coin`, version `2`. Bridged USDC and other tokens are not interchangeable.

| Network | Alias | CAIP-2 | Native USDC |
| --- | --- | --- | --- |
| Arbitrum One | `arbitrum` | `eip155:42161` | `0xaf88d065e77c8cC2239327C5EDb3A432268e5831` |
| Polygon PoS | `polygon` | `eip155:137` | `0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359` |

## Rollout

For each network, replace `<CHAIN>` with its uppercase alias:

- Facilitator: configure `X402_<CHAIN>_RPC_URL`,
  `X402_<CHAIN>_SIGNER_PRIVATE_KEY` and `X402_<CHAIN>_SIGNER_ADDRESS`;
  then set `X402_<CHAIN>_EXACT_ENABLED=true`.
  Optional `X402_<CHAIN>_GAS_LIMIT` defaults to 500000.
- Gateway and PlatformBackend: configure their business `X402_<CHAIN>_PAY_TO`,
  then set `X402_<CHAIN>_EXACT_ENABLED=true`. Keep RPC credentials and signer
  keys only in the facilitator's existing secret configuration.
- Use the existing deployment secret loading. No database migration or cost
  rule change is required. The existing USD price and Credits conversion remain
  authoritative; the new networks consume the same frozen atomic quote.

The merchant recipient may be an existing EVM address whose owner can access
that network. The facilitator's operational signer pays gas and is separate
from the recipient; do not put a personal wallet recovery phrase on the server.
The new networks settle each fixed price in full and do not offer `upto`.

Deploy facilitator support first, then the client SDK and checkout, followed by
Gateway/API and Backend/order advertisement. Verify `/supported` and run an
explicitly authorized small payment on each network: successful verification,
on-chain USDC transfer to the business-selected recipient, settlement receipt and
reconciliation; also check wrong asset/recipient, replay and failed API handling.
No mainnet transfer was performed as part of these PRs.

For rollback, disable advertisement in Gateway and PlatformBackend first.
Keep the facilitator rail, signer and RPC available until all pending payments
and settlement recovery work are drained. Only then disable its rail.

Sources: [Circle USDC contracts](https://developers.circle.com/stablecoins/usdc-contract-addresses)
and the [x402 EVM mechanism](https://github.com/x402-foundation/x402/tree/main/typescript/packages/mechanisms/evm).


Kubernetes manifests read optional RPC/address/gas configuration from the existing
`x402` Secret. The facilitator does not configure merchant recipients.
Business services retain `ARBITRUM_PAY_TO` to construct their expected quotes.
Operational signer keys remain in the isolated signing Secret. A new network
needs its explicit enable flag before it can accept payments.
