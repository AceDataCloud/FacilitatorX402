#!/usr/bin/env bash

set -euo pipefail

: "${CATALOG_ACCESS_TOKEN:?CATALOG_ACCESS_TOKEN is required}"
: "${CATALOG_SIGNING_SECRET:?CATALOG_SIGNING_SECRET is required}"

# Both zones must present the same token and HMAC key, otherwise the projector
# rejects every signed catalog page it fetches from PlatformBackend.
kubectl patch secret x402 -n acedatacloud --type merge -p "$(
	jq -n \
		--arg token "$(printf '%s' "$CATALOG_ACCESS_TOKEN" | base64)" \
		--arg signing "$(printf '%s' "$CATALOG_SIGNING_SECRET" | base64)" \
		'{data: {CATALOG_ACCESS_TOKEN: $token, CATALOG_SIGNING_SECRET: $signing}}'
)" >/dev/null

for key in CATALOG_ACCESS_TOKEN CATALOG_SIGNING_SECRET; do
	if [ -z "$(kubectl get secret x402 -n acedatacloud -o "jsonpath={.data.$key}")" ]; then
		echo "x402 secret is missing $key after sync" >&2
		exit 1
	fi
	echo "x402 secret has $key"
done
