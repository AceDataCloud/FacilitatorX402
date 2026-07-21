#!/usr/bin/env bash

set -euo pipefail

TAG="canary-${GITHUB_SHA:?GITHUB_SHA is required}"
MANIFEST="$(mktemp)"
MIGRATION_MANIFEST="$(mktemp)"
SNAPSHOT_DIR="$(mktemp -d)"
ROLLOUT_COMPLETE=0
SMOKE_JOB=""
RESOURCES=(
  configmap/facilitator2-config
  deployment/facilitator2-backend
  service/facilitator2-backend
  ingress/facilitator2-backend
  cronjob/facilitator2-reconcile
)

snapshot_resource() {
  local resource="$1"
  local path="$2"
  local raw="$path.raw"
  local temporary="$path.tmp"
  rm -f "$raw" "$temporary"
  if ! kubectl get "$resource" -n acedatacloud --ignore-not-found -o json >"$raw"; then
    rm -f "$raw"
    return 1
  fi
  if [ ! -s "$raw" ]; then
    rm -f "$raw"
    return 0
  fi
  if ! jq -e 'del(.status,.metadata.creationTimestamp,.metadata.generation,.metadata.managedFields,.metadata.resourceVersion,.metadata.uid) | select(type == "object" and length > 0)' <"$raw" >"$temporary"; then
    rm -f "$raw" "$temporary"
    return 1
  fi
  rm -f "$raw"
  if [ ! -s "$temporary" ]; then
    rm -f "$temporary"
    return 1
  fi
  mv "$temporary" "$path"
}

for resource in "${RESOURCES[@]}"; do
  name="${resource//\//-}"
  snapshot_resource "$resource" "$SNAPSHOT_DIR/$name.json"
done

cleanup() {
  exit_code=$?
  trap - EXIT INT TERM
  if [ -n "$SMOKE_JOB" ]; then
    kubectl delete job "$SMOKE_JOB" -n acedatacloud --ignore-not-found >/dev/null 2>&1 || true
  fi
  if [ "$exit_code" -ne 0 ] && [ "$ROLLOUT_COMPLETE" -ne 1 ]; then
    rollback_failed=0
    for resource in "${RESOURCES[@]}"; do
      name="${resource//\//-}"
      if [ -f "$SNAPSHOT_DIR/$name.json" ]; then
        kubectl apply -f "$SNAPSHOT_DIR/$name.json" || rollback_failed=1
      else
        kubectl delete "$resource" -n acedatacloud --ignore-not-found || rollback_failed=1
      fi
    done
    kubectl rollout status deployment/facilitator2-backend -n acedatacloud --timeout=600s || rollback_failed=1
    if [ "$rollback_failed" -ne 0 ]; then
      echo "facilitator2 parity rollback failed" >&2
    fi
  fi
  rm -f "$MANIFEST"
  rm -f "$MIGRATION_MANIFEST"
  rm -rf "$SNAPSHOT_DIR"
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

for key in \
  APP_SECRET_KEY \
  PGSQL_DATABASE_FACILITATOR PGSQL_HOST PGSQL_PASSWORD PGSQL_PORT PGSQL_USER \
  X402_SETTLE_TOKEN \
  X402_BASE_RPC_URL X402_BASE_SIGNER_PRIVATE_KEY X402_BASE_SIGNER_ADDRESS X402_BASE_PAY_TO X402_BASE_ASSET \
  X402_SOLANA_RPC_URL X402_SOLANA_SIGNER_PRIVATE_KEY X402_SOLANA_SIGNER_ADDRESS X402_SOLANA_PAY_TO X402_SOLANA_ASSET \
  X402_SOLANA_DEVNET_SIGNER_PRIVATE_KEY X402_SOLANA_DEVNET_SIGNER_ADDRESS X402_SOLANA_DEVNET_PAY_TO \
  X402_SKALE_RPC_URL X402_SKALE_SIGNER_PRIVATE_KEY X402_SKALE_SIGNER_ADDRESS X402_SKALE_PAY_TO X402_SKALE_ASSET; do
  test -n "$(kubectl get secret facilitator2-parity-runtime -n acedatacloud -o jsonpath="{.data.$key}")"
done

kubectl apply -f deploy/canary/config-parity.yaml
SHORT_SHA="${GITHUB_SHA:0:8}"
sed -e "s/\${TAG}/$TAG/g" -e "s/\${SHORT_SHA}/$SHORT_SHA/g" \
  deploy/canary/migration-parity.yaml >"$MIGRATION_MANIFEST"
kubectl delete job "facilitator2-migrate-$SHORT_SHA" -n acedatacloud --ignore-not-found >/dev/null
kubectl apply -f "$MIGRATION_MANIFEST"
kubectl wait --for=condition=complete "job/facilitator2-migrate-$SHORT_SHA" -n acedatacloud --timeout=300s
kubectl logs "job/facilitator2-migrate-$SHORT_SHA" -n acedatacloud

sed "s/\${TAG}/$TAG/g" deploy/canary/resources-parity.yaml >"$MANIFEST"
kubectl apply -f "$MANIFEST"
kubectl rollout status deployment/facilitator2-backend -n acedatacloud --timeout=900s
test "$(kubectl get deployment facilitator2-backend -n acedatacloud -o jsonpath='{.status.readyReplicas}')" = "2"

EXPECTED='["exact:eip155:1187947933","exact:eip155:8453","exact:solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","upto:eip155:8453"]'
kubectl exec deployment/facilitator2-backend -n acedatacloud -- \
  python -c 'import json,urllib.request; data=json.load(urllib.request.urlopen("http://127.0.0.1:8000/supported",timeout=10)); print(json.dumps(sorted(item["scheme"] + ":" + str(item["network"]) for item in data["kinds"])))' | \
  jq -e --argjson expected "$EXPECTED" '. == $expected' >/dev/null
/usr/bin/curl --fail --silent --show-error --connect-timeout 10 --max-time 30 \
  https://facilitator2.acedata.cloud/supported | \
  jq -e --argjson expected "$EXPECTED" '[.kinds[] | "\(.scheme):\(.network)"] | sort == $expected' >/dev/null

SMOKE_JOB="facilitator2-reconcile-smoke-${GITHUB_SHA:0:8}"
kubectl delete job "$SMOKE_JOB" -n acedatacloud --ignore-not-found >/dev/null
kubectl create job "$SMOKE_JOB" -n acedatacloud --from=cronjob/facilitator2-reconcile
kubectl wait --for=condition=complete "job/$SMOKE_JOB" -n acedatacloud --timeout=120s
kubectl logs "job/$SMOKE_JOB" -n acedatacloud
kubectl delete job "$SMOKE_JOB" -n acedatacloud --ignore-not-found >/dev/null
SMOKE_JOB=""

ROLLOUT_COMPLETE=1
