#!/usr/bin/env bash

set -euo pipefail

: "${OLD_TAG:?OLD_TAG is required}"
: "${CATALOG_ACCESS_TOKEN:?CATALOG_ACCESS_TOKEN is required}"
: "${CATALOG_SIGNING_SECRET:?CATALOG_SIGNING_SECRET is required}"

PREFLIGHT_JOB="facilitator-bazaar-rollback-preflight-$OLD_TAG"
SMOKE_JOB="facilitator-bazaar-rollback-smoke-$OLD_TAG"
SNAPSHOT_DIR="$(mktemp -d)"
CURRENT_DEPLOYMENT="$SNAPSHOT_DIR/deployment.json"
CURRENT_SPEC="$SNAPSHOT_DIR/deployment-spec.json"
CURRENT_SECRET="$SNAPSHOT_DIR/x402-secret.json"
CURRENT_CRONJOB="$SNAPSHOT_DIR/bazaar-cronjob.json"
CURRENT_CRONJOB_EXISTS=0
CUTOVER_COMPLETE=0

kubectl get deployment/facilitator-backend -n acedatacloud -o json >"$CURRENT_DEPLOYMENT"
jq -e '{spec: .spec}' "$CURRENT_DEPLOYMENT" >"$CURRENT_SPEC"
kubectl get secret/x402 -n acedatacloud -o json \
  | jq -e 'del(.metadata.creationTimestamp,.metadata.managedFields,.metadata.resourceVersion,.metadata.uid)' \
  >"$CURRENT_SECRET"
if kubectl get cronjob/facilitator-bazaar-refresh -n acedatacloud --ignore-not-found -o json >"$CURRENT_CRONJOB.raw" \
  && [ -s "$CURRENT_CRONJOB.raw" ]; then
  jq -e 'del(.status,.metadata.creationTimestamp,.metadata.generation,.metadata.managedFields,.metadata.resourceVersion,.metadata.uid)' \
    "$CURRENT_CRONJOB.raw" >"$CURRENT_CRONJOB"
  CURRENT_CRONJOB_EXISTS=1
fi
rm -f "$CURRENT_CRONJOB.raw"

restore_catalog_keys() {
  restore_failed=0
  for key in CATALOG_ACCESS_TOKEN CATALOG_SIGNING_SECRET; do
    original="$(jq -r --arg key "$key" '.data[$key] // empty' "$CURRENT_SECRET")"
    if [ -n "$original" ]; then
      kubectl patch secret x402 -n acedatacloud --type=merge -p "$(
        jq -n --arg key "$key" --arg value "$original" '{data: {($key): $value}}'
      )" || restore_failed=1
    else
      kubectl patch secret x402 -n acedatacloud --type=json \
        -p "$(jq -n --arg path "/data/$key" '[{op: "remove", path: $path}]')" || restore_failed=1
    fi
  done
  return "$restore_failed"
}

restore_current() {
  set +e
  restore_failed=0
  restore_catalog_keys || restore_failed=1
  if [ "$CURRENT_CRONJOB_EXISTS" -eq 1 ]; then
    kubectl apply -f "$CURRENT_CRONJOB" || restore_failed=1
  else
    kubectl delete cronjob/facilitator-bazaar-refresh -n acedatacloud \
      --ignore-not-found --timeout=120s --wait=true || restore_failed=1
  fi
  kubectl patch deployment/facilitator-backend -n acedatacloud \
    --type=merge --patch-file="$CURRENT_SPEC" || restore_failed=1
  kubectl rollout status deployment/facilitator-backend -n acedatacloud \
    --timeout=600s || restore_failed=1
  return "$restore_failed"
}

on_exit() {
  exit_code=$?
  trap - EXIT
  kubectl delete job "$PREFLIGHT_JOB" "$SMOKE_JOB" -n acedatacloud \
    --ignore-not-found --timeout=120s --wait=true >/dev/null 2>&1 || true
  if [ "$CUTOVER_COMPLETE" -ne 1 ]; then
    restore_current || exit_code=1
  fi
  rm -rf "$SNAPSHOT_DIR"
  exit "$exit_code"
}
trap on_exit EXIT

# Prove the old tag exists and starts without touching the live Deployment or DB.
kubectl delete job "$PREFLIGHT_JOB" -n acedatacloud --ignore-not-found --timeout=120s --wait=true
kubectl create job "$PREFLIGHT_JOB" -n acedatacloud \
  --image="ghcr.io/acedatacloud/facilitator-backend:$OLD_TAG" -- python manage.py check
kubectl wait --for=condition=complete "job/$PREFLIGHT_JOB" -n acedatacloud --timeout=120s
kubectl logs "job/$PREFLIGHT_JOB" -n acedatacloud

kubectl patch secret x402 -n acedatacloud --type=merge -p "$(
  jq -n \
    --arg token "$(printf '%s' "$CATALOG_ACCESS_TOKEN" | base64 | tr -d '\n')" \
    --arg signing "$(printf '%s' "$CATALOG_SIGNING_SECRET" | base64 | tr -d '\n')" \
    '{data: {CATALOG_ACCESS_TOKEN: $token, CATALOG_SIGNING_SECRET: $signing}}'
)" >/dev/null
for key in CATALOG_ACCESS_TOKEN CATALOG_SIGNING_SECRET; do
  test -n "$(kubectl get secret x402 -n acedatacloud -o "jsonpath={.data.$key}")"
done

# Restore the old serving runtime, then validate one refresh while scheduling is
# suspended. A failed refresh restores the retirement runtime automatically.
sed 's/\${TAG}/'"$OLD_TAG"'/g' deploy/rollback/deployment.yaml | kubectl apply -f -
kubectl rollout status deployment/facilitator-backend -n acedatacloud --timeout=600s
sed 's/\${TAG}/'"$OLD_TAG"'/g' deploy/rollback/bazaar-cronjob.yaml | kubectl apply -f -
kubectl delete job "$SMOKE_JOB" -n acedatacloud --ignore-not-found --timeout=120s --wait=true
kubectl create job "$SMOKE_JOB" -n acedatacloud --from=cronjob/facilitator-bazaar-refresh
kubectl wait --for=condition=complete "job/$SMOKE_JOB" -n acedatacloud --timeout=120s
kubectl logs "job/$SMOKE_JOB" -n acedatacloud
curl --fail --retry 5 --retry-delay 2 --connect-timeout 5 --max-time 15 \
  https://facilitator.acedata.cloud/discovery/resources >/dev/null
kubectl patch cronjob/facilitator-bazaar-refresh -n acedatacloud --type=merge -p '{"spec":{"suspend":false}}'
CUTOVER_COMPLETE=1
