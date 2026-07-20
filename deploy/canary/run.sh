#!/usr/bin/env bash

set -euo pipefail

TAG="canary-${GITHUB_SHA:?GITHUB_SHA is required}"
MANIFEST="$(mktemp)"
SNAPSHOT="$(mktemp)"
SERVICE_SNAPSHOT="$(mktemp)"
INGRESS_SNAPSHOT="$(mktemp)"
HAD_DEPLOYMENT=0
HAD_SERVICE=0
HAD_INGRESS=0
HAD_PVC=0
ROLLOUT_COMPLETE=0

snapshot_resource() {
  kubectl get "$1" -n acedatacloud -o json | \
    jq 'del(.status,.metadata.creationTimestamp,.metadata.generation,.metadata.managedFields,.metadata.resourceVersion,.metadata.uid)' >"$2"
}

if snapshot_resource deployment/facilitator2-backend "$SNAPSHOT" 2>/dev/null; then
  HAD_DEPLOYMENT=1
fi
if snapshot_resource service/facilitator2-backend "$SERVICE_SNAPSHOT" 2>/dev/null; then
  HAD_SERVICE=1
fi
if snapshot_resource ingress/facilitator2-backend "$INGRESS_SNAPSHOT" 2>/dev/null; then
  HAD_INGRESS=1
fi
if kubectl get pvc/facilitator2-data -n acedatacloud >/dev/null 2>&1; then
  HAD_PVC=1
  PVC_CLASS="$(kubectl get pvc/facilitator2-data -n acedatacloud -o jsonpath='{.spec.storageClassName}')"
  PVC_SIZE="$(kubectl get pvc/facilitator2-data -n acedatacloud -o jsonpath='{.spec.resources.requests.storage}')"
  [ "$PVC_CLASS" = "cbs" ] && [ "$PVC_SIZE" = "10Gi" ] || {
    echo "facilitator2-data PVC contract mismatch" >&2
    exit 1
  }
fi

cleanup() {
  exit_code=$?
  trap - EXIT
  if [ "$exit_code" -ne 0 ] && [ "$ROLLOUT_COMPLETE" -ne 1 ]; then
    if [ "$HAD_DEPLOYMENT" -eq 1 ]; then
      kubectl apply -f "$SNAPSHOT" || true
      kubectl rollout status deployment/facilitator2-backend -n acedatacloud --timeout=600s || true
    else
      kubectl delete deployment/facilitator2-backend -n acedatacloud --ignore-not-found || true
    fi
    if [ "$HAD_SERVICE" -eq 1 ]; then kubectl apply -f "$SERVICE_SNAPSHOT" || true; else kubectl delete service/facilitator2-backend -n acedatacloud --ignore-not-found || true; fi
    if [ "$HAD_INGRESS" -eq 1 ]; then kubectl apply -f "$INGRESS_SNAPSHOT" || true; else kubectl delete ingress/facilitator2-backend -n acedatacloud --ignore-not-found || true; fi
    if [ "$HAD_PVC" -eq 0 ]; then kubectl delete pvc/facilitator2-data -n acedatacloud --ignore-not-found || true; fi
  fi
  rm -f "$MANIFEST" "$SNAPSHOT" "$SERVICE_SNAPSHOT" "$INGRESS_SNAPSHOT"
  exit "$exit_code"
}
trap cleanup EXIT

sed "s/\${TAG}/$TAG/g" deploy/canary/resources.yaml >"$MANIFEST"
RUNTIME_SECRET="$(kubectl get secret facilitator2-runtime -n acedatacloud -o json)"
for key in BASE_SIGNER_PRIVATE_KEY BASE_SIGNER_ADDRESS BASE_PAY_TO SETTLE_TOKEN; do
  printf '%s' "$RUNTIME_SECRET" | jq -e --arg key "$key" '.data[$key] | strings | @base64d | length > 0' >/dev/null
done
if [ "$HAD_PVC" -eq 1 ]; then
  WITHOUT_PVC="$(mktemp)"
  awk 'BEGIN { skip=1 } /^---$/ && skip { skip=0; next } !skip { print }' "$MANIFEST" >"$WITHOUT_PVC"
  kubectl apply -f "$WITHOUT_PVC"
  rm -f "$WITHOUT_PVC"
else
  kubectl apply -f "$MANIFEST"
fi
kubectl wait --for=jsonpath='{.status.phase}'=Bound pvc/facilitator2-data -n acedatacloud --timeout=300s
kubectl rollout status deployment/facilitator2-backend -n acedatacloud --timeout=600s
kubectl exec deployment/facilitator2-backend -n acedatacloud -- \
  python -c 'import json, urllib.request; data=json.load(urllib.request.urlopen("http://127.0.0.1:8000/supported", timeout=5)); assert [{key:item[key] for key in ("x402Version","scheme","network")} for item in data["kinds"]] == [{"x402Version": 2, "scheme": "exact", "network": "eip155:84532"}]'
/usr/bin/curl --fail --silent --show-error --connect-timeout 10 --max-time 30 \
  https://facilitator2.acedata.cloud/supported | \
  jq -e '[.kinds[] | {x402Version,scheme,network}] == [{"x402Version":2,"scheme":"exact","network":"eip155:84532"}]' >/dev/null
ROLLOUT_COMPLETE=1