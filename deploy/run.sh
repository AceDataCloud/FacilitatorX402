#!/bin/bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-acedatacloud}"
DEPLOYMENT_NAME="facilitator-backend"
SERVICE_NAME="facilitator-backend"
BUILD_TAG="${BUILD_NUMBER:-latest}"
LOCAL_PORT="${FACILITATOR_SMOKE_PORT:-18080}"

sed "s/\${TAG}/${BUILD_TAG}/g" deploy/production/deployment.yaml | kubectl apply -f -
kubectl apply -f deploy/production/service.yaml

if [[ -f deploy/production/ingress.yaml ]]; then
  kubectl apply -f deploy/production/ingress.yaml
fi

kubectl -n "${NAMESPACE}" rollout status "deployment/${DEPLOYMENT_NAME}" --timeout=180s
kubectl -n "${NAMESPACE}" get endpoints "${SERVICE_NAME}"

kubectl -n "${NAMESPACE}" port-forward "service/${SERVICE_NAME}" "${LOCAL_PORT}:8000" >/tmp/facilitator-port-forward.log 2>&1 &
PORT_FORWARD_PID=$!
trap 'kill ${PORT_FORWARD_PID} >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:${LOCAL_PORT}/healthz" >/tmp/facilitator-health.json; then
    break
  fi
  sleep 1
done

curl -fsS "http://127.0.0.1:${LOCAL_PORT}/supported" >/tmp/facilitator-supported.json
curl -fsS "http://127.0.0.1:${LOCAL_PORT}/.well-known/x402" >/tmp/facilitator-well-known.json

python3 - <<'PY'
import json
from pathlib import Path

health = json.loads(Path("/tmp/facilitator-health.json").read_text())
supported = json.loads(Path("/tmp/facilitator-supported.json").read_text())
well_known = json.loads(Path("/tmp/facilitator-well-known.json").read_text())

assert health.get("status") == "ok", health
assert isinstance(supported.get("kinds"), list) and supported["kinds"], supported
assert well_known.get("facilitator", {}).get("endpoints", {}).get("verify"), well_known

print("Facilitator smoke checks passed.")
PY
