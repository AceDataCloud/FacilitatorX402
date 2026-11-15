#!/bin/sh
set -eu

: "${TAG:?TAG is required}"
python3 deploy/render.py --check-config >/dev/null

# Write before piping: a failed renderer must never be hidden by kubectl's exit code.
RENDER_DIR="$(mktemp -d)"
trap 'rm -rf "$RENDER_DIR"' EXIT
python3 deploy/render.py deploy/production/deployment.yaml >"$RENDER_DIR/deployment.yaml"
python3 deploy/render.py deploy/production/reconciliation-cronjob.yaml >"$RENDER_DIR/reconciliation-cronjob.yaml"
kubectl apply -f "$RENDER_DIR/deployment.yaml"
kubectl apply -f deploy/production/service.yaml
kubectl apply -f "$RENDER_DIR/reconciliation-cronjob.yaml"
