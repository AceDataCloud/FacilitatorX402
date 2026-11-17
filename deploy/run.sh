#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

: "${TAG:?TAG is required}"
: "${KUBE_CONTEXT:?KUBE_CONTEXT is required}"
rendered=$(mktemp -d)
trap 'rm -rf "$rendered"' EXIT
for manifest in deployment.yaml reconciliation-cronjob.yaml; do
  python3 deploy/render.py "deploy/production/$manifest" > "$rendered/$manifest"
done
cp deploy/production/service.yaml "$rendered/service.yaml"
kubectl --context "$KUBE_CONTEXT" apply -f "$rendered"
