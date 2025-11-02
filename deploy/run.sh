#!/usr/bin/env bash
set -euo pipefail

cat deploy/production/deployment.yaml | sed 's/\${TAG}/'"${BUILD_NUMBER:-latest}"'/g' | kubectl apply -f - || true
cat deploy/production/service.yaml | kubectl apply -f - || true
