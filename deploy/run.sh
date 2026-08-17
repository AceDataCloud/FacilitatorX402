#!/bin/sh
set -eu

: "${TAG:?TAG is required}"

sed 's/\${TAG}/'"$TAG"'/g' deploy/production/deployment.yaml | kubectl apply -f -
kubectl apply -f deploy/production/service.yaml
sed 's/\${TAG}/'"$TAG"'/g' deploy/production/reconciliation-cronjob.yaml | kubectl apply -f -
sed 's/\${TAG}/'"$TAG"'/g' deploy/production/bazaar-cronjob.yaml | kubectl apply -f -
