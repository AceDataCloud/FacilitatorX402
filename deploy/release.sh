#!/usr/bin/env bash

set -euo pipefail
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

: "${BUILD_NUMBER:?BUILD_NUMBER is required}"
: "${KUBE_CONTEXT:?KUBE_CONTEXT is required}"
export KUBE_CONTEXT
kubectl() { command kubectl --context "$KUBE_CONTEXT" "$@"; }

TAG="$BUILD_NUMBER"
export TAG
RELEASE_MODE="$(python3 deploy/render.py --check-config)"
PREFLIGHT_JOB="facilitator-preflight-$TAG-${GITHUB_RUN_ATTEMPT:-1}"
MIGRATION_JOB="facilitator-migrate-$TAG-${GITHUB_RUN_ATTEMPT:-1}"
SNAPSHOT_DIR="$(mktemp -d)"
ORIGINAL_DEPLOYMENT_FILE="$SNAPSHOT_DIR/deployment.json"
ORIGINAL_SPEC_FILE="$SNAPSHOT_DIR/spec.json"
ORIGINAL_CRONJOB_FILE="$SNAPSHOT_DIR/reconciliation-cronjob.json"
CUTOVER_COMPLETE=0
QUIESCE_STARTED=0
ORIGINAL_CRONJOB_EXISTS=0
TEMPORARY_JOBS=()

rollback() {
	set +e
	rollback_failed=0
	kubectl patch deployment/facilitator-backend -n acedatacloud --type=merge --patch-file="$ORIGINAL_SPEC_FILE" || rollback_failed=1
	if [ "$ORIGINAL_CRONJOB_EXISTS" -eq 1 ]; then
		kubectl apply -f "$ORIGINAL_CRONJOB_FILE" || rollback_failed=1
	else
		kubectl delete cronjob/facilitator-reconcile -n acedatacloud --ignore-not-found || rollback_failed=1
	fi
	return "$rollback_failed"
}

on_exit() {
	exit_code=$?
	trap - EXIT
	if [ "${#TEMPORARY_JOBS[@]}" -gt 0 ]; then
		kubectl delete job "${TEMPORARY_JOBS[@]}" \
			-n acedatacloud --ignore-not-found >/dev/null 2>&1 || true
	fi
	if [ "$QUIESCE_STARTED" -eq 1 ] && [ "$CUTOVER_COMPLETE" -ne 1 ] && ! rollback; then
		exit_code=1
	fi
	rm -rf "$SNAPSHOT_DIR"
	exit "$exit_code"
}
trap on_exit EXIT

kubectl get deployment/facilitator-backend -n acedatacloud -o json >"$ORIGINAL_DEPLOYMENT_FILE"
# Rollback preserves the previous image/configuration while keeping funds stopped.
jq -e '{spec: (.spec | .replicas = 0 |
  .template.spec.containers[].env |= map(select(.name | endswith("_SIGNER_PRIVATE_KEY") | not) |
    if (.name | endswith("_ENABLED")) then del(.valueFrom) | .value = "false" else . end))}' \
	"$ORIGINAL_DEPLOYMENT_FILE" >"$ORIGINAL_SPEC_FILE"
kubectl get cronjob/facilitator-reconcile -n acedatacloud --ignore-not-found -o json >"$ORIGINAL_CRONJOB_FILE"
if [ -s "$ORIGINAL_CRONJOB_FILE" ]; then
	jq -e 'del(.status,.metadata.creationTimestamp,.metadata.generation,.metadata.managedFields,.metadata.resourceVersion,.metadata.uid) |
	  .spec.suspend = true |
	  .spec.jobTemplate.spec.template.spec.containers[].env |=
	    map(select(.name | endswith("_SIGNER_PRIVATE_KEY") | not) |
	      if (.name | endswith("_ENABLED")) then del(.valueFrom) | .value = "false" else . end)' \
		"$ORIGINAL_CRONJOB_FILE" >"$ORIGINAL_CRONJOB_FILE.paused"
	mv "$ORIGINAL_CRONJOB_FILE.paused" "$ORIGINAL_CRONJOB_FILE"
	ORIGINAL_CRONJOB_EXISTS=1
fi
# Both staging and restoration first stop web traffic and reconciliation.
# The Gateway x402 feature flag must already be disabled for restoration.
QUIESCE_STARTED=1
if [ "$ORIGINAL_CRONJOB_EXISTS" -eq 1 ]; then
	kubectl patch cronjob/facilitator-reconcile -n acedatacloud --type=merge -p '{"spec":{"suspend":true}}'
fi
kubectl scale deployment/facilitator-backend -n acedatacloud --replicas=0
PODS="$(kubectl get pod -l app=facilitator-backend -n acedatacloud -o name)"
if [ -n "$PODS" ]; then
	kubectl wait --for=delete pod -l app=facilitator-backend -n acedatacloud --timeout=300s
fi
if [ "$RELEASE_MODE" = paused ]; then
	if [ -n "$(kubectl get pod -l app=facilitator-reconcile -n acedatacloud \
		--field-selector=status.phase!=Succeeded,status.phase!=Failed -o name)" ]; then
		echo "Stop existing reconciliation Jobs before staging a paused release" >&2
		exit 1
	fi
	TAG="$TAG" sh deploy/run.sh
	# No database access, preflight, migration, reconciler or health request in staging.
	CUTOVER_COMPLETE=1
	exit 0
fi
TEMPORARY_JOBS+=("$PREFLIGHT_JOB")
# shellcheck disable=SC2016
sed -e 's/\${TAG}/'"$TAG"'/g' -e 's/\${PREFLIGHT_JOB}/'"$PREFLIGHT_JOB"'/g' \
	deploy/production/preflight-job.yaml | kubectl apply -f -
if ! kubectl wait --for=condition=complete "job/$PREFLIGHT_JOB" -n acedatacloud --timeout=300s; then
	kubectl logs "job/$PREFLIGHT_JOB" -n acedatacloud
	exit 1
fi

TEMPORARY_JOBS+=("$MIGRATION_JOB")
# shellcheck disable=SC2016
sed -e 's/\${TAG}/'"$TAG"'/g' -e 's/\${MIGRATION_JOB}/'"$MIGRATION_JOB"'/g' \
	deploy/production/migration-job.yaml | kubectl apply -f -
if ! kubectl wait --for=condition=complete "job/$MIGRATION_JOB" -n acedatacloud --timeout=300s; then
	kubectl logs "job/$MIGRATION_JOB" -n acedatacloud
	exit 1
fi

TAG="$TAG" sh deploy/run.sh
kubectl rollout status deployment/facilitator-backend -n acedatacloud --timeout=600s

# Restoring web payment rails does not authorize replaying historical settlements.
# Reconciliation remains suspended and requires a separate operator action.
curl --fail --retry 5 --retry-delay 2 --connect-timeout 5 --max-time 15 https://facilitator.acedata.cloud/.well-known/x402 \
	| jq -e '.facilitator.endpoints.verify | endswith("/verify")' >/dev/null
CUTOVER_COMPLETE=1
