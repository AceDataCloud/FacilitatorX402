#!/usr/bin/env bash

set -euo pipefail

TAG="${BUILD_NUMBER:-latest}"
PREFLIGHT_JOB="facilitator-preflight-$TAG-${GITHUB_RUN_ATTEMPT:-1}"
MIGRATION_JOB="facilitator-migrate-$TAG-${GITHUB_RUN_ATTEMPT:-1}"
RECONCILE_SMOKE_JOB="facilitator-reconcile-smoke-$TAG-${GITHUB_RUN_ATTEMPT:-1}"
SNAPSHOT_DIR="$(mktemp -d)"
ORIGINAL_DEPLOYMENT_FILE="$SNAPSHOT_DIR/deployment.json"
ORIGINAL_SPEC_FILE="$SNAPSHOT_DIR/spec.json"
ORIGINAL_CRONJOB_FILE="$SNAPSHOT_DIR/reconciliation-cronjob.json"
CUTOVER_COMPLETE=0
QUIESCE_STARTED=0
ORIGINAL_CRONJOB_EXISTS=0

snapshot_cronjob() {
	local raw="$ORIGINAL_CRONJOB_FILE.raw"
	if ! kubectl get cronjob/facilitator-reconcile -n acedatacloud --ignore-not-found -o json >"$raw"; then
		rm -f "$raw"
		return 1
	fi
	if [ ! -s "$raw" ]; then
		rm -f "$raw"
		return 0
	fi
	jq -e 'del(.status,.metadata.creationTimestamp,.metadata.generation,.metadata.managedFields,.metadata.resourceVersion,.metadata.uid)' \
		<"$raw" >"$ORIGINAL_CRONJOB_FILE"
	rm -f "$raw"
	ORIGINAL_CRONJOB_EXISTS=1
}

rollback() {
	set +e
	rollback_failed=0
	kubectl patch deployment/facilitator-backend -n acedatacloud --type=merge --patch-file="$ORIGINAL_SPEC_FILE" || rollback_failed=1
	if [ "$ORIGINAL_CRONJOB_EXISTS" -eq 1 ]; then
		kubectl apply -f "$ORIGINAL_CRONJOB_FILE" || rollback_failed=1
	else
		kubectl delete cronjob/facilitator-reconcile -n acedatacloud --ignore-not-found || rollback_failed=1
	fi
	if [ "$ORIGINAL_REPLICAS" -gt 0 ]; then
		kubectl rollout status deployment/facilitator-backend -n acedatacloud --timeout=600s || rollback_failed=1
	fi
	return "$rollback_failed"
}

on_exit() {
	exit_code=$?
	trap - EXIT
	kubectl delete job "$PREFLIGHT_JOB" "$MIGRATION_JOB" "$RECONCILE_SMOKE_JOB" \
		-n acedatacloud --ignore-not-found >/dev/null 2>&1 || true
	if [ "$QUIESCE_STARTED" -eq 1 ] && [ "$CUTOVER_COMPLETE" -ne 1 ] && ! rollback; then
		exit_code=1
	fi
	rm -rf "$SNAPSHOT_DIR"
	exit "$exit_code"
}
trap on_exit EXIT

kubectl get deployment/facilitator-backend -n acedatacloud -o json >"$ORIGINAL_DEPLOYMENT_FILE"
ORIGINAL_REPLICAS="$(jq -er '.spec.replicas' "$ORIGINAL_DEPLOYMENT_FILE")"
jq -e '{spec: .spec}' "$ORIGINAL_DEPLOYMENT_FILE" >"$ORIGINAL_SPEC_FILE"
snapshot_cronjob

# Freeze legacy verify traffic before checking for unsettled authorizations.
# The Gateway x402 feature flag must already be disabled per the cutover runbook.
QUIESCE_STARTED=1
kubectl scale deployment/facilitator-backend -n acedatacloud --replicas=0
PODS="$(kubectl get pod -l app=facilitator-backend -n acedatacloud -o name)"
if [ -n "$PODS" ]; then
	kubectl wait --for=delete pod -l app=facilitator-backend -n acedatacloud --timeout=300s
fi

# shellcheck disable=SC2016
sed -e 's/\${TAG}/'"$TAG"'/g' -e 's/\${PREFLIGHT_JOB}/'"$PREFLIGHT_JOB"'/g' \
	deploy/production/preflight-job.yaml | kubectl apply -f -
if ! kubectl wait --for=condition=complete "job/$PREFLIGHT_JOB" -n acedatacloud --timeout=300s; then
	kubectl logs "job/$PREFLIGHT_JOB" -n acedatacloud
	exit 1
fi

# shellcheck disable=SC2016
sed -e 's/\${TAG}/'"$TAG"'/g' -e 's/\${MIGRATION_JOB}/'"$MIGRATION_JOB"'/g' \
	deploy/production/migration-job.yaml | kubectl apply -f -
if ! kubectl wait --for=condition=complete "job/$MIGRATION_JOB" -n acedatacloud --timeout=300s; then
	kubectl logs "job/$MIGRATION_JOB" -n acedatacloud
	exit 1
fi

# shellcheck disable=SC2016
sed 's/\${TAG}/'"$TAG"'/g' deploy/production/deployment.yaml | kubectl apply -f -

kubectl apply -f deploy/production/service.yaml
kubectl rollout status deployment/facilitator-backend -n acedatacloud --timeout=600s

# shellcheck disable=SC2016
sed 's/\${TAG}/'"$TAG"'/g' deploy/production/reconciliation-cronjob.yaml | kubectl apply -f -
kubectl delete job "$RECONCILE_SMOKE_JOB" -n acedatacloud --ignore-not-found >/dev/null
kubectl create job "$RECONCILE_SMOKE_JOB" -n acedatacloud --from=cronjob/facilitator-reconcile
if ! kubectl wait --for=condition=complete "job/$RECONCILE_SMOKE_JOB" -n acedatacloud --timeout=120s; then
	kubectl logs "job/$RECONCILE_SMOKE_JOB" -n acedatacloud
	exit 1
fi
kubectl logs "job/$RECONCILE_SMOKE_JOB" -n acedatacloud
kubectl delete job "$RECONCILE_SMOKE_JOB" -n acedatacloud --ignore-not-found >/dev/null
CUTOVER_COMPLETE=1
