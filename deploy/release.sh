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
ORIGINAL_BAZAAR_CRONJOB_FILE="$SNAPSHOT_DIR/bazaar-cronjob.json"
CUTOVER_COMPLETE=0
QUIESCE_STARTED=0
ORIGINAL_CRONJOB_EXISTS=0
ORIGINAL_BAZAAR_CRONJOB_EXISTS=0

snapshot_cronjob() {
	local name="$1"
	local output="$2"
	local raw="$output.raw"
	if ! kubectl get "cronjob/$name" -n acedatacloud --ignore-not-found -o json >"$raw"; then
		rm -f "$raw"
		return 1
	fi
	if [ ! -s "$raw" ]; then
		rm -f "$raw"
		return 2
	fi
	jq -e 'del(.status,.metadata.creationTimestamp,.metadata.generation,.metadata.managedFields,.metadata.resourceVersion,.metadata.uid)' \
		<"$raw" >"$output"
	rm -f "$raw"
}

rollback() {
	set +e
	rollback_failed=0
	if [ "$ORIGINAL_BAZAAR_CRONJOB_EXISTS" -eq 1 ]; then
		kubectl apply -f "$ORIGINAL_BAZAAR_CRONJOB_FILE" || rollback_failed=1
	else
		kubectl delete cronjob/facilitator-bazaar-refresh -n acedatacloud --ignore-not-found || rollback_failed=1
	fi
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
if snapshot_cronjob facilitator-reconcile "$ORIGINAL_CRONJOB_FILE"; then
	ORIGINAL_CRONJOB_EXISTS=1
elif [ "$?" -ne 2 ]; then
	exit 1
fi
if snapshot_cronjob facilitator-bazaar-refresh "$ORIGINAL_BAZAAR_CRONJOB_FILE"; then
	ORIGINAL_BAZAAR_CRONJOB_EXISTS=1
elif [ "$?" -ne 2 ]; then
	exit 1
fi

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

TAG="$TAG" sh deploy/run.sh
kubectl rollout status deployment/facilitator-backend -n acedatacloud --timeout=600s

kubectl delete job "$RECONCILE_SMOKE_JOB" -n acedatacloud --ignore-not-found >/dev/null
kubectl create job "$RECONCILE_SMOKE_JOB" -n acedatacloud --from=cronjob/facilitator-reconcile
if ! kubectl wait --for=condition=complete "job/$RECONCILE_SMOKE_JOB" -n acedatacloud --timeout=120s; then
	kubectl logs "job/$RECONCILE_SMOKE_JOB" -n acedatacloud
	exit 1
fi
kubectl logs "job/$RECONCILE_SMOKE_JOB" -n acedatacloud
kubectl delete job "$RECONCILE_SMOKE_JOB" -n acedatacloud --ignore-not-found >/dev/null

kubectl patch cronjob/facilitator-bazaar-refresh -n acedatacloud --type=merge \
	-p '{"spec":{"suspend":true}}' --ignore-not-found >/dev/null 2>&1 || true
kubectl delete cronjob/facilitator-bazaar-refresh -n acedatacloud \
	--ignore-not-found --cascade=foreground --timeout=120s --wait=true
BAZAAR_JOBS="$(kubectl get jobs -n acedatacloud -o json | jq -r '.items[] | select(any(.metadata.ownerReferences[]?; .kind == "CronJob" and .name == "facilitator-bazaar-refresh")) | .metadata.name')"
if [ -n "$BAZAAR_JOBS" ]; then
	# shellcheck disable=SC2086
	kubectl delete job -n acedatacloud $BAZAAR_JOBS --ignore-not-found --timeout=120s --wait=true
fi
curl --fail --retry 5 --retry-delay 2 --connect-timeout 5 --max-time 15 https://facilitator.acedata.cloud/.well-known/x402 \
	| jq -e '.facilitator.endpoints.verify | endswith("/verify")' >/dev/null
for path in discovery/resources list; do
	status="$(curl --silent --show-error --connect-timeout 5 --max-time 15 --output /tmp/facilitator-retirement.json \
		--write-out '%{http_code}' "https://facilitator.acedata.cloud/$path")"
	[ "$status" = "410" ]
	jq -e '.code == "resource_discovery_retired"' /tmp/facilitator-retirement.json >/dev/null
done
CUTOVER_COMPLETE=1
