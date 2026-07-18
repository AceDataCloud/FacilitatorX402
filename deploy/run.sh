set -eu

TAG="${BUILD_NUMBER:-latest}"
MIGRATION_JOB="facilitator-migrate-$TAG-${GITHUB_RUN_ATTEMPT:-1}"

sed -e 's/\${TAG}/'"$TAG"'/g' -e 's/\${MIGRATION_JOB}/'"$MIGRATION_JOB"'/g' \
	deploy/production/migration-job.yaml | kubectl apply -f -
if ! kubectl wait --for=condition=complete "job/$MIGRATION_JOB" -n acedatacloud --timeout=300s; then
	kubectl logs "job/$MIGRATION_JOB" -n acedatacloud
	exit 1
fi

sed 's/\${TAG}/'"$TAG"'/g' deploy/production/deployment.yaml | kubectl apply -f -

kubectl apply -f deploy/production/service.yaml
