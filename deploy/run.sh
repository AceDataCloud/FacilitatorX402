cat deploy/production/deployment.yaml | sed 's/\${TAG}/'"${BUILD_NUMBER:-latest}"'/g' | kubectl apply -f -

cat deploy/production/service.yaml | kubectl apply -f -
