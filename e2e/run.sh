#!/usr/bin/env bash

set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly E2E_DIR="$ROOT_DIR/e2e"
readonly CLUSTER_NAME="appsec-e2e"
readonly APPSEC_NAMESPACE="appsec-kong"

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'Required command not found: %s\n' "$1" >&2
    exit 1
  fi
}

for command in docker kind helm kubectl curl bats; do
  require "$command"
done

if ! kind get clusters | grep -Fxq "$CLUSTER_NAME"; then
  kind create cluster --name "$CLUSTER_NAME" --config "$E2E_DIR/kind.yaml"
fi

kubectl config use-context "kind-$CLUSTER_NAME" >/dev/null

helm repo add openappsec https://charts.openappsec.io --force-update
helm repo update openappsec

helm upgrade --install appsec-kong openappsec/open-appsec-kong \
  --namespace "$APPSEC_NAMESPACE" \
  --create-namespace \
  --values "$E2E_DIR/appsec.values.yaml" \
  --wait \
  --timeout 10m

kubectl apply --filename "$E2E_DIR/manifests/namespace.yaml"
kubectl apply \
  --filename "$E2E_DIR/manifests/echo.yaml" \
  --filename "$E2E_DIR/manifests/ingress.yaml"
kubectl --namespace appsec-e2e wait \
  --for=condition=Available deployment/echo \
  --timeout=2m

helm upgrade --install appsec-policies "$ROOT_DIR/charts/appsec-policies" \
  --values "$E2E_DIR/policies.values.yaml" \
  --wait \
  --timeout 2m

printf 'Waiting for prevent policy to load...\n'
for _ in $(seq 1 60); do
  status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --max-time 2 --noproxy '*' \
    'http://prevent.localtest.me/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E' || true)
  if [[ "$status" == "403" ]]; then
    break
  fi
  sleep 2
done

if [[ "$status" != "403" ]]; then
  printf 'Prevent policy did not load before timeout. Last status: %s\n' "$status" >&2
  exit 1
fi

bats "$E2E_DIR/tests"
