# Local Example

This example deploys the chart to a local Kind cluster with Kong, open-appsec, and an
HTTP echo application. It validates threat prevention and exception behavior through
the included test script.

## Requirements

- Docker
- Kind
- Helm 3
- kubectl
- curl

Run all commands from the repository root.

## Create the Cluster

```bash
kind create cluster --name appsec-lab --config hack/kind.yaml
```

The Kind configuration maps host ports `80` and `443` to the Kong NodePorts used by
the example.

## Install Kong and open-appsec

```bash
helm repo add openappsec https://charts.openappsec.io
helm repo update

helm upgrade --install appsec-kong openappsec/open-appsec-kong \
  --namespace appsec-kong \
  --create-namespace \
  --values hack/appsec.values.yaml

kubectl --namespace appsec-kong wait \
  --for=condition=Available deployment \
  --selector app.kubernetes.io/instance=appsec-kong \
  --timeout=600s
```

## Deploy the Example

Install the echo application and ingress:

```bash
kubectl apply --filename hack/echo/
kubectl --namespace lab wait \
  --for=condition=Available deployment/echo \
  --timeout=120s
```

Install the CRDs and policies from `hack/echo.values.yaml`:

```bash
helm upgrade --install appsec-policies ./charts/appsec-policies \
  --values hack/echo.values.yaml
```

Wait until the open-appsec agent reports that the policy was loaded:

```bash
kubectl --namespace appsec-kong logs \
  deployment/appsec-kong-open-appsec-kong \
  --container open-appsec \
  --follow | grep --max-count=1 'Web AppSec Policy Loaded Successfully'
```

## Run the Tests

`echo.localtest.me` resolves to `127.0.0.1`; no hosts file change is required.

```bash
bash scripts/test-exceptions.sh
```

The script checks normal traffic, XSS prevention, every configured exception action,
and rate-limit enforcement on `/rate`. It exits with a non-zero status when any scenario
fails.

## Inspect Resources

```bash
kubectl get policy,policyactivation
kubectl get threatpreventionpractice,accesscontrolpractice
kubectl get logtrigger,customresponse,sourcesidentifier,trustedsource
kubectl get exception
```

Inspect recent agent logs:

```bash
kubectl --namespace appsec-kong logs \
  deployment/appsec-kong-open-appsec-kong \
  --container open-appsec \
  --tail=100
```

## Cleanup

```bash
helm uninstall appsec-policies
helm uninstall appsec-kong --namespace appsec-kong
kind delete cluster --name appsec-lab
```
