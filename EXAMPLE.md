# End-to-End Tests

The E2E suite deploys the chart to a local Kind cluster with Kong, open-appsec, and an
HTTP echo application. Independent Bats tests validate each policy host.

## Requirements

- Docker
- Kind
- Helm 3
- kubectl
- curl
- Bats

Run all commands from the repository root.

## Run

```bash
./e2e/run.sh
```

The script creates or reuses the `appsec-e2e` Kind cluster, installs all dependencies,
deploys the test application and policies, then runs Bats. The cluster remains available
after the run for diagnostics.

Hosts under `localtest.me` resolve to `127.0.0.1`; no hosts file change is required.
Current scenarios use separate hosts:

- `prevent.localtest.me` validates normal traffic and XSS prevention.
- `rate-limit.localtest.me` validates rate limiting without sharing traffic with prevent.

Run only tests against an already provisioned cluster:

```bash
bats e2e/tests
```

## Inspect Resources

```bash
kubectl get policy,policyactivation
kubectl get threatpreventionpractice,accesscontrolpractice
kubectl get logtrigger,customresponse,sourcesidentifier,trustedsource
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
kind delete cluster --name appsec-e2e
```
