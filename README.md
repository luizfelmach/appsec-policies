# appsec-policies

Helm chart for declaring open-appsec policies and attaching them to application hosts.
Each policy receives its own security resources, generated from chart defaults and
optional per-policy overrides.

## Features

- Creates one `Policy` and `PolicyActivation` per host.
- Creates dedicated threat prevention, access control, logging, response, and source resources.
- Installs the required open-appsec CRDs by default.
- Deep-merges per-policy overrides onto reusable defaults.
- Supports rate limiting and `accept`, `drop`, `skip`, and `suppressLog` exceptions.
- Validates values through a JSON schema before rendering resources.

## Requirements

- Kubernetes
- Helm 3
- An open-appsec agent or controller

## Installation

Create a values file with at least one policy:

```yaml
policies:
  - name: example
    host: example.com
    mode: prevent-learn
```

Add the chart repository and install the chart:

```bash
helm repo add appsec-policies \
  https://luizfelmach.github.io/appsec-policies
helm repo update

helm upgrade --install appsec-policies appsec-policies/appsec-policies \
  --values my-values.yaml
```

The built-in defaults provide complete specifications for all supporting resources.
Override only values that differ for a policy:

```yaml
policies:
  - name: api
    host: api.example.com
    mode: prevent
    threatPrevention:
      webAttacks:
        minimumConfidence: high
    accessControl:
      rateLimit:
        overrideMode: prevent
        rules:
          - action: inherited
            uri: /
            limit: 100
            unit: minute
```

## Configuration

`defaults` contains the base specification for each supporting resource. Fields under
`policies[]` override the corresponding default. Maps merge recursively; scalar values
and arrays from a policy replace their default values.

The chart installs its CRDs when `installCRDs` is `true`, which is the default. Set it
to `false` when CRDs are managed separately.

Generated resources use deterministic names such as `api-threat-prevention` and
`api-access-control`. `TrustedSource` automatically references the generated
`SourcesIdentifier` for the same policy.

See [`charts/appsec-policies/README.md`](charts/appsec-policies/README.md) for
the complete values interface and merge behavior.

## Validation

```bash
helm lint ./charts/appsec-policies --values my-values.yaml
helm template appsec-policies ./charts/appsec-policies \
  --values my-values.yaml
```

## Releases

Pushes to `main` release changed charts through GitHub Actions. Before publishing a new
chart release, increment `version` in `charts/appsec-policies/Chart.yaml`. The
workflow creates a GitHub Release and updates the Helm repository index on `gh-pages`.

## Local Example

See [`EXAMPLE.md`](EXAMPLE.md) for a complete local deployment using Kind, Kong,
open-appsec, and the included automated test script.

## Uninstall

```bash
helm uninstall appsec-policies
```
