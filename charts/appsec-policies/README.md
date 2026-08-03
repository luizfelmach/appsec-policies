# appsec-policies

Helm chart for generating open-appsec `v1beta2` policies and their supporting resources.

## Installation

```bash
helm repo add appsec-policies \
  https://luizfelmach.github.io/appsec-policies
helm repo update

helm upgrade --install appsec-policies appsec-policies/appsec-policies \
  --values my-values.yaml
```

## Values

### Top-level values

| Value | Type | Description |
| --- | --- | --- |
| `appsecClassName` | string | Optional open-appsec class assigned to every generated resource. |
| `installCRDs` | boolean | Install required open-appsec CRDs. Defaults to `true`. |
| `defaults` | object | Base specifications for supporting resources. |
| `policies` | array | Hosts and policy-specific overrides. |

Set `installCRDs: false` when the CRDs are managed by another release or deployment
process.

### Resource defaults

The chart defines one default specification for each resource type:

```yaml
defaults:
  trigger: {}
  customResponse: {}
  threatPrevention: {}
  accessControl: {}
  sourceIdentifier: {}
  trustedSource: {}
```

Built-in values contain complete defaults. User values only need to define fields that
must differ. For example:

```yaml
defaults:
  threatPrevention:
    webAttacks:
      minimumConfidence: high
  customResponse:
    httpResponseCode: 403
```

### Policies

| Field | Required | Description |
| --- | --- | --- |
| `name` | yes | Policy and generated resource name prefix. |
| `host` | yes | Host protected by the policy, without URL scheme. |
| `mode` | yes | `prevent-learn`, `detect-learn`, `prevent`, `detect`, or `inactive`. |
| `trigger` | no | Override for the default log trigger specification. |
| `customResponse` | no | Override for the default custom response specification. |
| `threatPrevention` | no | Override for the default threat prevention specification. |
| `accessControl` | no | Override for the default access control specification. |
| `sourceIdentifier` | no | Override for the default source identifier specification. |
| `trustedSource` | no | Override for the default trusted source specification. |
| `exceptions` | no | Exception rules attached to the policy. |

Minimal policy:

```yaml
policies:
  - name: example
    host: example.com
    mode: prevent-learn
```

## Merge Behavior

Every supporting resource is created by recursively merging its default specification
with the matching policy override. Policy values take precedence.

- Maps merge recursively.
- Scalars replace default scalars.
- Arrays replace default arrays; they are not concatenated.
- Resource names cannot be overridden.
- `trustedSource.sourcesIdentifiers` is managed by the chart and points to the policy's
  generated `SourcesIdentifier`.

Example:

```yaml
policies:
  - name: example
    host: example.com
    mode: prevent
    trigger:
      extendedLogging:
        requestBody: true
```

Only `requestBody` changes. Other trigger fields remain inherited from
`defaults.trigger`.

## Exceptions

```yaml
policies:
  - name: example
    host: example.com
    mode: prevent
    exceptions:
      - name: allow-health
        host: example.com/health
        action: accept
        conditions:
          - key: url
            value: /health
```

Supported actions are `accept`, `drop`, `skip`, and `suppressLog`. Exception hosts must
belong to the policy host. Each exception creates an `Exception` resource and a matching
policy `specificRule`.

## Generated Resources

Each policy creates:

- `Policy`
- `PolicyActivation`
- `LogTrigger`
- `CustomResponse`
- `ThreatPreventionPractice`
- `AccessControlPractice`
- `SourcesIdentifier`
- `TrustedSource`
- One `Exception` per configured exception

Supporting resource names use `<policy-name>-<resource-type>`. Policy activation includes
both `http://<host>` and `https://<host>`.

## Validation

```bash
helm lint . --values my-values.yaml
helm template appsec-policies . --values my-values.yaml
```
