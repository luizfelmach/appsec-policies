{{- define "appsec-policies.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end }}

{{- define "appsec-policies.validate" -}}
{{- $policyNames := dict -}}
{{- $policyHosts := dict -}}
{{- $generatedNames := dict -}}
{{- range $policy := .Values.policies -}}
  {{- if hasKey $policyNames $policy.name }}{{ fail (printf "duplicate policy name %q" $policy.name) }}{{ end -}}
  {{- $_ := set $policyNames $policy.name true -}}
  {{- if hasKey $policyHosts $policy.host }}{{ fail (printf "duplicate policy host %q" $policy.host) }}{{ end -}}
  {{- $_ := set $policyHosts $policy.host true -}}
  {{- range $suffix := list "trigger" "custom-response" "threat-prevention" "access-control" "source-identifier" "trusted-source" -}}
    {{- $name := printf "%s-%s" $policy.name $suffix -}}
    {{- if or (gt (len $name) 63) (not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $name)) }}{{ fail (printf "generated resource name %q for policy %q is not a valid Kubernetes name" $name $policy.name) }}{{ end -}}
    {{- if hasKey $generatedNames $name }}{{ fail (printf "duplicate generated resource name %q" $name) }}{{ end -}}
    {{- $_ := set $generatedNames $name true -}}
  {{- end -}}
  {{- $exceptionNames := dict -}}
  {{- $exceptionHosts := dict -}}
  {{- range $exception := default (list) $policy.exceptions -}}
    {{- if hasKey $exceptionNames $exception.name }}{{ fail (printf "duplicate exception name %q in policy %q" $exception.name $policy.name) }}{{ end -}}
    {{- $_ := set $exceptionNames $exception.name true -}}
    {{- if hasKey $exceptionHosts $exception.host }}{{ fail (printf "duplicate exception host %q in policy %q" $exception.host $policy.name) }}{{ end -}}
    {{- $_ := set $exceptionHosts $exception.host true -}}
    {{- if not (or (eq $exception.host $policy.host) (hasPrefix (printf "%s/" $policy.host) $exception.host)) }}{{ fail (printf "exception %q host %q must belong to policy host %q" $exception.name $exception.host $policy.host) }}{{ end -}}
    {{- $resourceName := printf "%s-%s" $policy.name $exception.name -}}
    {{- if gt (len $resourceName) 63 }}{{ fail (printf "generated exception name %q exceeds 63 characters" $resourceName) }}{{ end -}}
    {{- $hasSourceIp := false -}}
    {{- $hasCountry := false -}}
    {{- $hasSkipKey := false -}}
    {{- range $condition := $exception.conditions -}}
      {{- if eq $condition.key "sourceIp" }}{{ $hasSourceIp = true }}{{ end -}}
      {{- if or (eq $condition.key "countryCode") (eq $condition.key "countryName") }}{{ $hasCountry = true }}{{ end -}}
      {{- if or (eq $condition.key "paramName") (eq $condition.key "paramValue") (eq $condition.key "indicator") }}{{ $hasSkipKey = true }}{{ end -}}
      {{- if and (eq $exception.action "drop") (or (eq $condition.key "paramName") (eq $condition.key "paramValue")) }}{{ fail (printf "exception %q: drop does not support paramName or paramValue" $exception.name) }}{{ end -}}
    {{- end -}}
    {{- if and $hasSourceIp (gt (len $exception.conditions) 1) }}{{ fail (printf "exception %q: sourceIp cannot be combined with other conditions" $exception.name) }}{{ end -}}
    {{- if and $hasCountry (gt (len $exception.conditions) 1) }}{{ fail (printf "exception %q: country conditions cannot be combined with other conditions" $exception.name) }}{{ end -}}
    {{- if and (eq $exception.action "skip") (not $hasSkipKey) }}{{ fail (printf "exception %q: skip requires paramName, paramValue, or indicator" $exception.name) }}{{ end -}}
  {{- end -}}
{{- end -}}
{{- end }}
