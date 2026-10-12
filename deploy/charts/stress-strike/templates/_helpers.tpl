{{- define "stress-strike.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "stress-strike.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" (include "stress-strike.name" .) .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
Common labels shared by every stress-strike resource. Kept separate from the
per-component selector labels so a `helm upgrade` never churns the immutable
Deployment/service selectors.
*/}}
{{- define "stress-strike.commonLabels" -}}
app.kubernetes.io/name: {{ include "stress-strike.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{/* Immutable selector labels — one set per component. */}}
{{- define "stress-strike.master.selectorLabels" -}}
app.kubernetes.io/name: {{ include "stress-strike.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: master
{{- end -}}
{{- define "stress-strike.worker.selectorLabels" -}}
app.kubernetes.io/name: {{ include "stress-strike.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: worker
{{- end -}}

{{/*
Master gRPC service name. Workers self-register against this DNS name, so it is
derived from the release instead of being hard-coded.
*/}}
{{- define "stress-strike.master.serviceName" -}}
{{- printf "%s-master" (include "stress-strike.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Shared control-plane token injection: when auth.tokenSecret.name is set, the
token is exposed to the container as $SS_TOKEN and referenced from args as
$(SS_TOKEN) — Kubernetes expands $(VAR) in args, so the secret value never
appears in the manifest. Renders nothing when no Secret is configured.

Usage: {{- include "stress-strike.tokenEnv" . | nindent 12 }}
*/}}
{{- define "stress-strike.tokenEnv" -}}
{{- with .Values.auth }}
{{- with .tokenSecret }}
{{- if .name }}
- name: SS_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ .name }}
      key: {{ default "token" .key }}
{{- end }}
{{- end }}
{{- end }}
{{- end -}}
