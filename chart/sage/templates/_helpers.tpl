{{- define "sage.fullname" -}}
{{- printf "%s" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "sage.labels" -}}
app.kubernetes.io/name: sage
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "sage.image" -}}
{{- $repo := required "image.repository è obbligatorio" .Values.image.repository -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $repo .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repo (required "imposta image.digest (consigliato) oppure image.tag" .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/* Controlli bloccanti: niente installazione con configurazione incompleta. */}}
{{- define "sage.validate" -}}
{{- $_ := required "config.ssh.user è obbligatorio" .Values.config.ssh.user -}}
{{- $_ := required "secrets.ssh è obbligatorio" .Values.secrets.ssh -}}
{{- if not .Values.config.groups -}}
{{- fail "config.groups: serve almeno un gruppo di nodi" -}}
{{- end -}}
{{- end -}}
