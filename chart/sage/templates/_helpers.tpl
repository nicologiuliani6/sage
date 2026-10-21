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

{{/*
Pod di SAGE, identico per lo scan (CronJob) e per la remediation (Job): stessa immagine,
stessi segreti, stessi permessi. Parametri: root (contesto) e args (argomenti del comando).
*/}}
{{- define "sage.podSpec" -}}
{{- $root := .root -}}
serviceAccountName: {{ include "sage.fullname" $root }}
restartPolicy: Never
{{- with $root.Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  fsGroup: 10001
  seccompProfile:
    type: RuntimeDefault
containers:
  - name: sage
    image: {{ include "sage.image" $root | quote }}
    imagePullPolicy: {{ $root.Values.image.pullPolicy }}
    args:
      {{- toYaml .args | nindent 6 }}
    env:
      - name: SAGE_RELEASE
        value: {{ $root.Release.Name | quote }}
      - name: SAGE_NAMESPACE
        valueFrom:
          fieldRef:
            fieldPath: metadata.namespace
      {{- with $root.Values.extraEnv }}
      {{- toYaml . | nindent 6 }}
      {{- end }}
    {{- if $root.Values.secrets.llm }}
    envFrom:
      - secretRef:
          name: {{ $root.Values.secrets.llm }}
    {{- end }}
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    resources:
      {{- toYaml $root.Values.resources | nindent 6 }}
    volumeMounts:
      - name: config
        mountPath: /etc/sage/config
        readOnly: true
      - name: ssh
        mountPath: /etc/sage/ssh
        readOnly: true
      - name: tmp
        mountPath: /tmp
volumes:
  - name: config
    configMap:
      name: {{ include "sage.fullname" $root }}-config
  - name: ssh
    secret:
      secretName: {{ $root.Values.secrets.ssh }}
      # Leggibile dal gruppo (fsGroup): sage copia la chiave in /tmp con permessi
      # 0600 prima di usarla, come richiede OpenSSH.
      defaultMode: 0440
  - name: tmp
    emptyDir: {}
{{- with $root.Values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $root.Values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $root.Values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}
