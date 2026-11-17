{{- define "rw.etiquettes" -}}
app.kubernetes.io/name: rootwarden
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "rw.selecteur" -}}
app.kubernetes.io/name: rootwarden
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .composant }}
{{- end -}}

{{- define "rw.image" -}}
{{- $img := index .root.Values.images .nom -}}
{{- $tag := $img.tag | default .root.Values.imageTag -}}
{{- if not $tag -}}{{- fail (printf "images.%s.tag ou imageTag est requis" .nom) -}}{{- end -}}
{{- printf "%s:%s" $img.repository $tag -}}
{{- end -}}

{{/* Sans capacites, sans elevation : comme docker-compose.prod.yml. */}}
{{- define "rw.securite" -}}
allowPrivilegeEscalation: false
capabilities:
  drop: ["ALL"]
  add: {{ toJson .ajout }}
{{- end -}}
