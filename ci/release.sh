#!/usr/bin/env bash
# Release per un tag vX.Y.Z: chart impacchettato e installer con immagine, chart e Helm
# fissati per digest e checksum. Richiede IMAGE (repo@sha256:...) dal job precedente.
source "$(dirname "$0")/lib.sh"
: "${IMAGE:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_REF_NAME:?}" "${GH_TOKEN:?}"
version="${GITHUB_REF_NAME#v}"
py_version=$(python3 -c \
  'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')
chart_version=$(awk '/^version:/ {print $2}' chart/sage/Chart.yaml)
app_version=$(awk -F'"' '/^appVersion:/ {print $2}' chart/sage/Chart.yaml)
for v in "$py_version" "$chart_version" "$app_version"; do
  if [ "$v" != "$version" ]; then
    echo "versione $v (pyproject o Chart.yaml) diversa dal tag $version" && exit 1
  fi
done

dist="$TOOLS/dist"
rm -rf "$dist" && mkdir -p "$dist"
helm package chart/sage -d "$dist"
chart="sage-${version}.tgz"
chart_sha=$(sha256sum "$dist/$chart" | cut -d' ' -f1)
base="https://github.com/${GITHUB_REPOSITORY}/releases/download/${GITHUB_REF_NAME}"

helm_args=()
for arch in amd64 arm64; do
  url="https://get.helm.sh/helm-${HELM_VERSION}-linux-${arch}.tar.gz"
  sha=$(curl -fsSL "${url}.sha256sum" | cut -d' ' -f1)
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || { echo "checksum di Helm non valido per $arch"; exit 1; }
  helm_args+=("helm_url_${arch}=${url}" "helm_sha256_${arch}=${sha}")
done

python3 ci/stamp_installer.py installer/sage_install.py "$dist/sage-install.py" \
  "version=${version}" "image=${IMAGE}" \
  "chart_url=${base}/${chart}" "chart_sha256=${chart_sha}" \
  "helm_version=${HELM_VERSION}" "${helm_args[@]}"
python3 "$dist/sage-install.py" --version
(cd "$dist" && sha256sum sage-install.py "$chart" > SHA256SUMS)

cat > "$dist/notes.md" <<NOTES
Installazione, da un master del cluster (serve kubectl con permessi di amministratore):

\`\`\`bash
curl -fsSLO ${base}/sage-install.py && python3 sage-install.py
\`\`\`

L'installer chiede quali nodi gestire, prepara chiave SSH, segreti e valori, installa il
chart e lancia un primo giro in simulazione. Rilanciato, riconfigura, passa al vivo o
disinstalla.

- Immagine: \`${IMAGE}\`
- Chart: \`${chart}\` (sha256 \`${chart_sha}\`)
NOTES

gh release create "$GITHUB_REF_NAME" \
  "$dist/sage-install.py" "$dist/$chart" "$dist/SHA256SUMS" \
  --repo "$GITHUB_REPOSITORY" --title "SAGE ${version}" --notes-file "$dist/notes.md"
