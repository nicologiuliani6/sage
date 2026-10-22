#!/usr/bin/env bash
# Release per un tag vX.Y.Z: chart impacchettato e installer con immagine, chart e Helm
# fissati per digest e checksum. Richiede IMAGE (repo@sha256:...) dal job precedente.
# La versione è quella del tag: chart, installer e immagine (SAGE_VERSION) la prendono da lì,
# senza commit di aggiornamento della versione prima della release.
source "$(dirname "$0")/lib.sh"
: "${IMAGE:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_REF_NAME:?}" "${GH_TOKEN:?}"
version="${GITHUB_REF_NAME#v}"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "tag $GITHUB_REF_NAME: serve la forma vX.Y.Z" && exit 1
fi

dist="$TOOLS/dist"
rm -rf "$dist" && mkdir -p "$dist"
helm package chart/sage -d "$dist" --version "$version" --app-version "$version"
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
# Eseguibile unico dall'installer già fissato: sui master non serve Python.
ci/installer_bin.sh "$dist/sage-install.py" "$dist"
(cd "$dist" && sha256sum sage sage-install.py "$chart" > SHA256SUMS)

cat > "$dist/notes.md" <<NOTES
Installazione, da un master del cluster (serve kubectl con permessi di amministratore):

\`\`\`bash
curl -fsSLO ${base}/sage && curl -fsSLO ${base}/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing && chmod +x sage && ./sage
\`\`\`

Eseguibile unico per linux amd64, senza dipendenze da Python: al primo avvio si installa
come comando di sistema (\`/usr/local/bin/sage\`), poi basta scrivere \`sage\`. Opzioni utili: \`--live\`
(modalità reale da subito), \`--allow-remove\`, \`--dashboard\`, \`--resume\` (giro in corso).
Su altre architetture: \`sage-install.py\` con Python 3.9 o più recente.

L'installer chiede quali nodi gestire, prepara chiave SSH, segreti e valori, installa il
chart e lancia un primo giro in simulazione. Rilanciato, riconfigura, passa al vivo o
disinstalla.

- Immagine: \`${IMAGE}\`
- Chart: \`${chart}\` (sha256 \`${chart_sha}\`)
NOTES

assets=("$dist/sage" "$dist/sage-install.py" "$dist/$chart" "$dist/SHA256SUMS")
if gh release view "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" > /dev/null 2>&1; then
  # Release creata a mano dalla pagina di GitHub (che crea anche il tag): si completano
  # file e note.
  gh release upload "$GITHUB_REF_NAME" "${assets[@]}" --clobber --repo "$GITHUB_REPOSITORY"
  gh release edit "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" \
    --title "SAGE ${version}" --notes-file "$dist/notes.md"
else
  gh release create "$GITHUB_REF_NAME" "${assets[@]}" \
    --repo "$GITHUB_REPOSITORY" --title "SAGE ${version}" --notes-file "$dist/notes.md"
fi
