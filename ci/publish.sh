#!/usr/bin/env bash
# Costruisce e pubblica l'immagine su GHCR. Il nome deriva dalla repo: nessun owner
# scritto a mano. Scrive il riferimento per digest nell'output `image` del job.
source "$(dirname "$0")/lib.sh"
: "${GH_TOKEN:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_SHA:?}" "${GITHUB_ACTOR:?}" "${GITHUB_REF:?}"
image="ghcr.io/${GITHUB_REPOSITORY,,}"
tag="sha-${GITHUB_SHA::12}"
echo "$GH_TOKEN" | docker login ghcr.io -u "$GITHUB_ACTOR" --password-stdin
docker build \
  --label "org.opencontainers.image.source=https://github.com/${GITHUB_REPOSITORY}" \
  --label "org.opencontainers.image.revision=${GITHUB_SHA}" \
  -t "$image:$tag" .
docker push "$image:$tag"
if [[ "$GITHUB_REF" == refs/tags/v* ]]; then
  docker tag "$image:$tag" "$image:${GITHUB_REF_NAME#v}"
  docker push "$image:${GITHUB_REF_NAME#v}"
fi
ref=$(docker inspect --format '{{index .RepoDigests 0}}' "$image:$tag")
echo "image=$ref" >> "${GITHUB_OUTPUT:-/dev/null}"
{
  echo "### Immagine pubblicata"
  echo ""
  echo "\`$ref\`"
} >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
