# syntax=docker/dockerfile:1
# Immagine unica di SAGE: Python + Ansible + OPA.
# Le versioni sono pinnate: quando ne aggiorni una, aggiorna anche il checksum.
FROM python:3.12-slim-trixie

ARG OPA_VERSION=1.21.3
ARG OPA_SHA256=add7c9dcf56e1ce1538426a6ee595ea1cc7ee830bbedd4c23219825b02b19a79
ARG UV_VERSION=0.11.32
# Per l'aggiornamento automatico (ADR-0021): verifica della firma e helm upgrade.
ARG COSIGN_VERSION=v3.1.3
ARG COSIGN_SHA256=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71
ARG HELM_VERSION=v4.3.0
ARG HELM_SHA256=86584a54def73570558f66f5111cc53dfed56689637ae32c1201205d494f54fb

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client ca-certificates curl \
 && curl -fsSL -o /usr/local/bin/opa \
      "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static" \
 && echo "${OPA_SHA256}  /usr/local/bin/opa" | sha256sum -c - \
 && chmod 0755 /usr/local/bin/opa \
 && curl -fsSL -o /usr/local/bin/cosign \
      "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64" \
 && echo "${COSIGN_SHA256}  /usr/local/bin/cosign" | sha256sum -c - \
 && chmod 0755 /usr/local/bin/cosign \
 && curl -fsSL -o /tmp/helm.tgz "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" \
 && echo "${HELM_SHA256}  /tmp/helm.tgz" | sha256sum -c - \
 && tar -xzf /tmp/helm.tgz -C /usr/local/bin --strip-components=1 linux-amd64/helm \
 && rm /tmp/helm.tgz \
 && apt-get purge -y curl && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "uv==${UV_VERSION}"

WORKDIR /opt/sage
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable && rm -rf /root/.cache
# Versione della release, dal tag (ci/publish.sh); vuota nelle build di sviluppo.
ARG SAGE_VERSION=""
ENV PATH="/opt/sage/.venv/bin:${PATH}" \
    SAGE_VERSION=${SAGE_VERSION} \
    ANSIBLE_CONFIG=/opt/sage/ansible/ansible.cfg \
    ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections \
    ANSIBLE_LOCAL_TEMP=/tmp/ansible \
    SAGE_ANSIBLE_DIR=/opt/sage/ansible \
    SAGE_POLICY_DIR=/opt/sage/policy \
    SAGE_OPA_BIN=/usr/local/bin/opa \
    SAGE_WORKDIR=/tmp/sage \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp

COPY ansible ./ansible
# Quello che ansible-galaxy lascia in /tmp (HOME) è di root e non scrivibile per l'utente 10001 (nel cluster
# /tmp è un emptyDir, ma l'immagine deve funzionare anche da sola).
RUN ansible-galaxy collection install -r ansible/requirements.yml -p /usr/share/ansible/collections \
 && find /tmp -mindepth 1 -delete

COPY policy ./policy

# Home dell'utente = /tmp (nel cluster un emptyDir scrivibile, il resto è in sola lettura):
# Ansible risolve ~ dal file passwd per i task eseguiti in locale.
RUN useradd --uid 10001 --home-dir /tmp --no-create-home --shell /usr/sbin/nologin sage
USER 10001

ENTRYPOINT ["sage"]
CMD ["--help"]
