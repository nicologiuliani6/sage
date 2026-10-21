# syntax=docker/dockerfile:1
# Immagine unica di SAGE: Python + Ansible + OPA.
# Le versioni sono pinnate: quando ne aggiorni una, aggiorna anche il checksum.
FROM python:3.12-slim-trixie

ARG OPA_VERSION=1.21.3
ARG OPA_SHA256=add7c9dcf56e1ce1538426a6ee595ea1cc7ee830bbedd4c23219825b02b19a79
ARG UV_VERSION=0.11.32

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client ca-certificates curl \
 && curl -fsSL -o /usr/local/bin/opa \
      "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static" \
 && echo "${OPA_SHA256}  /usr/local/bin/opa" | sha256sum -c - \
 && chmod 0755 /usr/local/bin/opa \
 && apt-get purge -y curl && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "uv==${UV_VERSION}"

WORKDIR /opt/sage
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable && rm -rf /root/.cache
ENV PATH="/opt/sage/.venv/bin:${PATH}" \
    ANSIBLE_CONFIG=/opt/sage/ansible/ansible.cfg \
    ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections \
    ANSIBLE_LOCAL_TEMP=/tmp/ansible \
    HOME=/tmp

COPY ansible ./ansible
RUN ansible-galaxy collection install -r ansible/requirements.yml -p /usr/share/ansible/collections

COPY policy ./policy

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin sage
USER 10001

ENTRYPOINT ["sage"]
CMD ["--help"]
