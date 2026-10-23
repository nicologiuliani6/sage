#!/usr/bin/env bash
# Lint, test Python e playbook. Collector e installer girano con il Python di sistema
# dei nodi (3.9): si provano anche con quello.
source "$(dirname "$0")/lib.sh"
install_uv
install_opa
uv sync --frozen --python 3.12
uv run ruff check .
uv run ruff format --check .
uv run ansible-galaxy collection install -r ansible/requirements.yml
(cd ansible \
  && uv run ansible-playbook --syntax-check -i localhost, collect.yml \
  && uv run ansible-playbook --syntax-check -i localhost, remediate.yml)
checked uv run pytest -v -rs --ignore=tests/live | tee "$TOOLS/pytest.log"
if grep -q "SKIPPED" "$TOOLS/pytest.log"; then
  echo "test saltati in CI: devono girare tutti" && exit 1
fi
uv run --no-project --python 3.9 python -c \
  "import ast; ast.parse(open('ansible/files/collect_node.py').read())"
checked uv run --no-project --python 3.9 python -m unittest -v tests.test_installer
uv run sage check-config --config examples/config.example.yaml
# Il collector sui gestori di pacchetti veri, in container delle distro (ADR-0017).
bash ci/distros.sh
