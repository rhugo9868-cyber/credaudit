#!/usr/bin/env bash
# CredAudit: запуск одной командой (Linux/macOS). Нужен Python 3.10+.
cd "$(dirname "$0")" || exit 1
if [ ! -x ".venv/bin/python" ]; then
  echo "Первый запуск: готовлю окружение..."
  python3 -m venv .venv && .venv/bin/python -m pip install -q -r backend/requirements.txt || exit 1
fi
exec .venv/bin/python run.py
