#!/usr/bin/env bash
# Set up independent Python and JavaScript environments and create lockfiles.
set -euo pipefail
cd "$(dirname "$0")/.."

for command in uv node npm; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Missing required tool: $command" >&2
    exit 2
  fi
done

if ! node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)'; then
  echo 'Node.js 22 or newer is required.' >&2
  exit 2
fi

echo 'Setting up isolated Python environment and uv.lock...'
uv sync --all-groups

echo 'Resolving web dependencies and generating package-lock.json...'
(
  cd apps/web
  npm install --package-lock-only --no-audit --no-fund
  npm ci --no-audit --no-fund
)

echo
printf '%s\n' 'Bootstrap complete.' \
  'IMPORTANT: Commit uv.lock and apps/web/package-lock.json with the repository.' \
  'Run: uv run python scripts/run_checks.py'
