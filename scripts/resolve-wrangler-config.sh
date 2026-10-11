#!/usr/bin/env bash
# Prints which wrangler config file deploy/migration commands should use: an
# explicit WRANGLER_CONFIG override, else the gitignored wrangler.deploy.jsonc
# (real resource IDs). Refuse to deploy with the committed template by default:
# its open registration and workers.dev settings are intentionally unsuitable
# for a public production vault. Set VAULTUR_ALLOW_INSECURE_TEMPLATE_DEPLOY=1
# only for an explicit disposable test deployment.
# Single source of truth for the `deploy` and `db:migrate:remote` package.json
# scripts, so both always resolve to the same config within one invocation.
set -euo pipefail

if [[ -n "${WRANGLER_CONFIG:-}" ]]; then
	echo "$WRANGLER_CONFIG"
elif [[ -f wrangler.deploy.jsonc ]]; then
	echo "wrangler.deploy.jsonc"
elif [[ "${VAULTUR_ALLOW_INSECURE_TEMPLATE_DEPLOY:-}" == "1" ]]; then
	echo "wrangler.jsonc"
else
	echo "No wrangler.deploy.jsonc found. Copy wrangler.jsonc to that file and set a custom domain, resource IDs, and restrictive production vars before deploying." >&2
	echo "For a disposable test only, set VAULTUR_ALLOW_INSECURE_TEMPLATE_DEPLOY=1." >&2
	exit 1
fi
