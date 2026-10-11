#!/usr/bin/env bash
# Fetches the prebuilt Bitwarden web vault (Vaultwarden's patched build, bw_web_builds)
# into public/web-vault so wrangler bundles it as static assets,
# then applies Vaultur branding overrides.
#
# Usage: scripts/fetch-web-vault.sh [version]
#   version: bw_web_builds release tag (default: the reviewed pinned release)
#
# Set GITHUB_TOKEN to authenticate GitHub requests. Shared CI/build fleets
# (e.g. Cloudflare Workers Builds) commonly exhaust GitHub's 60/hr
# unauthenticated rate limit or trip its IP-based abuse detection, surfacing
# as a bare `curl: (22) ... 403`.

set -euo pipefail

REPO="dani-garcia/bw_web_builds"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT_DIR/public/web-vault"
OVERRIDES="$ROOT_DIR/public/overrides"

curl_gh() {
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" "$@"
  else
    curl -fsSL "$@"
  fi
}

DEFAULT_VERSION="v2026.7.0"
DEFAULT_SHA256="002e972bf0d0487ec0324b06d916de33e29de4c29bffd92ee3b843084c300570"
VERSION="${1:-${WEB_VAULT_VERSION:-$DEFAULT_VERSION}}"
if [[ -z "$VERSION" ]]; then
  echo "Could not determine bw_web_builds version" >&2
  exit 1
fi
if ! [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "Invalid bw_web_builds version: $VERSION" >&2
	exit 1
fi

echo "Fetching bw_web_builds $VERSION ..."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

ASSET="bw_web_${VERSION}.tar.gz"
curl_gh -o "$TMP/web-vault.tar.gz" \
  "https://github.com/$REPO/releases/download/$VERSION/bw_web_$VERSION.tar.gz"

# Verify the release-provided digest before extracting untrusted archive data.
# CI may additionally pin WEB_VAULT_SHA256 to a digest reviewed by the operator;
# otherwise the release's sha256sums.txt is used.
EXPECTED_SHA256="${WEB_VAULT_SHA256:-}"
if [[ -z "$EXPECTED_SHA256" && "$VERSION" == "$DEFAULT_VERSION" ]]; then
	EXPECTED_SHA256="$DEFAULT_SHA256"
fi
if [[ -z "$EXPECTED_SHA256" ]]; then
	SUMS="$TMP/sha256sums.txt"
	curl_gh -o "$SUMS" \
		"https://github.com/$REPO/releases/download/$VERSION/sha256sums.txt"
	EXPECTED_SHA256=$(awk -v asset="$ASSET" '$2 == asset { print $1; exit }' "$SUMS")
fi
if ! [[ "$EXPECTED_SHA256" =~ ^[[:xdigit:]]{64}$ ]]; then
	echo "Missing or invalid SHA-256 for $ASSET" >&2
	exit 1
fi
ACTUAL_SHA256=$(sha256sum "$TMP/web-vault.tar.gz" | awk '{print $1}')
if [[ "${ACTUAL_SHA256,,}" != "${EXPECTED_SHA256,,}" ]]; then
	echo "SHA-256 mismatch for $ASSET" >&2
	exit 1
fi

rm -rf "$DEST"
mkdir -p "$DEST"
tar -xzf "$TMP/web-vault.tar.gz" -C "$DEST" --strip-components=1 --no-same-owner --no-same-permissions

# Rename vaultwarden.css reference to vaultur.css so our override is picked up
for htmlfile in "$DEST"/*.html; do
	[[ -f "$htmlfile" ]] || continue
	sed -i.bak -e 's/vaultwarden\.css/vaultur.css/g' "$htmlfile"
	rm -f "$htmlfile.bak"
done

# Apply Vaultur overrides (branding css, etc.) if present
if [[ -d "$OVERRIDES" ]]; then
  echo "Applying Vaultur overrides ..."
  cp -R "$OVERRIDES/." "$DEST/"
fi

echo "Web vault $VERSION installed at public/web-vault"
