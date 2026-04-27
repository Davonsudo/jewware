#!/bin/bash

set -euo pipefail

APP_NAME="JewWare"
REPO_OWNER="${JEWWARE_REPO_OWNER:-Davonsudo}"
REPO_NAME="${JEWWARE_REPO_NAME:-jewware}"
RELEASE_TAG="${JEWWARE_RELEASE_TAG:-latest}"

TMP_DIR="$(mktemp -d)"
DMG_PATH="${TMP_DIR}/${APP_NAME}.dmg"
MOUNT_POINT="${TMP_DIR}/mount"

cleanup() {
    hdiutil detach "${MOUNT_POINT}" >/dev/null 2>&1 || true
    rm -rf "${TMP_DIR}"
}

trap cleanup EXIT

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing required command: $1" >&2
        exit 1
    fi
}

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "This installer only supports macOS." >&2
    exit 1
fi

require_command curl
require_command hdiutil
require_command ditto
require_command open

case "$(uname -m)" in
    arm64)
        ASSET_NAME="${JEWWARE_ASSET_NAME:-JewWare-ARM64.dmg}"
        ;;
    x86_64)
        ASSET_NAME="${JEWWARE_ASSET_NAME:-JewWare-x86_64.dmg}"
        ;;
    *)
        echo "Unsupported architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

if [[ "${RELEASE_TAG}" == "latest" ]]; then
    DOWNLOAD_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest/download/${ASSET_NAME}"
else
    DOWNLOAD_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${RELEASE_TAG}/${ASSET_NAME}"
fi

echo "Downloading ${APP_NAME} for $(uname -m)..."
if ! curl -fL "${DOWNLOAD_URL}" -o "${DMG_PATH}"; then
    echo "Could not download ${ASSET_NAME}." >&2
    echo "Upload ${ASSET_NAME} to a GitHub release for ${REPO_OWNER}/${REPO_NAME} and try again." >&2
    exit 1
fi

mkdir -p "${MOUNT_POINT}"

echo "Mounting disk image..."
hdiutil attach "${DMG_PATH}" -mountpoint "${MOUNT_POINT}" -nobrowse -quiet

if [[ ! -d "${MOUNT_POINT}/${APP_NAME}.app" ]]; then
    echo "${APP_NAME}.app was not found inside ${ASSET_NAME}." >&2
    exit 1
fi

echo "Installing ${APP_NAME} to /Applications..."
rm -rf "/Applications/${APP_NAME}.app"
ditto "${MOUNT_POINT}/${APP_NAME}.app" "/Applications/${APP_NAME}.app"

open "/Applications/${APP_NAME}.app"
echo "${APP_NAME} installed successfully."
