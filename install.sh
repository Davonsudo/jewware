#!/bin/bash

set -euo pipefail

APP_NAME="JewWare"
REPO_OWNER="${JEWWARE_REPO_OWNER:-Davonsudo}"
REPO_NAME="${JEWWARE_REPO_NAME:-jewware}"
REPO_REF="${JEWWARE_REPO_REF:-main}"
ARCHIVE_URL="https://codeload.github.com/${REPO_OWNER}/${REPO_NAME}/tar.gz/refs/heads/${REPO_REF}"

TMP_DIR="$(mktemp -d)"
ARCHIVE_PATH="${TMP_DIR}/source.tar.gz"
EXTRACT_DIR="${TMP_DIR}/extract"

cleanup() {
    rm -rf "${TMP_DIR}"
}

trap cleanup EXIT

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Missing required command: $1" >&2
        exit 1
    fi
}

find_app_source_dir() {
    local search_root="$1"
    local package_file

    while IFS= read -r -d '' package_file; do
        if grep -q '"name"[[:space:]]*:[[:space:]]*"jewware"' "${package_file}"; then
            dirname "${package_file}"
            return 0
        fi
    done < <(find "${search_root}" -name package.json -print0)

    return 1
}

require_command curl
require_command tar
require_command npm
require_command node
require_command ditto

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "This installer only supports macOS." >&2
    exit 1
fi

case "$(uname -m)" in
    arm64)
        BUILD_ARCH_FLAG="--arm64"
        DIST_APP_SUBDIR="mac-arm64"
        ;;
    x86_64)
        BUILD_ARCH_FLAG="--x64"
        DIST_APP_SUBDIR="mac"
        ;;
    *)
        echo "Unsupported architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

mkdir -p "${EXTRACT_DIR}"

echo "Downloading ${APP_NAME} source from GitHub..."
curl -fL "${ARCHIVE_URL}" -o "${ARCHIVE_PATH}"

echo "Extracting source..."
tar -xzf "${ARCHIVE_PATH}" -C "${EXTRACT_DIR}"

SOURCE_DIR="$(find_app_source_dir "${EXTRACT_DIR}")"
if [[ -z "${SOURCE_DIR}" ]]; then
    echo "Could not find the ${APP_NAME} app source in the downloaded repository." >&2
    exit 1
fi

cd "${SOURCE_DIR}"

echo "Installing dependencies..."
npm ci

echo "Building ${APP_NAME} for $(uname -m)..."
./node_modules/.bin/electron-builder build --mac dir "${BUILD_ARCH_FLAG}" -c.mac.identity=null

BUILT_APP_PATH="${SOURCE_DIR}/dist/${DIST_APP_SUBDIR}/${APP_NAME}.app"
if [[ ! -d "${BUILT_APP_PATH}" ]]; then
    echo "Build completed, but ${BUILT_APP_PATH} was not found." >&2
    exit 1
fi

echo "Installing ${APP_NAME} to /Applications..."
rm -rf "/Applications/${APP_NAME}.app"
ditto "${BUILT_APP_PATH}" "/Applications/${APP_NAME}.app"

open "/Applications/${APP_NAME}.app"
echo "${APP_NAME} installed successfully."
