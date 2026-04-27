#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")"

APP_NAME="JewWare"
ARCH="$(uname -m)"

case "${ARCH}" in
    arm64)
        ARCH_LABEL="ARM64"
        ;;
    x86_64)
        ARCH_LABEL="x86_64"
        ;;
    *)
        echo "Unsupported architecture: ${ARCH}" >&2
        exit 1
        ;;
esac

APP_OUTPUT="${APP_NAME}-${ARCH_LABEL}.app"
DMG_OUTPUT="${APP_NAME}-${ARCH_LABEL}.dmg"
ZIP_OUTPUT="JewWareCompressed.zip"

echo "Preparing JewWare frontend for Tauri..."
node ./prepare-tauri-frontend.mjs

echo "Cleaning previous Tauri build artifacts..."
rm -rf "./${APP_OUTPUT}" "./${DMG_OUTPUT}" "./${ZIP_OUTPUT}" ./src-tauri/target/release/bundle

echo "Building ${APP_NAME} for ${ARCH_LABEL}..."
./node_modules/.bin/tauri build

APP_SOURCE="$(find ./src-tauri/target/release/bundle -type d -name "${APP_NAME}.app" | head -n 1)"
if [[ -z "${APP_SOURCE}" ]]; then
    echo "Built app bundle was not found." >&2
    exit 1
fi

cp -R "${APP_SOURCE}" "./${APP_OUTPUT}"

DMG_SOURCE="$(find ./src-tauri/target/release/bundle -type f -name "*.dmg" | head -n 1 || true)"
if [[ -n "${DMG_SOURCE}" ]]; then
    cp "${DMG_SOURCE}" "./${DMG_OUTPUT}"
fi

ditto -c -k --sequesterRsrc --keepParent "${APP_OUTPUT}" "${ZIP_OUTPUT}"

echo "Build complete:"
echo "  App: ${APP_OUTPUT}"
if [[ -f "${DMG_OUTPUT}" ]]; then
    echo "  DMG: ${DMG_OUTPUT}"
fi
echo "  ZIP: ${ZIP_OUTPUT}"
