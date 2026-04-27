#!/bin/bash

set -euo pipefail

APP_NAME="JewWare"
VERSION="$(node -p "require('./package.json').version")"
X64_APP="${APP_NAME}-x86_64.app"
ARM64_APP="${APP_NAME}-ARM64.app"
X64_DMG="${APP_NAME}-x86_64.dmg"
ARM64_DMG="${APP_NAME}-ARM64.dmg"

echo "Building JewWare for local installation."
rm -rf "./${X64_APP}" "./${ARM64_APP}" "./${X64_DMG}" "./${ARM64_DMG}" ./JewWareCompressed ./JewWareCompressed.zip ./dist
./node_modules/.bin/electron-builder build --mac dmg zip --x64 --arm64 \
    -c.mac.identity=null

mv "dist/mac/${APP_NAME}.app" "./${X64_APP}"

mv "dist/mac-arm64/${APP_NAME}.app" "./${ARM64_APP}"
mv "dist/${APP_NAME}-${VERSION}.dmg" "./${X64_DMG}"
mv "dist/${APP_NAME}-${VERSION}-arm64.dmg" "./${ARM64_DMG}"

mkdir JewWareCompressed
cp -R "${ARM64_APP}" "${X64_APP}" JewWareCompressed/
ditto -c -k --sequesterRsrc --keepParent JewWareCompressed JewWareCompressed.zip

rm -rf JewWareCompressed
rm -rf dist

echo "Build complete."
