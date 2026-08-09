#!/bin/zsh
set -e
ROOT="${0:A:h}"
cd "$ROOT"
BIN=TsukubaVPN
APPNAME="つくばVPN"
BUILD="$ROOT/build"
APP="$BUILD/$APPNAME.app"
rm -rf "$BUILD"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

SDK="$(xcrun --show-sdk-path)"
echo "SDK: $SDK"
swiftc -O -target arm64-apple-macos14.0 -sdk "$SDK" \
  -o "$APP/Contents/MacOS/$BIN" \
  Sources/Models.swift Sources/VPNGateAPI.swift Sources/Scripts.swift \
  Sources/VPNController.swift Sources/Management.swift Sources/AppModel.swift Sources/ContentView.swift \
  Sources/TsukubaVPNApp.swift \
  -framework AppKit -framework SwiftUI

cp Info.plist "$APP/Contents/Info.plist"
printf 'APPL????' > "$APP/Contents/PkgInfo"

if [ -f icon.png ]; then
  ICONSET="$BUILD/AppIcon.iconset"
  mkdir -p "$ICONSET"
  sips -z 16   16   icon.png --out "$ICONSET/icon_16x16.png"      >/dev/null
  sips -z 32   32   icon.png --out "$ICONSET/icon_16x16@2x.png"   >/dev/null
  sips -z 32   32   icon.png --out "$ICONSET/icon_32x32.png"      >/dev/null
  sips -z 64   64   icon.png --out "$ICONSET/icon_32x32@2x.png"   >/dev/null
  sips -z 128  128  icon.png --out "$ICONSET/icon_128x128.png"    >/dev/null
  sips -z 256  256  icon.png --out "$ICONSET/icon_128x128@2x.png" >/dev/null
  sips -z 256  256  icon.png --out "$ICONSET/icon_256x256.png"    >/dev/null
  sips -z 512  512  icon.png --out "$ICONSET/icon_256x256@2x.png" >/dev/null
  sips -z 512  512  icon.png --out "$ICONSET/icon_512x512.png"    >/dev/null
  sips -z 1024 1024 icon.png --out "$ICONSET/icon_512x512@2x.png" >/dev/null
  iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
  rm -rf "$ICONSET"
fi

codesign --force --sign - "$APP"
echo "BUILT: $APP"
