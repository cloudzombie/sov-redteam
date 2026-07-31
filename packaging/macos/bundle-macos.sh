#!/usr/bin/env bash
# Build "SOV Red Team.app" — a real macOS application bundle for Apple Silicon.
#
#   packaging/macos/bundle-macos.sh <version> [target-triple] [out-dir]
#
# Produces dist/SOV Red Team.app with the GUI binary, a generated .icns, an
# Info.plist, and an ad-hoc code signature (so Gatekeeper treats it as a normal
# unnotarized local app rather than a broken one). Run it locally or from CI —
# same script, same output.
set -euo pipefail

VERSION="${1:?usage: bundle-macos.sh <version> [target] [out-dir]}"
VERSION="${VERSION#v}"
TARGET="${2:-aarch64-apple-darwin}"
OUT="${3:-dist}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP="$OUT/SOV Red Team.app"

cd "$ROOT"
BIN="target/$TARGET/release/sov-redteam-gui"
CLI="target/$TARGET/release/sov-redteam"
test -x "$BIN" || { echo "missing $BIN — cargo build --release --target $TARGET first" >&2; exit 1; }

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# The GUI, plus the CLI alongside it so one download gives you both front ends.
cp "$BIN" "$APP/Contents/MacOS/sov-redteam-gui"
[ -x "$CLI" ] && cp "$CLI" "$APP/Contents/MacOS/sov-redteam"

# Icon: generated from source, never a checked-in binary blob of unknown origin.
ICONSET="$(mktemp -d)/AppIcon.iconset"
mkdir -p "$ICONSET"
python3 packaging/macos/make-icon.py "$ICONSET/icon_1024.png"
for s in 16 32 128 256 512; do
  sips -z "$s" "$s" "$ICONSET/icon_1024.png" --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  sips -z "$((s * 2))" "$((s * 2))" "$ICONSET/icon_1024.png" --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
mv "$ICONSET/icon_1024.png" "$ICONSET/icon_512x512@2x.png"
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>SOV Red Team</string>
  <key>CFBundleDisplayName</key><string>SOV Red Team</string>
  <key>CFBundleIdentifier</key><string>com.sovxus.redteam</string>
  <key>CFBundleExecutable</key><string>sov-redteam-gui</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSHumanReadableCopyright</key><string>Apache-2.0</string>
</dict>
</plist>
PLIST

# Ad-hoc signature. NOT notarization — this is an unsigned-developer build and the
# release notes say so plainly; it just keeps the bundle internally consistent.
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP"

echo "built: $APP"
lipo -archs "$APP/Contents/MacOS/sov-redteam-gui"
