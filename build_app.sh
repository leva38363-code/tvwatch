#!/bin/bash
# Сборка TVWatch.app. Запуск: bash build_app.sh
set -euo pipefail
cd "$(dirname "$0")"
( cd app && swift build -c release )
APP=TVWatch.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp app/.build/release/TVWatch "$APP/Contents/MacOS/TVWatch"
cat > "$APP/Contents/Info.plist" <<'PL'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>TV Watch</string>
  <key>CFBundleDisplayName</key><string>TV Watch</string>
  <key>CFBundleIdentifier</key><string>local.tvwatch.app</string>
  <key>CFBundleExecutable</key><string>TVWatch</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSLocalNetworkUsageDescription</key><string>TV Watch подключается к Raspberry Pi в домашней сети, чтобы показывать запросы телевизора и управлять фильтрами.</string>
</dict></plist>
PL
codesign --force --deep -s - "$APP"
echo "built $(pwd)/$APP"
