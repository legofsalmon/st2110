#!/usr/bin/env bash
# Builds "ST 2110 Viewer.app" into ./dist, and a zip of it to hand out (macOS only).
#
#   scripts/make-viewer-app.sh              # for this Mac's processor
#   scripts/make-viewer-app.sh --universal  # for Apple silicon and Intel Macs both
#
# Signs with the Developer ID in APPLE_SIGNING_IDENTITY when there is one, with the
# hardened runtime that notarizing needs, and ad hoc otherwise.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "$(uname)" != "Darwin" ]; then
    echo "error: app bundles can only be built on macOS" >&2
    exit 1
fi

universal=false
case "${1:-}" in
    --universal) universal=true ;;
    "") ;;
    *) echo "usage: $0 [--universal]" >&2; exit 2 ;;
esac

version=$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
name="ST 2110 Viewer"
bin="st2110-viewer"
app="dist/$name.app"

if $universal; then
    echo "Building $name $version for Apple silicon and Intel..."
    for target in aarch64-apple-darwin x86_64-apple-darwin; do
        rustup target add "$target" >/dev/null
        cargo build --release --locked -p st2110-viewer --target "$target"
    done
    built="target/universal/$bin"
    mkdir -p target/universal
    lipo -create -output "$built" \
        "target/aarch64-apple-darwin/release/$bin" "target/x86_64-apple-darwin/release/$bin"
else
    echo "Building $name $version for this Mac..."
    cargo build --release --locked -p st2110-viewer
    built="target/release/$bin"
fi

rm -rf dist
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$built" "$app/Contents/MacOS/$bin"

# The icon, made here from the committed 1024-pixel master: sips and iconutil come
# with macOS, and an .icns is what the Dock and Finder read. Each size once at 1x and
# once at 2x, as iconutil expects.
icon_src="crates/viewer/assets/icon-1024.png"
iconset_dir="$(mktemp -d)"
iconset="$iconset_dir/$bin.iconset"
mkdir -p "$iconset"
for size in 16 32 128 256 512; do
    sips -s format png -z "$size" "$size" "$icon_src" --out "$iconset/icon_${size}x${size}.png" >/dev/null
    sips -s format png -z "$((size * 2))" "$((size * 2))" "$icon_src" \
        --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/$bin.icns"
rm -rf "$iconset_dir"
# iconutil can succeed having written nothing useful, so look at what it wrote.
if [ ! -s "$app/Contents/Resources/$bin.icns" ]; then
    echo "error: iconutil made no $bin.icns" >&2
    exit 1
fi

# The notices that the licences of the crates compiled in ask a binary to carry,
# written by scripts/third-party-notices.py and kept current by CI.
cp crates/viewer/THIRD_PARTY_NOTICES.md "$app/Contents/Resources/THIRD_PARTY_NOTICES.md"
cp LICENSE "$app/Contents/Resources/LICENSE"

cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>$name</string>
    <key>CFBundleDisplayName</key><string>$name</string>
    <key>CFBundleIdentifier</key><string>com.colmhewson.st2110-viewer</string>
    <key>CFBundleExecutable</key><string>$bin</string>
    <key>CFBundleIconFile</key><string>$bin</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$version</string>
    <key>CFBundleVersion</key><string>$version</string>
    <key>LSMinimumSystemVersion</key><string>11.0</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>LSApplicationCategoryType</key><string>public.app-category.video</string>
    <!-- Joining a multicast group is local network access, which macOS 15 asks the
         person about. Without this key the app is not asked about but refused, and
         the refusal looks like a stream that never arrives. A run from Terminal does
         not show it, because it has Terminal's permission. -->
    <key>NSLocalNetworkUsageDescription</key><string>ST 2110 Viewer finds and receives the video streams that devices send on your local network.</string>
    <!-- The DNS-SD services it browses for, to find NMOS registries and Nodes. -->
    <key>NSBonjourServices</key><array><string>_nmos-query._tcp</string><string>_nmos-node._tcp</string></array>
</dict>
</plist>
EOF

if [[ -n "${APPLE_SIGNING_IDENTITY:-}" ]]; then
    echo "Signing with $APPLE_SIGNING_IDENTITY (hardened runtime)"
    # The hardened runtime is what notarizing asks for, and the timestamp keeps the
    # signature good after the certificate expires. The app needs no entitlements:
    # it is not sandboxed, and receiving is ordinary networking.
    codesign --force --timestamp --options runtime --sign "$APPLE_SIGNING_IDENTITY" "$app"
    codesign --verify --deep --strict --verbose=2 "$app"
else
    echo "No APPLE_SIGNING_IDENTITY: signing ad hoc, so the first launch needs Open Anyway"
    # Still needed: Apple silicon will not run an unsigned binary at all.
    codesign --force --sign - "$app"
fi

# The zip carries the version, and the app inside keeps its plain name, which is
# what it is called in /Applications and the Dock.
zip="dist/$bin-$version.app.zip"
ditto -c -k --keepParent "$app" "$zip"
echo "Built $app and $zip"
