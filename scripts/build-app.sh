#!/usr/bin/env bash
# Builds "LANA Scanner.app" (LAN Advanced Scanner) from the Swift package, ad-hoc signs it and (optionally) installs it.
#
#   scripts/build-app.sh                 # release build for the host arch -> "build/LANA Scanner.app"
#   scripts/build-app.sh --universal     # arm64 + x86_64 (requires full Xcode, not just CLT)
#   scripts/build-app.sh --install       # also install to /Applications (or $INSTALL_DIR)
#
# Idempotent: every run rebuilds the bundle in a temp dir and atomically replaces the old one.
set -euo pipefail

readonly APP_NAME="LANA Scanner"      # bundle / display name
readonly EXEC_NAME="NetScanner"       # SwiftPM product (binary inside the bundle)
readonly LEGACY_APP_NAMES=("NetScanner")
readonly BUNDLE_ID="${BUNDLE_ID:-com.github.lanascanner}"
readonly VERSION="${VERSION:-1.0.0}"
readonly MIN_MACOS="13.0"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly ROOT
readonly OUT_DIR="${ROOT}/build"
readonly APP="${OUT_DIR}/${APP_NAME}.app"

UNIVERSAL=0
INSTALL=0
STAGE=""

log()  { printf '\033[1;34m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
warn() { printf '\033[1;33m[%s] WARN:\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf '\033[1;31m[%s] ERROR:\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

cleanup() {
  if [[ -n "${STAGE}" && -d "${STAGE}" ]]; then rm -rf "${STAGE}"; fi
}
trap cleanup EXIT
trap 'die "interrupted"' INT TERM
trap 'die "failed at line ${LINENO}: ${BASH_COMMAND}"' ERR

usage() { sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --universal) UNIVERSAL=1 ;;
    --install)   INSTALL=1 ;;
    -h|--help)   usage 0 ;;
    *)           warn "unknown option: $1"; usage 2 ;;
  esac
  shift
done

[[ "$(uname -s)" == "Darwin" ]] || die "this script must run on macOS"
command -v swift >/dev/null    || die "swift not found — install Xcode Command Line Tools: xcode-select --install"
command -v codesign >/dev/null || die "codesign not found"

cd "${ROOT}"

ARCH_ARGS=()
if [[ ${UNIVERSAL} -eq 1 ]]; then
  ARCH_ARGS=(--arch arm64 --arch x86_64)
  log "building universal binary (arm64 + x86_64)"
else
  log "building for $(uname -m)"
fi

swift build -c release ${ARCH_ARGS[@]+"${ARCH_ARGS[@]}"}
BIN_DIR="$(swift build -c release ${ARCH_ARGS[@]+"${ARCH_ARGS[@]}"} --show-bin-path)"
[[ -x "${BIN_DIR}/${EXEC_NAME}" ]] || die "binary not found in ${BIN_DIR}"

mkdir -p "${OUT_DIR}"
STAGE="$(mktemp -d "${OUT_DIR}/.stage.XXXXXX")"
BUNDLE="${STAGE}/${APP_NAME}.app"
mkdir -p "${BUNDLE}/Contents/MacOS" "${BUNDLE}/Contents/Resources"
cp "${BIN_DIR}/${EXEC_NAME}" "${BUNDLE}/Contents/MacOS/${EXEC_NAME}"

# App icon (source: Assets/AppIcon.svg).
ICON_SRC="${ROOT}/Assets/AppIcon.icns"
if [[ -f "${ICON_SRC}" ]]; then
  cp "${ICON_SRC}" "${BUNDLE}/Contents/Resources/AppIcon.icns"
else
  warn "Assets/AppIcon.icns not found — building without an icon"
fi

# UI localizations (English base + Russian). macOS picks one from the system language.
for lproj in "${ROOT}"/Localization/*.lproj; do
  [[ -d "${lproj}" ]] || continue
  for strings in "${lproj}"/*.strings; do plutil -lint "${strings}" >/dev/null; done
  cp -R "${lproj}" "${BUNDLE}/Contents/Resources/"
done

# Optional: bundle a vendor DB so the app works offline from the first launch.
OUI_CACHE="${HOME}/Library/Application Support/NetScanner/oui.txt"
if [[ -s "${OUI_CACHE}" ]]; then
  cp "${OUI_CACHE}" "${BUNDLE}/Contents/Resources/oui.txt"
  log "bundled vendor DB ($(wc -l < "${OUI_CACHE}" | tr -d ' ') entries)"
fi

cat > "${BUNDLE}/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>                 <string>${APP_NAME}</string>
  <key>CFBundleDevelopmentRegion</key>    <string>en</string>
  <key>CFBundleLocalizations</key>        <array><string>en</string><string>ru</string></array>
  <key>CFBundleDisplayName</key>          <string>${APP_NAME}</string>
  <key>CFBundleIdentifier</key>           <string>${BUNDLE_ID}</string>
  <key>CFBundleExecutable</key>           <string>${EXEC_NAME}</string>
  <key>CFBundleIconFile</key>             <string>AppIcon</string>
  <key>CFBundlePackageType</key>          <string>APPL</string>
  <key>CFBundleShortVersionString</key>   <string>${VERSION}</string>
  <key>CFBundleVersion</key>              <string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key>       <string>${MIN_MACOS}</string>
  <key>LSApplicationCategoryType</key>    <string>public.app-category.developer-tools</string>
  <key>NSHighResolutionCapable</key>      <true/>
  <key>NSPrincipalClass</key>             <string>NSApplication</string>
  <!-- macOS 15+: required for the Local Network privacy prompt -->
  <key>NSLocalNetworkUsageDescription</key>
  <string>LANA Scanner scans your local network to find devices and open ports.</string>
</dict>
</plist>
PLIST
plutil -lint "${BUNDLE}/Contents/Info.plist" >/dev/null

# Ad-hoc signature: stable identity for TCC (Local Network permission) without a developer account.
codesign --force --sign - --timestamp=none "${BUNDLE}"
codesign --verify --strict "${BUNDLE}"

rm -rf "${APP}"
mv "${BUNDLE}" "${APP}"
log "built ${APP}"

if [[ ${INSTALL} -eq 1 ]]; then
  DEST="${INSTALL_DIR:-/Applications}"
  mkdir -p "${DEST}"
  for legacy in "${LEGACY_APP_NAMES[@]}"; do
    if [[ -d "${DEST}/${legacy}.app" ]]; then
      rm -rf "${DEST:?}/${legacy}.app"
      log "removed old ${DEST}/${legacy}.app"
    fi
  done
  rm -rf "${DEST:?}/${APP_NAME}.app"
  ditto "${APP}" "${DEST}/${APP_NAME}.app"
  # Make Finder/Dock pick up a changed icon instead of a cached one.
  touch "${DEST}/${APP_NAME}.app"
  log "installed to ${DEST}/${APP_NAME}.app"
fi

log "run: open \"${APP}\""
