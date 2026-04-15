#!/usr/bin/env zsh
# update_crashpad.zsh
#
# End-to-end script: sync Crashpad, build for Android ABIs, vendor artifacts
# into the crashkit library, and optionally publish to Maven local.
#
# Run with no args for interactive prompts with sensible defaults.
# All flags can also be passed directly to skip prompts:
#
#   scripts/update_crashpad.zsh --crashpad-dir external/crashpad --version 0.0.3-SNAPSHOT
#   scripts/update_crashpad.zsh --crashpad-dir external/crashpad --skip-bootstrap --skip-publish

set -euo pipefail

SCRIPT_DIR="${0:a:h}"
REPO_ROOT="${SCRIPT_DIR:h}"

# ── Colour helpers ────────────────────────────────────────────────────────────
bold=$'\e[1m'; reset=$'\e[0m'; green=$'\e[32m'; red=$'\e[31m'; dim=$'\e[2m'
info()    { print -P "%F{blue}▸%f $*" }
success() { print -P "%F{green}✔%f $*" }
warn()    { print -P "%F{yellow}⚠%f $*" }
die()     { print -P "%F{red}✖%f $*" >&2; exit 1 }
header()  { echo; echo "${bold}$*${reset}"; echo "${dim}$(printf '─%.0s' {1..60})${reset}" }

# ── Argument parsing ──────────────────────────────────────────────────────────
CRASHPAD_DIR=""
NDK_PATH=""
ABIS=""
SKIP_BOOTSTRAP=""
DO_PUBLISH=""
VERSION=""
NON_INTERACTIVE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --crashpad-dir)   CRASHPAD_DIR="$2"; shift 2 ;;
    --ndk)            NDK_PATH="$2"; shift 2 ;;
    --abis)           ABIS="$2"; shift 2 ;;
    --skip-bootstrap) SKIP_BOOTSTRAP=true; shift ;;
    --skip-publish)   DO_PUBLISH=false; shift ;;
    --version)        VERSION="$2"; shift 2 ;;
    -y|--yes)         NON_INTERACTIVE=true; shift ;;
    -h|--help)
      cat <<EOF
Usage: $(basename "$0") [options]

  --crashpad-dir <path>   Path to the Crashpad checkout (default: external/crashpad)
  --ndk <path>            Android NDK path (default: auto-discovered)
  --abis "<list>"         Space-separated ABIs (default: all four)
  --skip-bootstrap        Skip gclient sync — use if Crashpad is already up to date
  --skip-publish          Vendor artifacts only, do not publish to Maven local
  --version <ver>         crashkit version to publish (e.g. 0.0.3-SNAPSHOT)
  -y, --yes               Accept all defaults non-interactively
EOF
      exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

# ── Default discovery helpers ─────────────────────────────────────────────────

discover_ndk() {
  # Prefer explicit env vars
  [[ -n "${NDK:-}" && -d "${NDK}" ]]                     && { echo "$NDK"; return; }
  [[ -n "${ANDROID_NDK_HOME:-}" && -d "${ANDROID_NDK_HOME}" ]] && { echo "$ANDROID_NDK_HOME"; return; }
  [[ -n "${ANDROID_NDK_ROOT:-}" && -d "${ANDROID_NDK_ROOT}" ]] && { echo "$ANDROID_NDK_ROOT"; return; }
  # Fall back to latest installed NDK under ANDROID_HOME
  if [[ -n "${ANDROID_HOME:-}" && -d "${ANDROID_HOME}/ndk" ]]; then
    local latest
    latest=$(ls -d "${ANDROID_HOME}/ndk/"* 2>/dev/null | sort -V | tail -n1 || true)
    [[ -n "$latest" ]] && { echo "$latest"; return; }
  fi
  echo ""
}

discover_last_version() {
  local m2_dir="$HOME/.m2/repository/com/duckduckgo/crashkit/android-crashkit"
  if [[ -d "$m2_dir" ]]; then
    ls -d "$m2_dir"/*/  2>/dev/null | xargs -I{} basename {} | sort -V | tail -n1 || true
  fi
}

# ── Prompt helper: ask with default ──────────────────────────────────────────
# Usage: ask VARNAME "Prompt text" "default value"
ask() {
  local var="$1" prompt="$2" default="$3"
  if [[ "$NON_INTERACTIVE" == true ]]; then
    eval "$var=\"\$default\""
    return
  fi
  local answer
  if [[ -n "$default" ]]; then
    printf '%s [%s]: ' "$prompt" "${dim}${default}${reset}"
  else
    printf '%s: ' "$prompt"
  fi
  read -r answer
  eval "$var=\"\${answer:-\$default}\""
}

# ask_yn VARNAME "Prompt" default_bool  (default_bool: true=Y/n, false=y/N)
ask_yn() {
  local var="$1" prompt="$2" default="$3"
  local hint result
  [[ "$default" == true ]] && hint="Y/n" || hint="y/N"
  if [[ "$NON_INTERACTIVE" == true ]]; then
    eval "$var=$default"
    return
  fi
  printf '%s [%s]: ' "$prompt" "${dim}${hint}${reset}"
  local answer; read -r answer
  answer="${answer:l}"   # lowercase
  if [[ -z "$answer" ]]; then
    eval "$var=$default"
  elif [[ "$answer" == y || "$answer" == yes ]]; then
    eval "$var=true"
  else
    eval "$var=false"
  fi
}

# ── Interactive prompts ───────────────────────────────────────────────────────
header "crashpad update"

# Crashpad dir
default_crashpad="${REPO_ROOT}/external/crashpad"
[[ -z "$CRASHPAD_DIR" ]] && ask CRASHPAD_DIR "Crashpad dir" "$default_crashpad"

# NDK
default_ndk=$(discover_ndk)
[[ -z "$NDK_PATH" ]] && ask NDK_PATH "NDK path" "$default_ndk"
[[ -z "$NDK_PATH" || ! -d "$NDK_PATH" ]] && die "NDK not found: '${NDK_PATH}'. Set \$NDK or pass --ndk."

# ABIs
default_abis="arm64-v8a armeabi-v7a x86 x86_64"
[[ -z "$ABIS" ]] && ask ABIS "ABIs" "$default_abis"

# Skip bootstrap
if [[ -z "$SKIP_BOOTSTRAP" ]]; then
  skip_bootstrap_bool=false
  [[ -d "$CRASHPAD_DIR/.git" ]] && skip_bootstrap_bool=true   # already cloned → suggest skipping
  ask_yn SKIP_BOOTSTRAP "Skip Crashpad sync (gclient sync)" "$skip_bootstrap_bool"
fi

# Publish
if [[ -z "$DO_PUBLISH" ]]; then
  ask_yn DO_PUBLISH "Publish to Maven local after vendoring" true
fi

# Version (only if publishing)
if [[ "$DO_PUBLISH" == true && -z "$VERSION" ]]; then
  last_ver=$(discover_last_version)
  default_ver="${last_ver:-0.0.1-SNAPSHOT}"
  ask VERSION "crashkit version to publish" "$default_ver"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
header "Plan"
echo "  Crashpad dir  : $CRASHPAD_DIR"
echo "  NDK           : $NDK_PATH"
echo "  ABIs          : $ABIS"
echo "  Skip sync     : $SKIP_BOOTSTRAP"
echo "  Publish       : $DO_PUBLISH"
[[ "$DO_PUBLISH" == true ]] && echo "  Version       : $VERSION"
echo

if [[ "$NON_INTERACTIVE" != true ]]; then
  printf 'Proceed? [Y/n]: '
  read -r confirm
  confirm="${confirm:l}"
  [[ -n "$confirm" && "$confirm" != y && "$confirm" != yes ]] && { echo "Aborted."; exit 0; }
fi

# ── Step 1: Bootstrap / sync Crashpad ────────────────────────────────────────
if [[ "$SKIP_BOOTSTRAP" == true ]]; then
  info "Skipping Crashpad sync."
else
  header "Step 1 — Sync Crashpad"
  "$SCRIPT_DIR/bootstrap_crashpad.zsh" --dest "$CRASHPAD_DIR" --ndk "$NDK_PATH"
  success "Crashpad synced."
fi

# ── Step 1.5: Apply patches ───────────────────────────────────────────────────
header "Step 1.5 — Apply patches"
"$SCRIPT_DIR/apply_patches.zsh" --crashpad-dir "$CRASHPAD_DIR"

# ── Step 2: Build ─────────────────────────────────────────────────────────────
header "Step 2 — Build Crashpad"
# Export NDK so crashpad_build.zsh (called by crashpad_all.zsh) can find it
export NDK="$NDK_PATH"
# crashpad_all.zsh must run from inside the Crashpad dir so gn/ninja find the BUILD.gn
cd "$CRASHPAD_DIR"
"$SCRIPT_DIR/crashpad_all.zsh" --abis "$ABIS" --api 26 --out out
cd "$REPO_ROOT"
success "Build complete."

# ── Step 3: Vendor artifacts ──────────────────────────────────────────────────
header "Step 3 — Vendor artifacts into crashkit"
"$SCRIPT_DIR/copy_crashpad_static_libs.sh" \
  --src "${CRASHPAD_DIR}/out" \
  --dst "${REPO_ROOT}/crashkit/src/main/cpp/crashpad/" \
  --hdr-src "$CRASHPAD_DIR" \
  --abis "$ABIS"

# Record the Crashpad commit so we always know what's vendored
local cp_commit cp_date cp_title
cp_commit=$(git -C "$CRASHPAD_DIR" log -1 --format="%H")
cp_date=$(git -C "$CRASHPAD_DIR" log -1 --format="%as")
cp_title=$(git -C "$CRASHPAD_DIR" log -1 --format="%s")
cat > "${REPO_ROOT}/crashkit/src/main/cpp/crashpad/CRASHPAD_VERSION" <<EOF
commit: ${cp_commit}
date:   ${cp_date}
title:  ${cp_title}
url:    https://chromium.googlesource.com/crashpad/crashpad/+/${cp_commit}
EOF
info "Crashpad version recorded: ${cp_commit:0:12} (${cp_date})"
success "Artifacts vendored."

# ── Step 4: Publish ───────────────────────────────────────────────────────────
if [[ "$DO_PUBLISH" == true ]]; then
  header "Step 4 — Publish crashkit to Maven local"
  cd "$REPO_ROOT"
  ./gradlew :crashkit:publishToMavenLocal -PVERSION_NAME="$VERSION"
  success "Published com.duckduckgo.crashkit:android-crashkit:${VERSION} to Maven local."
else
  info "Skipping publish. Run when ready:"
  echo "  ./gradlew :crashkit:publishToMavenLocal -PVERSION_NAME=<version>"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
header "Done"
success "Crashpad updated and vendored into crashkit."
[[ "$DO_PUBLISH" == true ]] && success "crashkit ${VERSION} published to Maven local."
