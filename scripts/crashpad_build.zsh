#!/usr/bin/env zsh
# Gen + build Crashpad for one or more Android ABIs.
# Builds:
#   - handler ELF:   out/<dir>/crashpad_handler
#   - static libs:   obj/client/libclient.a
#                    obj/client/libcommon.a
#                    obj/util/libutil.a
#                    obj/third_party/mini_chromium/mini_chromium/base/libbase.a
#
# Example:
#   scripts/crashpad_all.zsh --abis "arm64-v8a x86 x86_64 armeabi-v7a" --api 26 --out out --jobs 12
#
# Requires:
#   - depot_tools in PATH (gn, ninja)
#   - export NDK=/path/to/android-ndk (or ANDROID_NDK_ROOT)

set -euo pipefail

print_usage() {
  cat <<EOF
Usage: $(basename "$0") --abis "arm64-v8a x86 x86_64 armeabi-v7a" --api <minSdk> --out <outdir> [--jobs N]
EOF
}

ABIS=""; API=""; OUT_ROOT=""; JOBS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --abis) ABIS="$2"; shift 2 ;;
    --api)  API="$2"; shift 2 ;;
    --out)  OUT_ROOT="$2"; shift 2 ;;
    --jobs) JOBS="$2"; shift 2 ;;
    -h|--help) print_usage; exit 0 ;;
    *) echo "Unknown arg: $1"; print_usage; exit 1 ;;
  esac
done

[[ -z "$ABIS" || -z "$API" || -z "$OUT_ROOT" ]] && { print_usage; exit 1; }

GN=$(command -v gn || true)
NINJA=$(command -v ninja || true)
[[ -z "$GN" ]] && { echo "ERROR: gn not found"; exit 1; }
[[ -z "$NINJA" ]] && { echo "ERROR: ninja not found"; exit 1; }

NDK="${NDK:-${ANDROID_NDK_ROOT:-}}"
[[ -z "$NDK" ]] && { echo "ERROR: set NDK or ANDROID_NDK_ROOT"; exit 1; }

if [[ -z "$JOBS" ]]; then
  if command -v sysctl >/dev/null 2>&1; then
    JOBS=$(sysctl -n hw.ncpu)
  else
    JOBS=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
  fi
fi

# Map ABI -> (gn cpu, out suffix)
map_abi() {
  case "$1" in
    arm64-v8a)  echo "arm64 android-arm64" ;;
    armeabi-v7a) echo "arm android-arm" ;;
    x86)        echo "x86 android-x86" ;;
    x86_64)     echo "x64 android-x64" ;;
    *)          echo "unsupported" ;;
  esac
}

gen_one() {
  local abi="$1"
  local m; m=$(map_abi "$abi")
  [[ "$m" == "unsupported" ]] && { echo "Unsupported ABI: $abi"; return 1; }
  local cpu="${m%% *}" ; local suffix="${m##* }"
  local out="${OUT_ROOT}/${suffix}"
  mkdir -p "$out"
  echo "gn gen $out -- $abi"
  "$GN" gen "$out" --args="target_os=\"android\" target_cpu=\"${cpu}\" is_debug=false use_custom_libcxx=false android_api_level=${API} android_ndk_root=\"${NDK}\" extra_ldflags=\"-static-libstdc++\""
}

build_one() {
  local abi="$1"
  local m; m=$(map_abi "$abi")
  [[ "$m" == "unsupported" ]] && { echo "Unsupported ABI: $abi"; return 1; }
  local suffix="${m##* }"
  local out="${OUT_ROOT}/${suffix}"

  # Build by artifact paths (no //labels -> avoids zsh/ninja quirks)
  local -a targets
  targets=(
    "crashpad_handler"
    "obj/client/libclient.a"
    "obj/client/libcommon.a"
    "obj/util/libutil.a"
    "obj/third_party/mini_chromium/mini_chromium/base/libbase.a"
  )

  echo "[$abi] ninja -C $out -j $JOBS ${targets[*]}"
  "$NINJA" -C "$out" -j "$JOBS" "${targets[@]}"
}

# GEN all first (better error surfacing), then BUILD
echo "Generating for: $ABIS"
for abi in ${(z)ABIS}; do gen_one "$abi"; done
echo "Done gn gen for: $ABIS"

for abi in ${(z)ABIS}; do build_one "$abi"; done

echo "All done. Outputs under: $OUT_ROOT"

